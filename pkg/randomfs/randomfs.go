package randomfs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// Block sizes for different file categories
	NanoBlockSize = 1024    // 1KB for small files
	MiniBlockSize = 65536   // 64KB for medium files
	BlockSize     = 1048576 // 1MB for large files

	// Thresholds for block size selection
	NanoThreshold = 100 * 1024       // 100KB
	MiniThreshold = 10 * 1024 * 1024 // 10MB

	// Protocol version
	ProtocolVersion = "v5"

	// Default IPFS API endpoint
	DefaultIPFSEndpoint = "http://localhost:5001"

	// TupleSize defines the number of blocks in an OFFSystem tuple.
	// This includes the anonymized block and its randomizer blocks.
	TupleSize = 3

	// DefaultBlockSize is the standard size for content blocks.
	DefaultBlockSize = 128 * 1024 // 128 KiB

	// MinEntropyThreshold is the minimum Shannon entropy a block must have to be considered for reuse.
	MinEntropyThreshold = 7.0
)

// RandomFS represents the main filesystem instance
type RandomFS struct {
	ipfsAPI              string
	dataDir              string
	blockCache           *SmartBlockCache
	mutex                sync.RWMutex
	useLocalStorage      bool
	RedundancyFactor     int
	blockIndex           []string
	blockIndexMutex      sync.Mutex
	analyzer             *ContentAnalyzer
	blockPopularity      map[string]int
	blockPopularityMutex sync.Mutex

	// Statistics
	stats Stats
}

// Stats holds system statistics
type Stats struct {
	FilesStored            int64         `json:"files_stored"`
	BlocksGenerated        int64         `json:"blocks_generated"`
	TotalSize              int64         `json:"total_size"`
	CacheHits              int64         `json:"cache_hits"`
	CacheMisses            int64         `json:"cache_misses"`
	BlockRetrievalFailures int64         `json:"block_retrieval_failures"`
	TotalRetrievalLatency  time.Duration `json:"total_retrieval_latency"`
	SuccessfulRetrievals   int64         `json:"successful_retrievals"`
	BlocksReused           int64         `json:"blocks_reused"`
	mutex                  sync.Mutex
}

// SmartBlockCache implements a multi-tier caching strategy for blocks.
type SmartBlockCache struct {
	hot         *lru.Cache // For frequently accessed blocks
	warm        *lru.Cache // For recently accessed blocks
	rfs         *RandomFS  // To access underlying storage
	mutex       sync.Mutex
	stats       *Stats
	promoCounts map[string]int // For promotion policy
}

// NewSmartBlockCache creates a new smart block cache.
func NewSmartBlockCache(rfs *RandomFS, stats *Stats, size int) (*SmartBlockCache, error) {
	hot, err := lru.New(size / 2)
	if err != nil {
		return nil, err
	}
	warm, err := lru.New(size / 2)
	if err != nil {
		return nil, err
	}
	return &SmartBlockCache{
		hot:         hot,
		warm:        warm,
		rfs:         rfs,
		stats:       stats,
		promoCounts: make(map[string]int),
	}, nil
}

// Get retrieves a block from the cache or underlying storage.
func (sbc *SmartBlockCache) Get(hash string) ([]byte, error) {
	sbc.mutex.Lock()
	defer sbc.mutex.Unlock()

	// 1. Check hot cache
	if data, ok := sbc.hot.Get(hash); ok {
		sbc.stats.mutex.Lock()
		sbc.stats.CacheHits++
		sbc.stats.mutex.Unlock()
		return data.([]byte), nil
	}

	// 2. Check warm cache
	if data, ok := sbc.warm.Get(hash); ok {
		sbc.stats.mutex.Lock()
		sbc.stats.CacheHits++
		sbc.stats.mutex.Unlock()
		// Promote to hot cache if accessed frequently enough
		if sbc.shouldPromote(hash) {
			sbc.warm.Remove(hash)
			sbc.hot.Add(hash, data)
		}
		return data.([]byte), nil
	}

	// 3. Fetch from cold storage (IPFS or local disk)
	sbc.stats.mutex.Lock()
	sbc.stats.CacheMisses++
	sbc.stats.mutex.Unlock()
	var blockData []byte
	var err error
	if sbc.rfs.useLocalStorage {
		blockData, err = sbc.rfs.catFromLocalStorage(hash, "block")
	} else {
		blockData, err = sbc.rfs.catFromIPFS(hash)
	}
	if err != nil {
		return nil, err
	}

	// Add to warm cache
	sbc.warm.Add(hash, blockData)

	return blockData, nil
}

// Put adds a block to the cache.
func (sbc *SmartBlockCache) Put(hash string, data []byte) {
	sbc.mutex.Lock()
	defer sbc.mutex.Unlock()
	sbc.warm.Add(hash, data)
}

// shouldPromote decides if a block should move from warm to hot cache.
func (sbc *SmartBlockCache) shouldPromote(hash string) bool {
	sbc.promoCounts[hash]++
	if sbc.promoCounts[hash] >= 3 {
		delete(sbc.promoCounts, hash)
		return true
	}
	return false
}

// FileRepresentation contains the metadata needed to reconstruct a file
type FileRepresentation struct {
	FileName    string       `json:"filename"`
	FileSize    int64        `json:"filesize"`
	BlockHashes []string     `json:"block_hashes"`
	BlockSize   int          `json:"block_size"`
	Timestamp   int64        `json:"timestamp"`
	ContentType string       `json:"content_type"`
	Version     string       `json:"version"`
	Descriptors [][][]string `json:"descriptors"` // OFF System descriptor lists with redundancy
}

// RandomURL represents a rfs:// URL for file access
type RandomURL struct {
	Scheme    string
	Host      string
	Version   string
	FileName  string
	FileSize  int64
	RepHash   string
	Timestamp int64
}

// StreamingReader enables reading large files as a stream.
type StreamingReader struct {
	rfs        *RandomFS
	rep        *FileRepresentation
	position   int64
	blockCache *lru.Cache // Caches reconstructed original blocks
	mutex      sync.Mutex
}

// NewRandomFS creates a new RandomFS instance
func NewRandomFS(ipfsAPI string, dataDir string, cacheSize int64) (*RandomFS, error) {
	return NewRandomFSWithOptions(ipfsAPI, dataDir, cacheSize, false)
}

// NewRandomFSWithoutIPFS creates a new RandomFS instance without requiring IPFS
func NewRandomFSWithoutIPFS(dataDir string, cacheSize int64) (*RandomFS, error) {
	return NewRandomFSWithOptions("", dataDir, cacheSize, true)
}

// NewRandomFSWithOptions creates a new RandomFS instance with options
func NewRandomFSWithOptions(ipfsAPI string, dataDir string, cacheSize int64, skipIPFSTest bool) (*RandomFS, error) {
	if ipfsAPI == "" {
		ipfsAPI = DefaultIPFSEndpoint
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	// Create subdirectories for local storage
	if skipIPFSTest {
		blocksDir := filepath.Join(dataDir, "blocks")
		repsDir := filepath.Join(dataDir, "representations")
		if err := os.MkdirAll(blocksDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create blocks directory: %v", err)
		}
		if err := os.MkdirAll(repsDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create representations directory: %v", err)
		}
	}

	rfs := &RandomFS{
		ipfsAPI:          ipfsAPI,
		dataDir:          dataDir,
		useLocalStorage:  skipIPFSTest,
		RedundancyFactor: 2, // Default redundancy factor
		blockIndex:       make([]string, 0),
		analyzer:         &ContentAnalyzer{},
		blockPopularity:  make(map[string]int),
	}

	// Load existing block hashes into the index if using local storage
	if skipIPFSTest {
		go rfs.loadBlockIndex()
	}

	// Initialize smart cache
	cache, err := NewSmartBlockCache(rfs, &rfs.stats, 100) // Cache up to 100 blocks total
	if err != nil {
		return nil, fmt.Errorf("failed to create smart cache: %v", err)
	}
	rfs.blockCache = cache

	// Test IPFS connection unless skipped
	if !skipIPFSTest {
		if err := rfs.testIPFSConnection(); err != nil {
			return nil, fmt.Errorf("failed to connect to IPFS: %v", err)
		}
		log.Printf("RandomFS initialized with IPFS at %s, data dir %s", ipfsAPI, dataDir)
	} else {
		log.Printf("RandomFS initialized with local storage, data dir %s", dataDir)
	}

	return rfs, nil
}

// GetStats returns current system statistics
func (rfs *RandomFS) GetStats() Stats {
	rfs.stats.mutex.Lock()
	defer rfs.stats.mutex.Unlock()
	return Stats{
		FilesStored:            rfs.stats.FilesStored,
		BlocksGenerated:        rfs.stats.BlocksGenerated,
		TotalSize:              rfs.stats.TotalSize,
		CacheHits:              rfs.stats.CacheHits,
		CacheMisses:            rfs.stats.CacheMisses,
		BlockRetrievalFailures: rfs.stats.BlockRetrievalFailures,
		TotalRetrievalLatency:  rfs.stats.TotalRetrievalLatency,
		SuccessfulRetrievals:   rfs.stats.SuccessfulRetrievals,
		BlocksReused:           rfs.stats.BlocksReused,
	}
}

// testIPFSConnection tests if IPFS daemon is accessible
func (rfs *RandomFS) testIPFSConnection() error {
	resp, err := http.Post(rfs.ipfsAPI+"/api/v0/version", "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("IPFS daemon not accessible, status: %d", resp.StatusCode)
	}

	return nil
}

// StoreFile stores a file in RandomFS, returning a hash of the file's representation.
// The representation is encrypted with the provided password.
func (rfs *RandomFS) StoreFile(filename string, data []byte, contentType string, password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("a password is required to encrypt the file descriptor")
	}

	blockSize := rfs.selectBlockSize(int64(len(data)))
	blocks := splitIntoBlocks(data, blockSize)

	rep := FileRepresentation{
		FileName:    filename,
		FileSize:    int64(len(data)),
		BlockSize:   blockSize,
		Timestamp:   time.Now().Unix(),
		ContentType: contentType,
		Version:     ProtocolVersion,
		Descriptors: make([][][]string, len(blocks)),
	}

	// Collect all blocks to be stored in a batch
	var allBlocks [][]byte

	for i, block := range blocks {
		for j := 0; j < rfs.RedundancyFactor; j++ {
			// In each redundancy round, we anonymize
			// the original block with a set of other random blocks.
			randomizerBlocks, _, err := rfs.selectRandomizerBlocks(TupleSize-1, blockSize)
			if err != nil {
				return "", fmt.Errorf("failed to select randomizer blocks for block %d: %v", i, err)
			}

			// Add randomizer blocks to the batch
			for _, rBlock := range randomizerBlocks {
				allBlocks = append(allBlocks, rBlock)
			}

			// The last block in the tuple is the XOR sum of the original block and the randomizers.
			// To get the anonymized block, we start with the original data.
			anonymizedBlock := make([]byte, len(block))
			copy(anonymizedBlock, block)

			// XOR with all randomizer blocks
			for _, rBlock := range randomizerBlocks {
				XORBlocksInPlace(anonymizedBlock, rBlock)
			}

			// Add anonymized block to the batch
			allBlocks = append(allBlocks, anonymizedBlock)
		}
	}

	// Store all blocks in a batch
	allHashes, err := rfs.StoreAndIndexBlocks(allBlocks)
	if err != nil {
		return "", fmt.Errorf("failed to batch store blocks: %v", err)
	}

	// Build descriptors using the returned hashes
	hashIndex := 0
	for i := range blocks {
		var blockDescriptors [][]string
		for j := 0; j < rfs.RedundancyFactor; j++ {
			var descriptor []string

			// Add randomizer hashes
			for k := 0; k < TupleSize-1; k++ {
				descriptor = append(descriptor, allHashes[hashIndex])
				hashIndex++
			}

			// Add anonymized hash at the beginning
			anonymizedHash := allHashes[hashIndex]
			descriptor = append([]string{anonymizedHash}, descriptor...)
			hashIndex++

			blockDescriptors = append(blockDescriptors, descriptor)
		}
		rep.Descriptors[i] = blockDescriptors
	}

	// Encrypt the representation
	repJSON, err := json.Marshal(rep)
	if err != nil {
		return "", fmt.Errorf("failed to marshal file representation: %v", err)
	}

	encryptedRep, err := rfs.encryptData(repJSON, password)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt file representation: %v", err)
	}

	// Store the encrypted representation
	repHash, err := rfs.storeBlock(encryptedRep)
	if err != nil {
		return "", fmt.Errorf("failed to store encrypted file representation: %v", err)
	}

	// Update popularity counts for all reused randomizer blocks
	rfs.updateBlockPopularity(&rep)

	rfs.updateStats(func(s *Stats) {
		s.FilesStored++
		s.BlocksGenerated += int64(len(rep.BlockHashes))
		s.TotalSize += rep.FileSize
	})

	return repHash, nil
}

// RetrieveFile retrieves a file from RandomFS using its representation hash.
// The password must match the one used during storage.
func (rfs *RandomFS) RetrieveFile(repHash string, password string) ([]byte, *FileRepresentation, error) {
	if password == "" {
		return nil, nil, fmt.Errorf("a password is required to decrypt the file descriptor")
	}

	encryptedRep, err := rfs.retrieveBlock(repHash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve encrypted representation block %s: %v", repHash, err)
	}

	rep, err := rfs.getRepresentation(encryptedRep, password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get representation from hash %s: %v", repHash, err)
	}

	// Now that we have the (decrypted) representation, we can fetch the file blocks.
	var wg sync.WaitGroup
	fileData := make([][]byte, len(rep.Descriptors))
	blockErrors := make(chan error, len(rep.Descriptors))

	// --- Cover Traffic ---
	// Fetch decoy blocks concurrently to obfuscate the real block requests.
	numDecoys := len(rep.Descriptors) * TupleSize // Fetch roughly same number of decoys as real blocks
	decoyHashes := rfs.selectDecoyBlocks(numDecoys)
	for _, decoyHash := range decoyHashes {
		go rfs.retrieveBlock(decoyHash) // We don't care about the result, just the network traffic.
	}
	// ---------------------

	for i := range rep.Descriptors {
		wg.Add(1)
		go func(blockIndex int) {
			defer wg.Done()
			// This logic attempts to reconstruct the block using redundant descriptors
			// if the primary one fails.
			for _, descriptor := range rep.Descriptors[blockIndex] {
				if len(descriptor) == 0 {
					continue // Should not happen, but good to be safe.
				}
				anonymizedHash := descriptor[0]
				randomizerHashes := descriptor[1:]

				// Fetch all blocks in the tuple concurrently
				type blockResult struct {
					isAnonymized bool
					data         []byte
					err          error
				}
				results := make(chan blockResult, len(descriptor))
				var fetchWg sync.WaitGroup

				fetchWg.Add(1)
				go func() {
					defer fetchWg.Done()
					data, err := rfs.retrieveBlock(anonymizedHash)
					results <- blockResult{isAnonymized: true, data: data, err: err}
				}()

				for _, rHash := range randomizerHashes {
					fetchWg.Add(1)
					go func(hash string) {
						defer fetchWg.Done()
						data, err := rfs.retrieveBlock(hash)
						results <- blockResult{isAnonymized: false, data: data, err: err}
					}(rHash)
				}

				fetchWg.Wait()
				close(results)

				var anonymizedBlock []byte
				randomizerBlocks := make([][]byte, 0, len(randomizerHashes))
				var fetchErr error

				for res := range results {
					if res.err != nil {
						fetchErr = res.err
						break
					}
					if res.isAnonymized {
						anonymizedBlock = res.data
					} else {
						randomizerBlocks = append(randomizerBlocks, res.data)
					}
				}

				if fetchErr != nil {
					log.Printf("Failed to fetch a block for descriptor, trying next one. Error: %v", fetchErr)
					continue // Try the next redundant descriptor
				}

				// Reconstruct the original block
				reconstructedBlock := make([]byte, rep.BlockSize)
				copy(reconstructedBlock, anonymizedBlock)
				for _, rBlock := range randomizerBlocks {
					XORBlocksInPlace(reconstructedBlock, rBlock)
				}
				fileData[blockIndex] = reconstructedBlock
				return // Successfully reconstructed this block, exit the redundancy loop
			}
			// If we get here, all redundant descriptors for this block failed.
			blockErrors <- fmt.Errorf("failed to reconstruct block %d after all retries", blockIndex)
		}(i)
	}

	wg.Wait()
	close(blockErrors)

	if err := <-blockErrors; err != nil {
		return nil, nil, err
	}

	// Assemble the file from the reconstructed blocks
	var fullFile []byte
	for _, block := range fileData {
		fullFile = append(fullFile, block...)
	}

	// Trim padding from the last block
	if rep.FileSize > 0 && len(fullFile) > int(rep.FileSize) {
		fullFile = fullFile[:rep.FileSize]
	}

	return fullFile, &rep, nil
}

// getRepresentation decrypts and unmarshals the file representation.
func (rfs *RandomFS) getRepresentation(encryptedData []byte, password string) (FileRepresentation, error) {
	var rep FileRepresentation
	decryptedJSON, err := rfs.decryptData(encryptedData, password)
	if err != nil {
		return rep, fmt.Errorf("failed to decrypt representation: %v", err)
	}

	if err := json.Unmarshal(decryptedJSON, &rep); err != nil {
		return rep, fmt.Errorf("failed to unmarshal representation JSON: %v", err)
	}

	return rep, nil
}

func (rfs *RandomFS) generateKey(password string) (*[32]byte, error) {
	hash := sha256.Sum256([]byte(password))
	return &hash, nil
}

func (rfs *RandomFS) encryptData(data []byte, password string) ([]byte, error) {
	key, err := rfs.generateKey(password)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], data, &nonce, key)
	return encrypted, nil
}

func (rfs *RandomFS) decryptData(encryptedData []byte, password string) ([]byte, error) {
	key, err := rfs.generateKey(password)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if len(encryptedData) < len(nonce) {
		return nil, fmt.Errorf("encrypted data is too short")
	}
	copy(nonce[:], encryptedData[:len(nonce)])

	decrypted, ok := secretbox.Open(nil, encryptedData[len(nonce):], &nonce, key)
	if !ok {
		return nil, fmt.Errorf("decryption failed, likely incorrect password")
	}

	return decrypted, nil
}

// updateBlockPopularity increments the usage count for each randomizer block in a representation.
func (rfs *RandomFS) updateBlockPopularity(rep *FileRepresentation) {
	rfs.blockPopularityMutex.Lock()
	defer rfs.blockPopularityMutex.Unlock()

	for _, descriptorList := range rep.Descriptors {
		for _, descriptor := range descriptorList {
			// The first hash is the anonymized block, the rest are randomizers.
			if len(descriptor) > 1 {
				for _, randomizerHash := range descriptor[1:] {
					rfs.blockPopularity[randomizerHash]++
				}
			}
		}
	}
}

// GenerateRandomBlocks creates randomized blocks using the OFF System algorithm
func GenerateRandomBlocks(data []byte, blockSize int) ([][]byte, error) {
	var blocks [][]byte

	for offset := 0; offset < len(data); offset += blockSize {
		end := offset + blockSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[offset:end]

		// Pad chunk to full block size if needed
		paddedChunk := make([]byte, blockSize)
		copy(paddedChunk, chunk)

		// Select t-1 randomizer blocks from existing cache or generate new ones
		randomizers := make([][]byte, TupleSize-1)
		for i := 0; i < TupleSize-1; i++ {
			// For now, generate new random blocks
			// In a real implementation, you'd select from existing cache
			randomBlock := make([]byte, blockSize)
			if _, err := rand.Read(randomBlock); err != nil {
				return nil, fmt.Errorf("failed to generate random data: %v", err)
			}
			randomizers[i] = randomBlock
		}

		// Calculate o_i = s_i ⊕ r_1 ⊕ r_2 ⊕ ... ⊕ r_{t-1}
		result := make([]byte, blockSize)
		copy(result, paddedChunk)

		for _, randomizer := range randomizers {
			XORBlocksInPlace(result, randomizer)
		}

		// Store the result block
		blocks = append(blocks, result)

		// Also store the randomizer blocks for reuse
		blocks = append(blocks, randomizers...)
	}

	return blocks, nil
}

// DeRandomizeBlock recovers original data using the OFF System algorithm
// This function is called for each block in the descriptor set
func DeRandomizeBlock(block []byte, dataSize int) []byte {
	// In the OFF System, derandomization happens by XORing all blocks in the tuple
	// This function is called for each block, but the actual XOR happens in RetrieveFile
	result := make([]byte, dataSize)
	copy(result, block[:dataSize])
	return result
}

// XORBlocks returns the XOR of two byte slices (up to the length of the shorter slice)
func XORBlocks(a, b []byte) []byte {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	out := make([]byte, minLen)
	for i := 0; i < minLen; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// XORBlocksInPlace XORs b into a in place (up to the length of b)
func XORBlocksInPlace(a, b []byte) {
	for i := 0; i < len(b) && i < len(a); i++ {
		a[i] ^= b[i]
	}
}

// storeBlock stores a block in IPFS and local cache
func (rfs *RandomFS) storeBlock(block []byte) (string, error) {
	var hash string
	var err error

	if rfs.useLocalStorage {
		hash, err = rfs.addToLocalStorage(block, "block")
	} else {
		hash, err = rfs.addToIPFS(block)
	}

	if err != nil {
		return "", err
	}

	// Add to cache
	rfs.blockCache.Put(hash, block)

	// Add to block index for reuse
	rfs.blockIndexMutex.Lock()
	rfs.blockIndex = append(rfs.blockIndex, hash)
	rfs.blockIndexMutex.Unlock()

	return hash, nil
}

// StoreAndIndexBlocks stores multiple blocks in a batch and returns their hashes
func (rfs *RandomFS) StoreAndIndexBlocks(blocks [][]byte) ([]string, error) {
	if len(blocks) == 0 {
		return []string{}, nil
	}

	var hashes []string
	var err error

	if rfs.useLocalStorage {
		// For local storage, we still need to store blocks individually
		// since local storage doesn't support batch operations
		hashes = make([]string, len(blocks))
		for i, block := range blocks {
			hash, err := rfs.addToLocalStorage(block, "block")
			if err != nil {
				return nil, fmt.Errorf("failed to store block %d: %v", i, err)
			}
			hashes[i] = hash
		}
	} else {
		// For IPFS, use batch upload
		hashes, err = rfs.addManyToIPFS(blocks)
		if err != nil {
			return nil, fmt.Errorf("failed to batch store blocks: %v", err)
		}
	}

	// Add all blocks to cache and index
	rfs.blockIndexMutex.Lock()
	for i, hash := range hashes {
		rfs.blockCache.Put(hash, blocks[i])
		rfs.blockIndex = append(rfs.blockIndex, hash)
	}
	rfs.blockIndexMutex.Unlock()

	return hashes, nil
}

// retrieveBlock retrieves a block from the cache or IPFS
func (rfs *RandomFS) retrieveBlock(hash string) ([]byte, error) {
	startTime := time.Now()
	block, err := rfs.blockCache.Get(hash)

	rfs.stats.mutex.Lock()
	defer rfs.stats.mutex.Unlock()

	if err != nil {
		rfs.stats.BlockRetrievalFailures++
	} else {
		rfs.stats.SuccessfulRetrievals++
		rfs.stats.TotalRetrievalLatency += time.Since(startTime)
	}

	return block, err
}

// selectBlockSize determines the appropriate block size for a file
func (rfs *RandomFS) selectBlockSize(fileSize int64) int {
	if fileSize <= NanoThreshold {
		return NanoBlockSize
	} else if fileSize <= MiniThreshold {
		return MiniBlockSize
	}
	return BlockSize
}

// addToIPFS adds data to IPFS and returns the hash
func (rfs *RandomFS) addToIPFS(data []byte) (string, error) {
	// Create a multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Create a form file
	part, err := writer.CreateFormFile("file", "data")
	if err != nil {
		return "", fmt.Errorf("failed to create form file: %v", err)
	}

	// Write the data to the form file
	if _, err := part.Write(data); err != nil {
		return "", fmt.Errorf("failed to write data to form: %v", err)
	}

	// Close the writer
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close writer: %v", err)
	}

	// Create the request
	url := fmt.Sprintf("%s/api/v0/add", rfs.ipfsAPI)
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send the request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("IPFS API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var result struct {
		Hash string `json:"Hash"`
		Name string `json:"Name"`
		Size string `json:"Size"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	return result.Hash, nil
}

// addManyToIPFS adds multiple blocks to IPFS in a single request and returns their hashes
func (rfs *RandomFS) addManyToIPFS(blocks [][]byte) ([]string, error) {
	// Create a multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add each block as a separate form file
	for i, block := range blocks {
		part, err := writer.CreateFormFile("file", fmt.Sprintf("block_%d", i))
		if err != nil {
			return nil, fmt.Errorf("failed to create form file for block %d: %v", i, err)
		}

		if _, err := part.Write(block); err != nil {
			return nil, fmt.Errorf("failed to write block %d to form: %v", i, err)
		}
	}

	// Close the writer
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %v", err)
	}

	// Create the request
	url := fmt.Sprintf("%s/api/v0/add", rfs.ipfsAPI)
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send the request
	client := &http.Client{Timeout: 60 * time.Second} // Longer timeout for batch operations
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("IPFS API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the streaming response - IPFS returns one JSON object per line
	var hashes []string
	decoder := json.NewDecoder(resp.Body)

	for decoder.More() {
		var result struct {
			Hash string `json:"Hash"`
			Name string `json:"Name"`
			Size string `json:"Size"`
		}

		if err := decoder.Decode(&result); err != nil {
			return nil, fmt.Errorf("failed to decode response: %v", err)
		}

		hashes = append(hashes, result.Hash)
	}

	if len(hashes) != len(blocks) {
		return nil, fmt.Errorf("expected %d hashes, got %d", len(blocks), len(hashes))
	}

	return hashes, nil
}

// catFromIPFS retrieves data from IPFS using HTTP API
func (rfs *RandomFS) catFromIPFS(hash string) ([]byte, error) {
	resp, err := http.Post(rfs.ipfsAPI+"/api/v0/cat?arg="+hash, "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IPFS cat failed with status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// addToLocalStorage stores data locally and returns a hash
func (rfs *RandomFS) addToLocalStorage(data []byte, dataType string) (string, error) {
	// Generate hash for the data
	hash := fmt.Sprintf("%x", sha256.Sum256(data))

	// Determine directory based on data type
	var dir string
	switch dataType {
	case "block":
		dir = filepath.Join(rfs.dataDir, "blocks")
	case "representation":
		dir = filepath.Join(rfs.dataDir, "representations")
	default:
		dir = filepath.Join(rfs.dataDir, "data")
	}

	// Write data to file
	filename := filepath.Join(dir, hash)
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write to local storage: %v", err)
	}

	return hash, nil
}

// catFromLocalStorage retrieves data from local storage
func (rfs *RandomFS) catFromLocalStorage(hash string, dataType string) ([]byte, error) {
	// Determine directory based on data type
	var dir string
	switch dataType {
	case "block":
		dir = filepath.Join(rfs.dataDir, "blocks")
	case "representation":
		dir = filepath.Join(rfs.dataDir, "representations")
	default:
		dir = filepath.Join(rfs.dataDir, "data")
	}

	// Read data from file
	filename := filepath.Join(dir, hash)
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read from local storage: %v", err)
	}

	return data, nil
}

// ParseRandomURL parses a rfs:// URL
func ParseRandomURL(rawURL string) (*RandomURL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	if u.Scheme != "rfs" {
		return nil, fmt.Errorf("invalid scheme: expected 'rfs', got '%s'", u.Scheme)
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 1 {
		return nil, fmt.Errorf("invalid rfs:// URL format: expected rfs://<hash>")
	}

	hash := parts[0]

	return &RandomURL{
		Scheme:    u.Scheme,
		Host:      u.Host,
		Version:   ProtocolVersion,
		FileName:  "", // Will be retrieved from representation
		FileSize:  0,  // Will be retrieved from representation
		RepHash:   hash,
		Timestamp: 0, // Will be retrieved from representation
	}, nil
}

// String returns the string representation of a RandomURL
func (ru *RandomURL) String() string {
	return fmt.Sprintf("rfs://%s", ru.RepHash)
}

// OpenStream opens a streaming reader for a large file.
// NOTE: This function does not currently support encrypted descriptors.
func (rfs *RandomFS) OpenStream(repHash string) (*StreamingReader, error) {
	// Since we don't have the password, we can't decrypt the real representation.
	// For now, this will fail. A future update could involve passing the password here.
	encryptedRep, err := rfs.retrieveBlock(repHash)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve representation block for streaming: %v", err)
	}

	// This call will fail as an empty password is not allowed for decryption.
	rep, err := rfs.getRepresentation(encryptedRep, "")
	if err != nil {
		return nil, fmt.Errorf("cannot open stream without a password for encrypted descriptor: %v", err)
	}

	cache, _ := lru.New(10) // Cache for reconstructed blocks
	return &StreamingReader{
		rfs:        rfs,
		rep:        &rep,
		position:   0,
		blockCache: cache,
	}, nil
}

// Read implements the io.Reader interface for StreamingReader.
func (sr *StreamingReader) Read(p []byte) (n int, err error) {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	if sr.position >= sr.rep.FileSize {
		return 0, io.EOF
	}

	blockIndex := int(sr.position / int64(sr.rep.BlockSize))
	blockOffset := int(sr.position % int64(sr.rep.BlockSize))

	// Get the reconstructed block, loading if not in cache.
	originalBlock, err := sr.getBlock(blockIndex)
	if err != nil {
		return 0, err
	}

	// Copy data from the block to the destination buffer 'p'.
	bytesToCopy := len(originalBlock) - blockOffset
	if bytesToCopy > len(p) {
		bytesToCopy = len(p)
	}

	// Ensure we don't read past the end of the file.
	if sr.position+int64(bytesToCopy) > sr.rep.FileSize {
		bytesToCopy = int(sr.rep.FileSize - sr.position)
	}

	if bytesToCopy <= 0 {
		return 0, io.EOF
	}

	copy(p, originalBlock[blockOffset:blockOffset+bytesToCopy])

	sr.position += int64(bytesToCopy)

	// Simple prefetch for the next block.
	if sr.position < sr.rep.FileSize {
		nextBlockIndex := int(sr.position / int64(sr.rep.BlockSize))
		if nextBlockIndex > blockIndex {
			go sr.getBlock(nextBlockIndex) // Prefetch in the background, errors are ignored.
		}
	}

	return bytesToCopy, nil
}

// getBlock retrieves a single reconstructed block, from cache or by fetching and derandomizing.
func (sr *StreamingReader) getBlock(blockIndex int) ([]byte, error) {
	// Check cache first.
	if cachedBlock, ok := sr.blockCache.Get(blockIndex); ok {
		return cachedBlock.([]byte), nil
	}

	// Block not in cache, load it.
	numOriginalBlocks := (len(sr.rep.BlockHashes) + TupleSize - 1) / TupleSize
	if blockIndex >= numOriginalBlocks {
		return nil, io.EOF
	}

	start := blockIndex * TupleSize
	end := start + TupleSize
	if end > len(sr.rep.BlockHashes) {
		end = len(sr.rep.BlockHashes)
	}

	tupleHashes := sr.rep.BlockHashes[start:end]

	// Retrieve tuple blocks in parallel.
	type blockResult struct {
		idx  int
		data []byte
		err  error
	}

	results := make(chan blockResult, len(tupleHashes))
	var wg sync.WaitGroup

	for i, hash := range tupleHashes {
		wg.Add(1)
		go func(i int, hash string) {
			defer wg.Done()
			data, err := sr.rfs.retrieveBlock(hash)
			results <- blockResult{i, data, err}
		}(i, hash)
	}

	wg.Wait()
	close(results)

	tupleBlocks := make([][]byte, len(tupleHashes))
	for res := range results {
		if res.err != nil {
			return nil, fmt.Errorf("failed to retrieve block %s for tuple %d: %v", tupleHashes[res.idx], blockIndex, res.err)
		}
		tupleBlocks[res.idx] = res.data
	}

	// Reconstruct the original block by XORing.
	if len(tupleBlocks) == 0 {
		return nil, fmt.Errorf("no blocks found for tuple %d", blockIndex)
	}
	originalBlock := make([]byte, len(tupleBlocks[0]))
	copy(originalBlock, tupleBlocks[0])

	for i := 1; i < len(tupleBlocks); i++ {
		XORBlocksInPlace(originalBlock, tupleBlocks[i])
	}

	// Add to cache.
	sr.blockCache.Add(blockIndex, originalBlock)

	return originalBlock, nil
}

// splitIntoBlocks is a helper function to divide data into fixed-size blocks.
func splitIntoBlocks(data []byte, blockSize int) [][]byte {
	var blocks [][]byte
	for i := 0; i < len(data); i += blockSize {
		end := i + blockSize
		if end > len(data) {
			end = len(data)
		}
		// Pad the last block if it's smaller than blockSize
		chunk := make([]byte, blockSize)
		copy(chunk, data[i:end])
		blocks = append(blocks, chunk)
	}
	return blocks
}

// selectRandomizerBlocks selects existing blocks to be used as randomizers
// and generates new ones if not enough are available. It uses a content analyzer
// to pick the best candidates for reuse.
func (rfs *RandomFS) selectRandomizerBlocks(count int, blockSize int) (blocks [][]byte, reusedCount int, err error) {
	// 1. Get a pool of candidates from the block index.
	const maxCandidates = 20 // Analyze up to 20 candidates for performance.
	candidateHashes := rfs.selectRandomizerHashes(maxCandidates)

	rfs.blockPopularityMutex.Lock()
	defer rfs.blockPopularityMutex.Unlock()

	candidates := make([]BlockCandidate, 0, len(candidateHashes))
	for _, hash := range candidateHashes {
		data, err := rfs.retrieveBlock(hash) // This uses the cache, so it should be fast.
		if err == nil {
			candidates = append(candidates, BlockCandidate{
				Hash:       hash,
				Data:       data,
				Popularity: rfs.blockPopularity[hash], // Get popularity
			})
		}
	}

	var selectedBlocks [][]byte

	// 2. If we have candidates, use the analyzer to select the best ones.
	if len(candidates) > 0 {
		numToSelect := count
		if len(candidates) < count {
			numToSelect = len(candidates)
		}
		// Use the hybrid selection strategy.
		optimalCandidates := rfs.analyzer.selectOptimalBlocks(candidates, numToSelect, MinEntropyThreshold)
		for _, c := range optimalCandidates {
			selectedBlocks = append(selectedBlocks, c.Data)
		}
	}

	reusedCount = len(selectedBlocks)
	if reusedCount > 0 {
		rfs.updateStats(func(s *Stats) {
			s.BlocksReused += int64(reusedCount)
		})
	}

	// 3. Generate new random blocks if we don't have enough.
	for len(selectedBlocks) < count {
		newBlock := make([]byte, blockSize)
		if _, err := rand.Read(newBlock); err != nil {
			return nil, 0, fmt.Errorf("failed to generate new randomizer block: %v", err)
		}
		selectedBlocks = append(selectedBlocks, newBlock)
	}

	return selectedBlocks, reusedCount, nil
}

// selectRandomizerHashes selects a random set of block hashes from the index.
func (rfs *RandomFS) selectRandomizerHashes(count int) []string {
	rfs.blockIndexMutex.Lock()
	defer rfs.blockIndexMutex.Unlock()

	if len(rfs.blockIndex) == 0 {
		return []string{}
	}

	numToPick := count
	if len(rfs.blockIndex) < count {
		numToPick = len(rfs.blockIndex)
	}

	// Shuffle indices to pick random, unique blocks.
	indices := mrand.Perm(len(rfs.blockIndex))
	pickedHashes := make([]string, numToPick)
	for i := 0; i < numToPick; i++ {
		pickedHashes[i] = rfs.blockIndex[indices[i]]
	}
	return pickedHashes
}

// loadBlockIndex populates the block index from the local storage directory on startup.
func (rfs *RandomFS) loadBlockIndex() {
	blocksDir := filepath.Join(rfs.dataDir, "blocks")
	entries, err := os.ReadDir(blocksDir)
	if err != nil {
		log.Printf("Warning: could not read blocks directory to populate index: %v", err)
		return
	}

	rfs.blockIndexMutex.Lock()
	defer rfs.blockIndexMutex.Unlock()
	for _, entry := range entries {
		if !entry.IsDir() {
			rfs.blockIndex = append(rfs.blockIndex, entry.Name())
		}
	}
	log.Printf("Loaded %d block hashes into index from local storage.", len(rfs.blockIndex))
}

// updateStats updates the statistics for the RandomFS instance
func (rfs *RandomFS) updateStats(updateFunc func(*Stats)) {
	rfs.stats.mutex.Lock()
	defer rfs.stats.mutex.Unlock()
	updateFunc(&rfs.stats)
}

// selectDecoyBlocks selects a number of random block hashes from the index for cover traffic.
func (rfs *RandomFS) selectDecoyBlocks(count int) []string {
	rfs.blockIndexMutex.Lock()
	defer rfs.blockIndexMutex.Unlock()

	if len(rfs.blockIndex) < 2 {
		return []string{} // Not enough blocks to select decoys
	}

	numToSelect := count
	if len(rfs.blockIndex) < count {
		numToSelect = len(rfs.blockIndex)
	}

	// Just select randomly from the index
	indices := mrand.Perm(len(rfs.blockIndex))
	decoys := make([]string, numToSelect)
	for i := 0; i < numToSelect; i++ {
		decoys[i] = rfs.blockIndex[indices[i]]
	}
	return decoys
}
