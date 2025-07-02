package randomfs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
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
	ProtocolVersion = "v4"

	// Default IPFS API endpoint
	DefaultIPFSEndpoint = "http://localhost:5001"
)

// RandomFS represents the main filesystem instance
type RandomFS struct {
	ipfsAPI         string
	dataDir         string
	blockCache      *BlockCache
	mutex           sync.RWMutex
	useLocalStorage bool

	// Statistics
	stats Stats
}

// Stats holds system statistics
type Stats struct {
	FilesStored     int64 `json:"files_stored"`
	BlocksGenerated int64 `json:"blocks_generated"`
	TotalSize       int64 `json:"total_size"`
	CacheHits       int64 `json:"cache_hits"`
	CacheMisses     int64 `json:"cache_misses"`
}

// BlockCache manages block storage and retrieval
type BlockCache struct {
	blocks      map[string][]byte
	mutex       sync.RWMutex
	maxSize     int64
	currentSize int64
}

// FileRepresentation contains the metadata needed to reconstruct a file
type FileRepresentation struct {
	FileName    string     `json:"filename"`
	FileSize    int64      `json:"filesize"`
	BlockHashes []string   `json:"block_hashes"`
	BlockSize   int        `json:"block_size"`
	Timestamp   int64      `json:"timestamp"`
	ContentType string     `json:"content_type"`
	Version     string     `json:"version"`
	Descriptors [][]string `json:"descriptors"` // OFF System descriptor lists
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
		ipfsAPI:         ipfsAPI,
		dataDir:         dataDir,
		useLocalStorage: skipIPFSTest,
		blockCache: &BlockCache{
			blocks:  make(map[string][]byte),
			maxSize: cacheSize,
		},
	}

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
	rfs.mutex.RLock()
	defer rfs.mutex.RUnlock()
	return rfs.stats
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

// StoreFile stores a file in the randomized block format using OFF System algorithm
func (rfs *RandomFS) StoreFile(filename string, data []byte, contentType string) (*RandomURL, error) {
	rfs.mutex.Lock()
	defer rfs.mutex.Unlock()

	// Determine block size based on file size
	blockSize := rfs.selectBlockSize(int64(len(data)))

	// Generate randomized blocks using OFF System algorithm
	blocks, err := GenerateRandomBlocks(data, blockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate blocks: %v", err)
	}

	// Store blocks and build descriptor lists
	var blockHashes []string
	var descriptors [][]string
	tupleSize := 3

	for i := 0; i < len(blocks); i += tupleSize {
		// Each tuple contains: [result_block, randomizer1, randomizer2]
		tuple := blocks[i : i+tupleSize]
		if len(tuple) < tupleSize {
			// Pad with random data if needed
			for len(tuple) < tupleSize {
				randomBlock := make([]byte, blockSize)
				if _, err := rand.Read(randomBlock); err != nil {
					return nil, fmt.Errorf("failed to generate padding: %v", err)
				}
				tuple = append(tuple, randomBlock)
			}
		}

		// Store each block in the tuple
		tupleHashes := make([]string, tupleSize)
		for j, block := range tuple {
			hash, err := rfs.storeBlock(block)
			if err != nil {
				return nil, fmt.Errorf("failed to store block: %v", err)
			}
			tupleHashes[j] = hash
			blockHashes = append(blockHashes, hash)
		}

		// Add descriptor for this tuple
		descriptors = append(descriptors, tupleHashes)
	}

	// Create file representation
	rep := &FileRepresentation{
		FileName:    filepath.Base(filename),
		FileSize:    int64(len(data)),
		BlockHashes: blockHashes,
		BlockSize:   blockSize,
		Timestamp:   time.Now().Unix(),
		ContentType: contentType,
		Version:     ProtocolVersion,
		Descriptors: descriptors,
	}

	// Store representation
	repData, err := json.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal representation: %v", err)
	}

	var repHash string
	if rfs.useLocalStorage {
		repHash, err = rfs.addToLocalStorage(repData, "representation")
	} else {
		repHash, err = rfs.addToIPFS(repData)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to store representation: %v", err)
	}

	// Update statistics
	rfs.stats.FilesStored++
	rfs.stats.BlocksGenerated += int64(len(blocks))
	rfs.stats.TotalSize += int64(len(data))

	// Create RandomURL
	randomURL := &RandomURL{
		Scheme:    "rfs",
		Host:      "randomfs",
		Version:   ProtocolVersion,
		FileName:  rep.FileName,
		FileSize:  rep.FileSize,
		RepHash:   repHash,
		Timestamp: rep.Timestamp,
	}

	log.Printf("Stored file %s (%d bytes) with %d blocks, representation hash: %s",
		filename, len(data), len(blocks), repHash)

	return randomURL, nil
}

// RetrieveFile retrieves and reconstructs a file from its representation hash using OFF System algorithm
func (rfs *RandomFS) RetrieveFile(repHash string) ([]byte, *FileRepresentation, error) {
	// Retrieve representation
	var repData []byte
	var err error
	if rfs.useLocalStorage {
		repData, err = rfs.catFromLocalStorage(repHash, "representation")
	} else {
		repData, err = rfs.catFromIPFS(repHash)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve representation: %v", err)
	}

	var rep FileRepresentation
	if err := json.Unmarshal(repData, &rep); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal representation: %v", err)
	}

	// Retrieve and combine blocks using OFF System algorithm
	var reconstructed bytes.Buffer
	blockIndex := 0

	for _, descriptor := range rep.Descriptors {
		// Retrieve all blocks in this descriptor tuple
		tupleBlocks := make([][]byte, len(descriptor))
		for i, blockHash := range descriptor {
			blockData, err := rfs.retrieveBlock(blockHash)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to retrieve block %d: %v", i, err)
			}
			tupleBlocks[i] = blockData
		}

		// Perform OFF System reconstruction: s_i = b_1 ⊕ b_2 ⊕ ... ⊕ b_t
		reconstructedBlock := make([]byte, rep.BlockSize)
		copy(reconstructedBlock, tupleBlocks[0]) // Start with first block

		// XOR with all other blocks in the tuple
		for i := 1; i < len(tupleBlocks); i++ {
			XORBlocksInPlace(reconstructedBlock, tupleBlocks[i])
		}

		// Determine how much data to write (handle last block)
		remaining := rep.FileSize - int64(reconstructed.Len())
		if remaining <= int64(rep.BlockSize) {
			// Last block - only write the actual data
			reconstructed.Write(reconstructedBlock[:remaining])
		} else {
			// Full block
			reconstructed.Write(reconstructedBlock)
		}

		blockIndex++
	}

	log.Printf("Retrieved file %s (%d bytes) from %d descriptor tuples",
		rep.FileName, rep.FileSize, len(rep.Descriptors))

	return reconstructed.Bytes(), &rep, nil
}

// GenerateRandomBlocks creates randomized blocks using the OFF System algorithm
func GenerateRandomBlocks(data []byte, blockSize int) ([][]byte, error) {
	var blocks [][]byte
	tupleSize := 3 // Default tuple size as per OFF System

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
		randomizers := make([][]byte, tupleSize-1)
		for i := 0; i < tupleSize-1; i++ {
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

	// Cache locally for faster access
	rfs.blockCache.mutex.Lock()
	defer rfs.blockCache.mutex.Unlock()

	rfs.blockCache.blocks[hash] = block
	rfs.blockCache.currentSize += int64(len(block))

	// Simple cache eviction if over limit
	if rfs.blockCache.currentSize > rfs.blockCache.maxSize {
		rfs.evictOldestBlocks()
	}

	return hash, nil
}

// retrieveBlock retrieves a block from cache or IPFS
func (rfs *RandomFS) retrieveBlock(hash string) ([]byte, error) {
	// Check cache first
	rfs.blockCache.mutex.RLock()
	if block, exists := rfs.blockCache.blocks[hash]; exists {
		rfs.blockCache.mutex.RUnlock()
		rfs.stats.CacheHits++
		return block, nil
	}
	rfs.blockCache.mutex.RUnlock()

	// Retrieve from storage
	rfs.stats.CacheMisses++
	if rfs.useLocalStorage {
		return rfs.catFromLocalStorage(hash, "block")
	}
	return rfs.catFromIPFS(hash)
}

// evictOldestBlocks removes oldest blocks from cache
func (rfs *RandomFS) evictOldestBlocks() {
	// Simple implementation - remove half the cache
	target := rfs.blockCache.maxSize / 2
	for hash, block := range rfs.blockCache.blocks {
		delete(rfs.blockCache.blocks, hash)
		rfs.blockCache.currentSize -= int64(len(block))
		if rfs.blockCache.currentSize <= target {
			break
		}
	}
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

// addToIPFS adds data to IPFS using HTTP API
func (rfs *RandomFS) addToIPFS(data []byte) (string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", "data")
	if err != nil {
		return "", err
	}

	if _, err := part.Write(data); err != nil {
		return "", err
	}

	if err := writer.Close(); err != nil {
		return "", err
	}

	resp, err := http.Post(rfs.ipfsAPI+"/api/v0/add", writer.FormDataContentType(), &buf)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IPFS add failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Hash string `json:"Hash"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Hash, nil
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
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid rfs:// URL format")
	}

	fileSize, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid file size: %v", err)
	}

	timestamp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %v", err)
	}

	return &RandomURL{
		Scheme:    u.Scheme,
		Host:      u.Host,
		Version:   parts[0],
		FileName:  parts[2],
		FileSize:  fileSize,
		RepHash:   parts[4],
		Timestamp: timestamp,
	}, nil
}

// String returns the string representation of a RandomURL
func (ru *RandomURL) String() string {
	return fmt.Sprintf("rfs://%s/%s/%d/%s/%d/%s",
		ru.Host, ru.Version, ru.FileSize, ru.FileName, ru.Timestamp, ru.RepHash)
}
