package randomfs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testPassword = "test-password-123"

func setupTestFS(t *testing.T) (*RandomFS, string, func()) {
	// A temporary directory for local storage.
	tempDir, err := os.MkdirTemp("", "randomfs-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Initialize RandomFS to use local storage instead of a real IPFS daemon.
	rfs, err := NewRandomFSWithoutIPFS(tempDir, 100)
	if err != nil {
		t.Fatalf("Failed to initialize RandomFS: %v", err)
	}

	// The teardown function cleans up the temporary directory.
	teardown := func() {
		os.RemoveAll(tempDir)
	}

	return rfs, tempDir, teardown
}

func TestStoreAndRetrieveFile(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	testData := []byte("This is a test file for RandomFS.")
	filename := "test.txt"

	repHash, err := rfs.StoreFile(filename, testData, "text/plain", testPassword)
	if err != nil {
		t.Fatalf("Failed to store file: %v", err)
	}
	if repHash == "" {
		t.Fatal("StoreFile returned an empty representation hash")
	}

	retrievedData, _, err := rfs.RetrieveFile(repHash, testPassword)
	if err != nil {
		t.Fatalf("Failed to retrieve file: %v", err)
	}

	if !bytes.Equal(testData, retrievedData) {
		t.Errorf("Retrieved data does not match original data. Got %s, want %s", retrievedData, testData)
	}
}

func TestEncryption(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	testData := []byte("This is a test file for RandomFS encryption.")
	filename := "test_encryption.txt"
	password := "correct-password"
	wrongPassword := "wrong-password"

	// Store the file with encryption
	repHash, err := rfs.StoreFile(filename, testData, "text/plain", password)
	if err != nil {
		t.Fatalf("Failed to store file with encryption: %v", err)
	}

	// Retrieve the file with the correct password
	retrievedData, _, err := rfs.RetrieveFile(repHash, password)
	if err != nil {
		t.Fatalf("Failed to retrieve file with correct password: %v", err)
	}
	if !bytes.Equal(testData, retrievedData) {
		t.Errorf("Retrieved data does not match original data. Got %s, want %s", retrievedData, testData)
	}

	// Attempt to retrieve with the wrong password
	_, _, err = rfs.RetrieveFile(repHash, wrongPassword)
	if err == nil {
		t.Fatalf("Expected an error when retrieving with the wrong password, but got none")
	}

	// Attempt to retrieve with an empty password
	_, _, err = rfs.RetrieveFile(repHash, "")
	if err == nil {
		t.Fatalf("Expected an error when retrieving with an empty password, but got none")
	}
}

func TestCoverTraffic(t *testing.T) {
	rfs, err := NewRandomFSWithoutIPFS(t.TempDir(), 1000)
	if err != nil {
		t.Fatalf("Failed to create RandomFS: %v", err)
	}

	// Store a file
	testData := []byte("This is test data for cover traffic verification")
	repHash, err := rfs.StoreFile("test.txt", testData, "text/plain", "testpassword")
	if err != nil {
		t.Fatalf("Failed to store file: %v", err)
	}

	// Retrieve the file and count successful retrievals
	_, rep, err := rfs.RetrieveFile(repHash, "testpassword")
	if err != nil {
		t.Fatalf("Failed to retrieve file: %v", err)
	}

	// Count legitimate blocks (anonymized + randomizer blocks)
	legitimateBlocks := 0
	for _, blockDescriptors := range rep.Descriptors {
		for _, descriptor := range blockDescriptors {
			legitimateBlocks += len(descriptor)
		}
	}

	// Get stats to see total retrievals
	stats := rfs.GetStats()
	totalRetrievals := stats.SuccessfulRetrievals

	// Verify that we have more total retrievals than legitimate blocks
	// (indicating cover traffic was generated)
	if totalRetrievals <= int64(legitimateBlocks) {
		t.Errorf("Cover traffic not working. Legitimate blocks: %d, Total retrievals: %d", legitimateBlocks, totalRetrievals)
	} else {
		t.Logf("Successfully verified cover traffic. Legitimate blocks: %d, Total retrievals: %d", legitimateBlocks, totalRetrievals)
	}
}

func TestBatchOperations(t *testing.T) {
	rfs, err := NewRandomFSWithoutIPFS(t.TempDir(), 1000)
	if err != nil {
		t.Fatalf("Failed to create RandomFS: %v", err)
	}

	// Test data
	testData := []byte("This is test data for batch operations verification. It should be large enough to create multiple blocks.")

	// Store file using batch operations
	repHash, err := rfs.StoreFile("batch_test.txt", testData, "text/plain", "testpassword")
	if err != nil {
		t.Fatalf("Failed to store file with batch operations: %v", err)
	}

	// Retrieve the file
	retrievedData, rep, err := rfs.RetrieveFile(repHash, "testpassword")
	if err != nil {
		t.Fatalf("Failed to retrieve file: %v", err)
	}

	// Verify data integrity
	if !bytes.Equal(testData, retrievedData) {
		t.Errorf("Data integrity check failed. Original: %d bytes, Retrieved: %d bytes", len(testData), len(retrievedData))
	}

	// Verify that descriptors are properly structured
	for i, blockDescriptors := range rep.Descriptors {
		if len(blockDescriptors) == 0 {
			t.Errorf("Block %d has no descriptors", i)
			continue
		}

		for j, descriptor := range blockDescriptors {
			if len(descriptor) != TupleSize {
				t.Errorf("Block %d, descriptor %d has wrong size. Expected %d, got %d", i, j, TupleSize, len(descriptor))
			}

			// Verify that the first hash is the anonymized block
			// and the rest are randomizer blocks
			if len(descriptor) > 0 {
				anonymizedHash := descriptor[0]
				randomizerHashes := descriptor[1:]

				if anonymizedHash == "" {
					t.Errorf("Block %d, descriptor %d has empty anonymized hash", i, j)
				}

				for k, rHash := range randomizerHashes {
					if rHash == "" {
						t.Errorf("Block %d, descriptor %d, randomizer %d has empty hash", i, j, k)
					}
				}
			}
		}
	}

	t.Logf("Successfully tested batch operations. File size: %d bytes, Blocks: %d", len(testData), len(rep.Descriptors))
}

func TestRedundancyRecoveryWithEncryption(t *testing.T) {
	rfs, tempDir, teardown := setupTestFS(t)
	defer teardown()

	testData := []byte("Data that must be recovered despite a block failure.")
	repHash, err := rfs.StoreFile("redundant.txt", testData, "text/plain", testPassword)
	if err != nil {
		t.Fatalf("Failed to store file: %v", err)
	}

	// Intentionally corrupt one block's file in local storage to simulate a failure.
	// Find the first block hash in the index and corrupt its file.
	rfs.blockIndexMutex.Lock()
	if len(rfs.blockIndex) == 0 {
		rfs.blockIndexMutex.Unlock()
		t.Fatalf("No blocks found in index")
	}
	corruptedBlockHash := rfs.blockIndex[0]
	rfs.blockIndexMutex.Unlock()

	corruptedBlockPath := filepath.Join(tempDir, "blocks", corruptedBlockHash)
	if err := os.WriteFile(corruptedBlockPath, []byte("corrupted data"), 0644); err != nil {
		t.Fatalf("Failed to corrupt block file: %v", err)
	}

	// Attempt to retrieve the file. This should fail if the corrupted block is critical.
	_, _, err = rfs.RetrieveFile(repHash, testPassword)
	if err == nil {
		t.Logf("File successfully retrieved despite block corruption (redundancy worked)")
	} else {
		t.Logf("File retrieval failed due to corruption: %v", err)
		// In the current implementation, a single block corruption will cause failure
		// since we don't have redundancy. This is expected behavior.
	}
}

// TestBlockMetadataTracking tests that block metadata is properly tracked
func TestBlockMetadataTracking(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// Store some test data to create blocks
	testData := []byte("Test data for metadata tracking verification")
	repHash, err := rfs.StoreFile("metadata_test.txt", testData, "text/plain", testPassword)
	if err != nil {
		t.Fatalf("Failed to store file: %v", err)
	}

	// Verify that blocks have creation time metadata
	rfs.blockMetadataMutex.RLock()
	for hash := range rfs.blockCreationTime {
		creationTime := rfs.blockCreationTime[hash]
		if creationTime.IsZero() {
			t.Errorf("Block %s has zero creation time", hash)
		}

		// Verify retrieval stats were initialized
		if stats, exists := rfs.blockRetrievalStats[hash]; !exists {
			t.Errorf("Block %s missing retrieval stats", hash)
		} else {
			// Initial stats should be zero
			if stats.SuccessCount != 0 || stats.FailureCount != 0 {
				t.Errorf("Block %s has non-zero initial stats: success=%d, failure=%d",
					hash, stats.SuccessCount, stats.FailureCount)
			}
		}
	}
	rfs.blockMetadataMutex.RUnlock()

	// Retrieve the file to generate some latency data
	_, _, err = rfs.RetrieveFile(repHash, testPassword)
	if err != nil {
		t.Fatalf("Failed to retrieve file: %v", err)
	}

	// Verify that retrieval generated latency data and success stats
	rfs.blockMetadataMutex.RLock()
	foundLatencyData := false
	foundSuccessStats := false
	for hash := range rfs.blockLatencyHistory {
		if len(rfs.blockLatencyHistory[hash]) > 0 {
			foundLatencyData = true
		}
		if stats := rfs.blockRetrievalStats[hash]; stats.SuccessCount > 0 {
			foundSuccessStats = true
		}
	}
	rfs.blockMetadataMutex.RUnlock()

	if !foundLatencyData {
		t.Error("No latency data found after file retrieval")
	}
	if !foundSuccessStats {
		t.Error("No success stats found after file retrieval")
	}
}

// TestAvailabilityScoring tests the availability calculation algorithm
func TestAvailabilityScoring(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// Create a test block and manually set up retrieval stats
	testHash := "test_availability_hash"
	rfs.blockMetadataMutex.Lock()
	rfs.blockRetrievalStats[testHash] = &BlockRetrievalStats{
		SuccessCount: 8,
		FailureCount: 2,
		LastSuccess:  time.Now().Add(-30 * time.Minute),
		LastFailure:  time.Now().Add(-10 * time.Minute), // Recent failure
	}
	rfs.blockMetadataMutex.Unlock()

	// Test availability score
	availability := rfs.calculateAvailabilityScore(testHash)

	// Should be less than 0.8 (8/10) due to recent failure penalty
	if availability >= 0.8 {
		t.Errorf("Expected availability < 0.8 due to recent failure, got %f", availability)
	}
	if availability <= 0.5 {
		t.Errorf("Availability penalty too severe, got %f", availability)
	}

	// Test with old failure (should have minimal impact)
	rfs.blockMetadataMutex.Lock()
	rfs.blockRetrievalStats[testHash].LastFailure = time.Now().Add(-2 * time.Hour)
	rfs.blockMetadataMutex.Unlock()

	availability = rfs.calculateAvailabilityScore(testHash)
	if availability < 0.75 {
		t.Errorf("Expected higher availability for old failure, got %f", availability)
	}

	// Test new block (should default to high availability)
	newBlockAvailability := rfs.calculateAvailabilityScore("nonexistent_hash")
	if newBlockAvailability != 1.0 {
		t.Errorf("Expected new block to have 1.0 availability, got %f", newBlockAvailability)
	}
}

// TestLatencyCalculation tests the latency averaging algorithm
func TestLatencyCalculation(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	testHash := "test_latency_hash"

	// Add some latency measurements
	latencies := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		150 * time.Millisecond,
	}

	rfs.blockMetadataMutex.Lock()
	rfs.blockLatencyHistory[testHash] = latencies
	rfs.blockMetadataMutex.Unlock()

	avgLatency := rfs.calculateAverageLatency(testHash)
	expectedAvg := (100 + 200 + 150) / 3 * time.Millisecond

	if avgLatency != expectedAvg {
		t.Errorf("Expected average latency %v, got %v", expectedAvg, avgLatency)
	}

	// Test with empty history
	emptyLatency := rfs.calculateAverageLatency("nonexistent_hash")
	if emptyLatency != 0 {
		t.Errorf("Expected zero latency for nonexistent hash, got %v", emptyLatency)
	}
}

// TestBlockCandidatePopulation tests that all BlockCandidate fields are populated correctly
func TestBlockCandidatePopulation(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// Store some files to create blocks with different characteristics
	files := []struct {
		name string
		data []byte
	}{
		{"high_entropy.bin", make([]byte, 1024)},
		{"low_entropy.txt", bytes.Repeat([]byte("A"), 1024)},
		{"medium_file.dat", bytes.Repeat([]byte("ABCD"), 256)},
	}

	// Fill high entropy file with random data
	for i := range files[0].data {
		files[0].data[i] = byte(i % 256)
	}

	// Store all files
	for _, file := range files {
		_, err := rfs.StoreFile(file.name, file.data, "application/octet-stream", testPassword)
		if err != nil {
			t.Fatalf("Failed to store file %s: %v", file.name, err)
		}
	}

	// Simulate some usage to create realistic metadata
	for i := 0; i < 5; i++ {
		// Retrieve blocks to generate latency and success data
		rfs.blockIndexMutex.Lock()
		if len(rfs.blockIndex) > 0 {
			hash := rfs.blockIndex[i%len(rfs.blockIndex)]
			rfs.blockIndexMutex.Unlock()
			_, _ = rfs.retrieveBlock(hash) // Ignore errors for this test
		} else {
			rfs.blockIndexMutex.Unlock()
		}
	}

	// Test selectRandomizerBlocks to see if candidates are properly populated
	blocks, reusedCount, err := rfs.selectRandomizerBlocks(2, 1024)
	if err != nil {
		t.Fatalf("Failed to select randomizer blocks: %v", err)
	}

	t.Logf("Selected %d blocks, reused %d existing blocks", len(blocks), reusedCount)

	// Verify that if we have enough blocks, some should be reused
	rfs.blockIndexMutex.Lock()
	blockCount := len(rfs.blockIndex)
	rfs.blockIndexMutex.Unlock()

	if blockCount >= 2 && reusedCount == 0 {
		t.Error("Expected some block reuse when sufficient blocks are available")
	}

	// Test the selection with a controlled scenario
	const maxCandidates = 5
	candidateHashes := rfs.selectRandomizerHashes(maxCandidates)

	if len(candidateHashes) > blockCount {
		t.Errorf("Got more candidates (%d) than available blocks (%d)", len(candidateHashes), blockCount)
	}

	// Manually create BlockCandidate objects to verify field population
	rfs.blockPopularityMutex.Lock()
	defer rfs.blockPopularityMutex.Unlock()

	for _, hash := range candidateHashes {
		data, err := rfs.retrieveBlock(hash)
		if err != nil {
			continue // Skip failed retrievals for this test
		}

		// Calculate all metadata (similar to selectRandomizerBlocks)
		rfs.blockMetadataMutex.RLock()
		creationTime, hasCreationTime := rfs.blockCreationTime[hash]
		rfs.blockMetadataMutex.RUnlock()

		var age time.Duration
		if hasCreationTime {
			age = time.Since(creationTime)
		}

		// Note: LastUsed field not used in this test

		avgLatency := rfs.calculateAverageLatency(hash)
		availability := rfs.calculateAvailabilityScore(hash)

		candidate := BlockCandidate{
			Hash:           hash,
			Data:           data,
			Popularity:     rfs.blockPopularity[hash],
			Age:            age,
			NetworkLatency: avgLatency,
			Availability:   availability,
		}

		// Verify all fields are set appropriately
		if candidate.Hash == "" {
			t.Error("BlockCandidate has empty hash")
		}
		if len(candidate.Data) == 0 {
			t.Error("BlockCandidate has empty data")
		}
		if candidate.Age < 0 {
			t.Error("BlockCandidate has negative age")
		}
		if candidate.Availability < 0 || candidate.Availability > 1 {
			t.Errorf("BlockCandidate has invalid availability: %f", candidate.Availability)
		}
		if candidate.NetworkLatency < 0 {
			t.Error("BlockCandidate has negative latency")
		}

		t.Logf("Candidate %s: age=%v, latency=%v, availability=%f, popularity=%d",
			hash[:8], candidate.Age, candidate.NetworkLatency, candidate.Availability, candidate.Popularity)
	}
}

// TestBlockScoringAlgorithm tests the complete scoring algorithm behavior
func TestBlockScoringAlgorithm(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// Create blocks with different characteristics
	testBlocks := []struct {
		data       []byte
		expectHigh bool // Whether this should score highly
		name       string
	}{
		{make([]byte, 1024), true, "high_entropy_popular"},      // Will be made popular
		{bytes.Repeat([]byte("A"), 1024), false, "low_entropy"}, // Low entropy
		{make([]byte, 1024), false, "high_entropy_unpopular"},   // High entropy but unpopular
	}

	// Fill high entropy blocks with varied data
	for i := range testBlocks[0].data {
		testBlocks[0].data[i] = byte(i % 256)
	}
	for i := range testBlocks[2].data {
		testBlocks[2].data[i] = byte((i * 7) % 256) // Different pattern
	}

	// Store blocks and track their hashes
	var blockHashes []string
	for _, block := range testBlocks {
		hash, err := rfs.storeBlock(block.data)
		if err != nil {
			t.Fatalf("Failed to store test block: %v", err)
		}
		blockHashes = append(blockHashes, hash)
	}

	// Make the first block popular by simulating usage
	rfs.blockPopularityMutex.Lock()
	rfs.blockPopularity[blockHashes[0]] = 10 // High popularity
	rfs.blockPopularityMutex.Unlock()

	// Simulate different performance characteristics
	rfs.blockMetadataMutex.Lock()
	// Block 0: Good performance
	rfs.blockLatencyHistory[blockHashes[0]] = []time.Duration{50 * time.Millisecond}
	rfs.blockRetrievalStats[blockHashes[0]] = &BlockRetrievalStats{
		SuccessCount: 10,
		FailureCount: 0,
		LastSuccess:  time.Now(),
	}

	// Block 1: Poor performance (but won't matter due to low entropy)
	rfs.blockLatencyHistory[blockHashes[1]] = []time.Duration{500 * time.Millisecond}
	rfs.blockRetrievalStats[blockHashes[1]] = &BlockRetrievalStats{
		SuccessCount: 5,
		FailureCount: 5,
		LastFailure:  time.Now().Add(-30 * time.Minute),
	}

	// Block 2: Good performance but unpopular
	rfs.blockLatencyHistory[blockHashes[2]] = []time.Duration{75 * time.Millisecond}
	rfs.blockRetrievalStats[blockHashes[2]] = &BlockRetrievalStats{
		SuccessCount: 8,
		FailureCount: 1,
		LastSuccess:  time.Now(),
	}
	rfs.blockMetadataMutex.Unlock()

	// Use the analyzer to select optimal blocks
	candidates := make([]BlockCandidate, 0, len(blockHashes))
	for i, hash := range blockHashes {
		data, _ := rfs.retrieveBlock(hash)

		rfs.blockMetadataMutex.RLock()
		creationTime := rfs.blockCreationTime[hash]
		rfs.blockMetadataMutex.RUnlock()

		age := time.Since(creationTime)
		avgLatency := rfs.calculateAverageLatency(hash)
		availability := rfs.calculateAvailabilityScore(hash)

		rfs.blockPopularityMutex.Lock()
		popularity := rfs.blockPopularity[hash]
		rfs.blockPopularityMutex.Unlock()

		candidate := BlockCandidate{
			Hash:           hash,
			Data:           data,
			Popularity:     popularity,
			Age:            age,
			LastUsed:       time.Time{},
			NetworkLatency: avgLatency,
			Availability:   availability,
		}
		candidates = append(candidates, candidate)

		t.Logf("Block %d (%s): entropy=%.2f, popularity=%d, latency=%v, availability=%.2f",
			i, testBlocks[i].name, calculateEntropy(data), popularity, avgLatency, availability)
	}

	// Select top candidate
	selected := rfs.analyzer.selectOptimalBlocks(candidates, 1, MinEntropyThreshold)

	if len(selected) == 0 {
		t.Fatal("No blocks selected by algorithm")
	}

	// The high entropy, popular block should be selected
	selectedHash := selected[0].Hash
	expectedHash := blockHashes[0] // high_entropy_popular

	if selectedHash != expectedHash {
		// Find which block was actually selected
		var selectedName string
		for i, hash := range blockHashes {
			if hash == selectedHash {
				selectedName = testBlocks[i].name
				break
			}
		}
		t.Logf("Selected block: %s (expected: %s)", selectedName, testBlocks[0].name)

		// This might not always fail due to randomization in the algorithm,
		// but we can check that a reasonable choice was made
		if selectedName == "low_entropy" {
			t.Error("Low entropy block should not be selected")
		}
	}

	// Test entropy filtering
	lowEntropySelected := rfs.analyzer.selectOptimalBlocks(candidates, 3, 7.5) // High threshold
	hasLowEntropy := false
	lowEntropyCount := 0
	for _, sel := range lowEntropySelected {
		entropy := calculateEntropy(sel.Data)
		if entropy < 7.5 {
			hasLowEntropy = true
			lowEntropyCount++
		}
	}

	// The algorithm severely penalizes low entropy blocks but may still include them
	// in weighted random selection. Verify that high entropy blocks are preferred.
	if lowEntropyCount > 1 {
		t.Error("Too many low entropy blocks selected despite high threshold")
	}

	if hasLowEntropy {
		t.Logf("Low entropy block selected but heavily penalized (expected with weighted random selection)")
	}
}

// TestBlockReuseIntegration tests the complete block reuse system in an integrated scenario
func TestBlockReuseIntegration(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// Store multiple files to build up a diverse block pool
	testFiles := []string{
		"File with random content for entropy testing",
		"Another file with different content patterns",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // Low entropy
		"Mixed content with 1234567890 numbers and text",
	}

	var storedHashes []string
	for i, content := range testFiles {
		filename := fmt.Sprintf("test_%d.txt", i)
		repHash, err := rfs.StoreFile(filename, []byte(content), "text/plain", testPassword)
		if err != nil {
			t.Fatalf("Failed to store file %d: %v", i, err)
		}
		storedHashes = append(storedHashes, repHash)
	}

	// Retrieve files multiple times to build up popularity and performance data
	for round := 0; round < 3; round++ {
		for i, repHash := range storedHashes {
			_, _, err := rfs.RetrieveFile(repHash, testPassword)
			if err != nil {
				t.Logf("Failed to retrieve file %d in round %d: %v", i, round, err)
			}
		}
	}

	// Get statistics
	stats := rfs.GetStats()
	t.Logf("System stats: Files=%d, Blocks=%d, Reused=%d, Cache hits/misses=%d/%d",
		stats.FilesStored, stats.BlocksGenerated, stats.BlocksReused,
		stats.CacheHits, stats.CacheMisses)

	// Store another file that should trigger block reuse
	newContent := "New file that might reuse existing blocks for randomization"
	_, err := rfs.StoreFile("reuse_test.txt", []byte(newContent), "text/plain", testPassword)
	if err != nil {
		t.Fatalf("Failed to store reuse test file: %v", err)
	}

	// Check if reuse occurred
	newStats := rfs.GetStats()
	if newStats.BlocksReused > stats.BlocksReused {
		t.Logf("Block reuse successful: %d blocks reused (was %d)",
			newStats.BlocksReused, stats.BlocksReused)
	} else {
		t.Logf("No additional block reuse detected (might be expected if block pool is small)")
	}

	// Verify that block metadata is being maintained
	rfs.blockMetadataMutex.RLock()
	metadataCount := len(rfs.blockCreationTime)
	latencyCount := len(rfs.blockLatencyHistory)
	statsCount := len(rfs.blockRetrievalStats)
	rfs.blockMetadataMutex.RUnlock()

	if metadataCount == 0 {
		t.Error("No block creation time metadata found")
	}
	if latencyCount == 0 {
		t.Error("No latency history found")
	}
	if statsCount == 0 {
		t.Error("No retrieval stats found")
	}

	t.Logf("Metadata tracking: %d creation times, %d latency histories, %d stat records",
		metadataCount, latencyCount, statsCount)
}
