package randomfs

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// setupTestFS creates a temporary RandomFS instance for testing
func setupTestFS(t *testing.T) (*RandomFS, string, func()) {
	// Create a temporary directory for test data
	tempDir, err := ioutil.TempDir("", "randomfs-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Initialize RandomFS with local storage for testing
	rfs, err := NewRandomFSWithoutIPFS(tempDir, 10*1024*1024) // 10MB cache
	if err != nil {
		t.Fatalf("Failed to create RandomFS: %v", err)
	}

	// Teardown function to clean up
	teardown := func() {
		os.RemoveAll(tempDir)
	}

	return rfs, tempDir, teardown
}

// TestStoreAndRetrieveFile tests basic file storage and retrieval
func TestStoreAndRetrieveFile(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// Test data
	testData := []byte("Hello, this is a test file for RandomFS.")
	testFilename := "testfile.txt"

	// Store the file
	url, err := rfs.StoreFile(testFilename, testData, "text/plain")
	if err != nil {
		t.Fatalf("StoreFile failed: %v", err)
	}
	if url == nil {
		t.Fatal("StoreFile returned a nil URL")
	}

	// Retrieve the file
	retrievedData, _, err := rfs.RetrieveFile(url.RepHash)
	if err != nil {
		t.Fatalf("RetrieveFile failed: %v", err)
	}

	// Compare original and retrieved data
	if !bytes.Equal(testData, retrievedData) {
		t.Errorf("Retrieved data does not match original data.\nOriginal: %s\nRetrieved: %s", string(testData), string(retrievedData))
	}

	t.Logf("Successfully stored and retrieved file. URL: %s", url.String())
}

// TestEmptyFile tests storing and retrieving an empty file
func TestEmptyFile(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	testData := []byte{}
	testFilename := "empty.txt"

	url, err := rfs.StoreFile(testFilename, testData, "text/plain")
	if err != nil {
		t.Fatalf("StoreFile failed for empty file: %v", err)
	}

	retrievedData, _, err := rfs.RetrieveFile(url.RepHash)
	if err != nil {
		t.Fatalf("RetrieveFile failed for empty file: %v", err)
	}

	if len(retrievedData) != 0 {
		t.Errorf("Expected empty data, got %d bytes", len(retrievedData))
	}
}

// TestLargeFile tests storing and retrieving a file larger than a single block
func TestLargeFile(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// Create large test data (e.g., 2.5 MB)
	largeData := make([]byte, int(2.5*1024*1024))
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	testFilename := "largefile.bin"

	url, err := rfs.StoreFile(testFilename, largeData, "application/octet-stream")
	if err != nil {
		t.Fatalf("StoreFile failed for large file: %v", err)
	}

	retrievedData, _, err := rfs.RetrieveFile(url.RepHash)
	if err != nil {
		t.Fatalf("RetrieveFile failed for large file: %v", err)
	}

	if !bytes.Equal(largeData, retrievedData) {
		t.Fatal("Retrieved large file data does not match original data.")
	}
}

// TestStreamingReader tests reading a file using the streaming API
func TestStreamingReader(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// Create large test data
	largeData := make([]byte, int(2.5*1024*1024))
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	testFilename := "largefile_stream.bin"

	// Store the file
	url, err := rfs.StoreFile(testFilename, largeData, "application/octet-stream")
	if err != nil {
		t.Fatalf("StoreFile failed for large file: %v", err)
	}

	// Open a stream reader
	reader, err := rfs.OpenStream(url.RepHash)
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	// Read all data from the stream
	retrievedData, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read from stream: %v", err)
	}

	// Compare original and retrieved data
	if !bytes.Equal(largeData, retrievedData) {
		t.Fatal("Retrieved stream data does not match original data.")
	}
	t.Logf("Successfully streamed and verified large file.")
}

// TestSmartCache tests the functionality of the multi-tier smart cache.
func TestSmartCache(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// 1. Store a file to populate the cache.
	testData := []byte("This is a test for the smart cache.")
	url, err := rfs.StoreFile("caching_test.txt", testData, "text/plain")
	if err != nil {
		t.Fatalf("StoreFile failed: %v", err)
	}

	rep, err := rfs.getRepresentation(url.RepHash)
	if err != nil {
		t.Fatalf("getRepresentation failed: %v", err)
	}

	// Get a block hash to test with.
	if len(rep.BlockHashes) == 0 {
		t.Fatal("No blocks were created for the test file.")
	}
	blockHash := rep.BlockHashes[0]

	// 2. Clear caches to ensure we start from a clean slate for this test.
	rfs.blockCache.hot.Purge()
	rfs.blockCache.warm.Purge()

	// 3. First retrieval should be a cache miss.
	initialStats := rfs.GetStats()
	_, err = rfs.retrieveBlock(blockHash)
	if err != nil {
		t.Fatalf("retrieveBlock failed: %v", err)
	}
	statsAfterMiss := rfs.GetStats()
	if statsAfterMiss.CacheMisses <= initialStats.CacheMisses {
		t.Errorf("Expected a cache miss, but miss count did not increase.")
	}
	if !rfs.blockCache.warm.Contains(blockHash) {
		t.Error("Block should be in the warm cache after a miss.")
	}

	// 4. Second retrieval should be a hit from the warm cache.
	statsBeforeHit := rfs.GetStats()
	_, err = rfs.retrieveBlock(blockHash)
	if err != nil {
		t.Fatalf("retrieveBlock failed: %v", err)
	}
	statsAfterHit := rfs.GetStats()
	if statsAfterHit.CacheHits <= statsBeforeHit.CacheHits {
		t.Errorf("Expected a cache hit, but hit count did not increase.")
	}

	// 5. Retrieve two more times to trigger promotion.
	_, _ = rfs.retrieveBlock(blockHash)
	_, _ = rfs.retrieveBlock(blockHash)

	// 6. Verify promotion to hot cache.
	if !rfs.blockCache.hot.Contains(blockHash) {
		t.Error("Block should be promoted to the hot cache after multiple accesses.")
	}
	if rfs.blockCache.warm.Contains(blockHash) {
		t.Error("Block should be removed from warm cache after promotion.")
	}
}

// TestRedundancyRecovery tests the file recovery using redundant blocks.
func TestRedundancyRecovery(t *testing.T) {
	rfs, tempDir, teardown := setupTestFS(t)
	defer teardown()

	rfs.RedundancyFactor = 2
	testData := []byte("This file will test the redundancy recovery.")
	url, err := rfs.StoreFile("recovery_test.txt", testData, "text/plain")
	if err != nil {
		t.Fatalf("StoreFile failed: %v", err)
	}

	rep, err := rfs.getRepresentation(url.RepHash)
	if err != nil {
		t.Fatalf("getRepresentation failed: %v", err)
	}

	// Corrupt the primary descriptor by deleting one of its blocks.
	if len(rep.Descriptors) == 0 || len(rep.Descriptors[0]) == 0 || len(rep.Descriptors[0][0]) == 0 {
		t.Fatal("Not enough descriptors to run the test.")
	}
	blockToCorrupt := rep.Descriptors[0][0][0] // Hash of the first block of the primary tuple.

	blockPath := filepath.Join(tempDir, "blocks", blockToCorrupt)
	if err := os.Remove(blockPath); err != nil {
		t.Fatalf("Failed to delete block file for corruption: %v", err)
	}

	// Now, try to retrieve the file. It should succeed by using the redundant descriptor.
	retrievedData, _, err := rfs.RetrieveFile(url.RepHash)
	if err != nil {
		t.Fatalf("RetrieveFile failed during recovery: %v", err)
	}

	if !bytes.Equal(testData, retrievedData) {
		t.Fatal("Recovered data does not match original data.")
	}
	t.Logf("Successfully recovered file using redundant descriptor.")
}

// TestNetworkHealthMonitoring tests the collection of network health metrics.
func TestNetworkHealthMonitoring(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// 1. Store a file and retrieve it.
	testData := []byte("This is a test for network health monitoring.")
	url, err := rfs.StoreFile("monitoring_test.txt", testData, "text/plain")
	if err != nil {
		t.Fatalf("StoreFile failed: %v", err)
	}

	initialStats := rfs.GetStats()
	_, _, err = rfs.RetrieveFile(url.RepHash)
	if err != nil {
		t.Fatalf("RetrieveFile failed: %v", err)
	}
	statsAfterSuccess := rfs.GetStats()

	rep, _ := rfs.getRepresentation(url.RepHash)
	// In the happy path, only the primary descriptors are used.
	expectedRetrievals := int64(len(rep.Descriptors) * TupleSize)

	if statsAfterSuccess.SuccessfulRetrievals != initialStats.SuccessfulRetrievals+expectedRetrievals {
		t.Errorf("Expected %d successful retrievals, but got %d",
			expectedRetrievals, statsAfterSuccess.SuccessfulRetrievals-initialStats.SuccessfulRetrievals)
	}
	if statsAfterSuccess.TotalRetrievalLatency <= initialStats.TotalRetrievalLatency {
		t.Error("Expected total retrieval latency to increase.")
	}

	// 2. Attempt to retrieve a non-existent block.
	statsBeforeFailure := rfs.GetStats()
	_, err = rfs.retrieveBlock("non-existent-hash")
	if err == nil {
		t.Error("Expected an error when retrieving a non-existent block, but got nil.")
	}
	statsAfterFailure := rfs.GetStats()

	if statsAfterFailure.BlockRetrievalFailures <= statsBeforeFailure.BlockRetrievalFailures {
		t.Error("Expected block retrieval failures to increase, but it did not.")
	}
}
