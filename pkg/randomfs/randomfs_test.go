package randomfs

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

// setupTestFS creates a temporary RandomFS instance for testing
func setupTestFS(t *testing.T) (*RandomFS, func()) {
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

	return rfs, teardown
}

// TestStoreAndRetrieveFile tests basic file storage and retrieval
func TestStoreAndRetrieveFile(t *testing.T) {
	rfs, teardown := setupTestFS(t)
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
	rfs, teardown := setupTestFS(t)
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
	rfs, teardown := setupTestFS(t)
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
	rfs, teardown := setupTestFS(t)
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
