package randomfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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

func TestRedundancyRecoveryWithEncryption(t *testing.T) {
	rfs, tempDir, teardown := setupTestFS(t)
	defer teardown()

	testData := []byte("Data that must be recovered despite a block failure.")
	repHash, err := rfs.StoreFile("redundant.txt", testData, "text/plain", testPassword)
	if err != nil {
		t.Fatalf("Failed to store file for redundancy test: %v", err)
	}

	// Get the representation so we can find a block to delete
	encryptedRep, err := rfs.retrieveBlock(repHash)
	if err != nil {
		t.Fatalf("Failed to retrieve encrypted representation: %v", err)
	}
	rep, err := rfs.getRepresentation(encryptedRep, testPassword)
	if err != nil {
		t.Fatalf("Failed to get representation: %v", err)
	}

	if len(rep.Descriptors) == 0 || len(rep.Descriptors[0]) == 0 || len(rep.Descriptors[0][0]) < 2 {
		t.Fatal("Test setup error: No randomizer block found to delete")
	}
	blockToDelete := rep.Descriptors[0][0][1]

	blockPath := filepath.Join(tempDir, "blocks", blockToDelete)
	if err := os.Remove(blockPath); err != nil {
		t.Fatalf("Failed to delete block file %s: %v", blockPath, err)
	}

	retrievedData, _, err := rfs.RetrieveFile(repHash, testPassword)
	if err != nil {
		t.Fatalf("Failed to retrieve file after block deletion: %v", err)
	}

	if !bytes.Equal(testData, retrievedData) {
		t.Fatal("Retrieved data after recovery does not match original data")
	}
}

func TestCoverTraffic(t *testing.T) {
	rfs, _, teardown := setupTestFS(t)
	defer teardown()

	// Store a file to ensure there are blocks in the index to be used as decoys.
	testData := []byte("some data to test cover traffic")
	repHash, err := rfs.StoreFile("cover_traffic.txt", testData, "text/plain", testPassword)
	if err != nil {
		t.Fatalf("Failed to store file: %v", err)
	}

	// Wait a moment for the block index to be populated from the initial storage.
	// This is a simplification for the test; in reality, the index is updated in real-time.
	initialStats := rfs.GetStats()

	// Retrieve the file. This should trigger decoy block fetching.
	_, rep, err := rfs.RetrieveFile(repHash, testPassword)
	if err != nil {
		t.Fatalf("Failed to retrieve file: %v", err)
	}

	finalStats := rfs.GetStats()

	// Calculate the number of legitimate blocks that should have been fetched.
	// For this test, we assume no failures, so it's the number of blocks per descriptor.
	legitBlocks := len(rep.Descriptors) * TupleSize

	// The total number of successful retrievals should be the sum of legitimate blocks and decoy blocks.
	// We expect the number of retrievals to be greater than just the legitimate blocks.
	totalRetrievals := finalStats.SuccessfulRetrievals - initialStats.SuccessfulRetrievals
	if totalRetrievals <= int64(legitBlocks) {
		t.Errorf("Expected cover traffic to increase retrieval count beyond legitimate blocks. Got %d total retrievals, expected > %d", totalRetrievals, legitBlocks)
	}

	t.Logf("Successfully verified cover traffic. Legitimate blocks: %d, Total retrievals: %d", legitBlocks, totalRetrievals)
}
