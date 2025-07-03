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
