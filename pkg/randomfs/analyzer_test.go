package randomfs

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSelectOptimalBlocks(t *testing.T) {
	analyzer := &ContentAnalyzer{}
	blockSize := 1024

	// Candidate 1: Low entropy (all zeros)
	lowEntropyBlock := make([]byte, blockSize)
	candidateLow := BlockCandidate{Hash: "low", Data: lowEntropyBlock}

	// Candidate 2: High entropy (random data)
	highEntropyBlock := make([]byte, blockSize)
	_, err := rand.Read(highEntropyBlock)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}
	candidateHigh := BlockCandidate{Hash: "high", Data: highEntropyBlock}

	// Candidate 3: Medium entropy (repeated pattern)
	mediumEntropyBlock := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, blockSize/4)
	candidateMedium := BlockCandidate{Hash: "medium", Data: mediumEntropyBlock}

	candidates := []BlockCandidate{candidateLow, candidateHigh, candidateMedium}

	// Test selecting the single best block
	t.Run("SelectBest_1", func(t *testing.T) {
		selected := analyzer.selectOptimalBlocks(candidates, 1)
		if len(selected) != 1 {
			t.Fatalf("Expected 1 block, got %d", len(selected))
		}
		if selected[0].Hash != "high" {
			t.Errorf("Expected block 'high' to be selected for its high entropy, but got '%s'", selected[0].Hash)
		}
	})

	// Test selecting the top two blocks
	t.Run("SelectBest_2", func(t *testing.T) {
		selected := analyzer.selectOptimalBlocks(candidates, 2)
		if len(selected) != 2 {
			t.Fatalf("Expected 2 blocks, got %d", len(selected))
		}
		if selected[0].Hash != "high" {
			t.Errorf("Expected first block to be 'high', got '%s'", selected[0].Hash)
		}
		if selected[1].Hash != "medium" {
			t.Errorf("Expected second block to be 'medium', got '%s'", selected[1].Hash)
		}
	})

	// Test entropy calculation sanity check
	t.Run("EntropyCalculation", func(t *testing.T) {
		entropyLow := calculateEntropy(candidateLow.Data)
		entropyMedium := calculateEntropy(candidateMedium.Data)
		entropyHigh := calculateEntropy(candidateHigh.Data)

		if entropyLow != 0 {
			t.Errorf("Expected entropy of all zeros to be 0, got %f", entropyLow)
		}
		if entropyMedium <= entropyLow {
			t.Errorf("Expected medium entropy (%f) to be greater than low entropy (%f)", entropyMedium, entropyLow)
		}
		if entropyHigh <= entropyMedium {
			t.Errorf("Expected high entropy (%f) to be greater than medium entropy (%f)", entropyHigh, entropyMedium)
		}
		t.Logf("Entropies: Low=%.2f, Medium=%.2f, High=%.2f", entropyLow, entropyMedium, entropyHigh)
	})
}
