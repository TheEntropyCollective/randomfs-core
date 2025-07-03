package randomfs

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSelectOptimalBlocks_Hybrid(t *testing.T) {
	analyzer := &ContentAnalyzer{}
	blockSize := 1024
	minEntropy := 6.5 // A threshold for this test

	// Candidate 1: Low entropy, high popularity (should be ignored due to low entropy)
	lowEntropyBlock := make([]byte, blockSize)
	candidateLow := BlockCandidate{Hash: "low", Data: lowEntropyBlock, Popularity: 100}

	// Candidate 2: High entropy, low popularity
	highEntropyBlock1 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock1)
	candidateHigh1 := BlockCandidate{Hash: "high1", Data: highEntropyBlock1, Popularity: 5}

	// Candidate 3: High entropy, high popularity (should be chosen first)
	highEntropyBlock2 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock2)
	candidateHigh2 := BlockCandidate{Hash: "high2", Data: highEntropyBlock2, Popularity: 50}

	// Candidate 4: High entropy, medium popularity (should be chosen second)
	highEntropyBlock3 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock3)
	candidateHigh3 := BlockCandidate{Hash: "high3", Data: highEntropyBlock3, Popularity: 20}

	// Candidate 5: Medium entropy, high popularity (should be ignored)
	mediumEntropyBlock := bytes.Repeat([]byte{0xDE, 0xAD}, blockSize/2)
	candidateMedium := BlockCandidate{Hash: "medium", Data: mediumEntropyBlock, Popularity: 200}

	candidates := []BlockCandidate{candidateLow, candidateHigh1, candidateHigh2, candidateHigh3, candidateMedium}

	// Test selecting the top two blocks
	t.Run("SelectBest_2_Hybrid", func(t *testing.T) {
		selected := analyzer.selectOptimalBlocks(candidates, 2, minEntropy)
		if len(selected) != 2 {
			t.Fatalf("Expected 2 blocks, got %d", len(selected))
		}
		// Expect the most popular of the high-entropy blocks first
		if selected[0].Hash != "high2" {
			t.Errorf("Expected first block to be 'high2' (most popular high-entropy), got '%s'", selected[0].Hash)
		}
		// Expect the second most popular high-entropy block second
		if selected[1].Hash != "high3" {
			t.Errorf("Expected second block to be 'high3' (second most popular high-entropy), got '%s'", selected[1].Hash)
		}
	})

	t.Run("EntropyFiltering", func(t *testing.T) {
		selected := analyzer.selectOptimalBlocks(candidates, 5, minEntropy)
		for _, s := range selected {
			if s.Hash == "low" || s.Hash == "medium" {
				t.Errorf("Block '%s' was selected but should have been filtered out due to low entropy", s.Hash)
			}
		}
		if len(selected) != 3 {
			t.Errorf("Expected 3 high-entropy blocks to be selected, but got %d", len(selected))
		}
	})
}
