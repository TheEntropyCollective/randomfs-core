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

func TestSelectOptimalBlocks_WeightedRandom(t *testing.T) {
	analyzer := &ContentAnalyzer{}
	blockSize := 1024
	minEntropy := 6.5

	// Candidate 1: Low entropy, high popularity (should never be selected)
	candidateLow := BlockCandidate{Hash: "low", Data: make([]byte, blockSize), Popularity: 500}

	// Candidate 2: High entropy, high popularity (should be selected most often)
	highEntropyBlock1 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock1)
	candidateHighPop := BlockCandidate{Hash: "high_pop", Data: highEntropyBlock1, Popularity: 50}

	// Candidate 3: High entropy, low popularity (should be selected less often)
	highEntropyBlock2 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock2)
	candidateLowPop := BlockCandidate{Hash: "low_pop", Data: highEntropyBlock2, Popularity: 5}

	candidates := []BlockCandidate{candidateLow, candidateHighPop, candidateLowPop}

	// Run the selection many times to check the distribution
	selectionCounts := make(map[string]int)
	iterations := 1000
	for i := 0; i < iterations; i++ {
		selected := analyzer.selectOptimalBlocks(candidates, 1, minEntropy)
		if len(selected) > 0 {
			selectionCounts[selected[0].Hash]++
		}
	}

	// 1. Check that the low entropy block was never selected
	if count, ok := selectionCounts["low"]; ok {
		t.Errorf("Low entropy block was selected %d times, expected 0", count)
	}

	// 2. Check that the high-popularity block was selected more than the low-popularity one
	highPopCount := selectionCounts["high_pop"]
	lowPopCount := selectionCounts["low_pop"]

	if highPopCount <= lowPopCount {
		t.Errorf("Expected high-popularity block to be selected more often, but got high_pop: %d, low_pop: %d", highPopCount, lowPopCount)
	}

	// 3. Check that the distribution is reasonable
	// The weights are (50+1) vs (5+1) = 51 vs 6. Expected ratio is ~8.5 : 1
	// We'll check for a ratio of at least 3:1 to avoid flaky tests.
	if highPopCount < lowPopCount*3 {
		t.Errorf("Selection distribution is skewed. Expected high_pop to be selected at least 3x more than low_pop, but got high_pop: %d, low_pop: %d", highPopCount, lowPopCount)
	}

	// 4. Check that only high-entropy blocks were selected
	totalSelections := highPopCount + lowPopCount
	if totalSelections != iterations {
		t.Errorf("Expected %d total selections of high-entropy blocks, but got %d", iterations, totalSelections)
	}

	t.Logf("Selection distribution after %d iterations: high_pop=%d, low_pop=%d", iterations, highPopCount, lowPopCount)
}
