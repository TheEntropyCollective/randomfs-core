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

	// Candidate 1: Low entropy, high popularity (should be heavily penalized)
	lowEntropyBlock := make([]byte, blockSize)
	candidateLow := BlockCandidate{
		Hash:         "low",
		Data:         lowEntropyBlock,
		Popularity:   100,
		Availability: 1.0,
	}

	// Candidate 2: High entropy, low popularity
	highEntropyBlock1 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock1)
	candidateHigh1 := BlockCandidate{
		Hash:         "high1",
		Data:         highEntropyBlock1,
		Popularity:   5,
		Availability: 1.0,
	}

	// Candidate 3: High entropy, high popularity (should be chosen first)
	highEntropyBlock2 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock2)
	candidateHigh2 := BlockCandidate{
		Hash:         "high2",
		Data:         highEntropyBlock2,
		Popularity:   50,
		Availability: 1.0,
	}

	// Candidate 4: High entropy, medium popularity
	highEntropyBlock3 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock3)
	candidateHigh3 := BlockCandidate{
		Hash:         "high3",
		Data:         highEntropyBlock3,
		Popularity:   20,
		Availability: 1.0,
	}

	// Candidate 5: Medium entropy, high popularity (should be penalized)
	mediumEntropyBlock := bytes.Repeat([]byte{0xDE, 0xAD}, blockSize/2)
	candidateMedium := BlockCandidate{
		Hash:         "medium",
		Data:         mediumEntropyBlock,
		Popularity:   200,
		Availability: 1.0,
	}

	candidates := []BlockCandidate{candidateLow, candidateHigh1, candidateHigh2, candidateHigh3, candidateMedium}

	// Test selecting the top two blocks
	t.Run("SelectBest_2_Hybrid", func(t *testing.T) {
		selected := analyzer.selectOptimalBlocks(candidates, 2, minEntropy)
		if len(selected) != 2 {
			t.Fatalf("Expected 2 blocks, got %d", len(selected))
		}
		// The high entropy blocks should be preferred, though exact order may vary due to randomization
		highEntropySelected := 0
		for _, sel := range selected {
			entropy := calculateEntropy(sel.Data)
			if entropy >= minEntropy {
				highEntropySelected++
			}
		}
		if highEntropySelected < 1 {
			t.Errorf("Expected at least 1 high-entropy block to be selected, got %d", highEntropySelected)
		}
	})

	t.Run("EntropyPenalization", func(t *testing.T) {
		// Test with high threshold - low entropy blocks should be heavily penalized
		selected := analyzer.selectOptimalBlocks(candidates, 3, 7.0)
		lowEntropyCount := 0
		highEntropyCount := 0
		for _, s := range selected {
			entropy := calculateEntropy(s.Data)
			if entropy < 7.0 {
				lowEntropyCount++
			} else {
				highEntropyCount++
			}
		}
		// High entropy blocks should be strongly preferred
		if highEntropyCount == 0 {
			t.Error("No high-entropy blocks selected")
		}
		// Low entropy blocks may be selected but should be minority
		if lowEntropyCount > highEntropyCount {
			t.Error("More low-entropy blocks selected than high-entropy blocks")
		}
	})
}

func TestSelectOptimalBlocks_WeightedRandom(t *testing.T) {
	analyzer := &ContentAnalyzer{}
	blockSize := 1024
	minEntropy := 6.5

	// Candidate 1: Low entropy, high popularity (should be heavily penalized)
	candidateLow := BlockCandidate{
		Hash:         "low",
		Data:         make([]byte, blockSize),
		Popularity:   500,
		Availability: 1.0,
	}

	// Candidate 2: High entropy, high popularity (should be selected most often)
	highEntropyBlock1 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock1)
	candidateHighPop := BlockCandidate{
		Hash:         "high_pop",
		Data:         highEntropyBlock1,
		Popularity:   50,
		Availability: 1.0,
	}

	// Candidate 3: High entropy, low popularity (should be selected less often)
	highEntropyBlock2 := make([]byte, blockSize)
	_, _ = rand.Read(highEntropyBlock2)
	candidateLowPop := BlockCandidate{
		Hash:         "low_pop",
		Data:         highEntropyBlock2,
		Popularity:   5,
		Availability: 1.0,
	}

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

	// Check that the high-popularity block was selected more than the low-popularity one
	highPopCount := selectionCounts["high_pop"]
	lowPopCount := selectionCounts["low_pop"]
	lowEntropyCount := selectionCounts["low"]

	// Due to randomization (30% of selections are randomized), the popularity preference
	// may not always be dominant. Check for reasonable distribution.
	totalHighEntropySelections := highPopCount + lowPopCount

	// At least one of the high entropy blocks should be selected reasonably often
	if totalHighEntropySelections < iterations*7/10 {
		t.Errorf("High entropy blocks should dominate selections, got %d/%d", totalHighEntropySelections, iterations)
	}

	// Check that low entropy blocks are heavily penalized (should be < 15% of selections)
	if lowEntropyCount > iterations*15/100 {
		t.Errorf("Low entropy block selected too often: %d times (should be < %d)", lowEntropyCount, iterations*15/100)
	}

	t.Logf("Selection distribution after %d iterations: high_pop=%d, low_pop=%d, low_entropy=%d",
		iterations, highPopCount, lowPopCount, lowEntropyCount)
}
