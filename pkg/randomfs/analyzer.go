package randomfs

import (
	"math"
	"sort"
)

// ContentAnalyzer provides tools for selecting optimal blocks.
type ContentAnalyzer struct {
	// In the future, this could hold classifiers, etc.
}

// BlockCandidate represents a potential block to be used as a randomizer.
type BlockCandidate struct {
	Hash string
	Data []byte
}

// ScoredCandidate holds a candidate and its score.
type ScoredCandidate struct {
	Candidate BlockCandidate
	Score     float64
}

// calculateEntropy computes the Shannon entropy of a byte slice.
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	counts := make(map[byte]int)
	for _, b := range data {
		counts[b]++
	}

	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// selectOptimalBlocks scores and selects the best randomizer blocks based on entropy.
func (ca *ContentAnalyzer) selectOptimalBlocks(candidates []BlockCandidate, count int) []BlockCandidate {
	if len(candidates) <= count {
		// Return all candidates if there are not enough to choose from.
		return candidates
	}

	scored := make([]ScoredCandidate, len(candidates))

	for i, candidate := range candidates {
		score := 0.0
		candidateEntropy := calculateEntropy(candidate.Data)
		// Prefer blocks with higher entropy to maximize randomness.
		// A more advanced strategy could be to match entropy, but maximizing it is a good start.
		score = candidateEntropy

		scored[i] = ScoredCandidate{candidate, score}
	}

	// Sort candidates by score descending to get the highest entropy blocks.
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})

	// Select top N candidates
	topCandidates := make([]BlockCandidate, count)
	for i := 0; i < count; i++ {
		topCandidates[i] = scored[i].Candidate
	}
	return topCandidates
}
