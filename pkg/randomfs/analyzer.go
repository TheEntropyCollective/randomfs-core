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
	Hash       string
	Data       []byte
	Popularity int
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

// selectOptimalBlocks scores and selects the best randomizer blocks based on a hybrid strategy.
func (ca *ContentAnalyzer) selectOptimalBlocks(candidates []BlockCandidate, count int, minEntropy float64) []BlockCandidate {
	if len(candidates) == 0 {
		return []BlockCandidate{}
	}

	// 1. Filter out candidates that don't meet the minimum entropy threshold.
	highEntropyCandidates := make([]BlockCandidate, 0, len(candidates))
	for _, c := range candidates {
		if calculateEntropy(c.Data) >= minEntropy {
			highEntropyCandidates = append(highEntropyCandidates, c)
		}
	}

	// If filtering left us with too few candidates, we return what we have,
	// sorted by popularity.
	if len(highEntropyCandidates) <= count {
		sort.Slice(highEntropyCandidates, func(i, j int) bool {
			return highEntropyCandidates[i].Popularity > highEntropyCandidates[j].Popularity
		})
		return highEntropyCandidates
	}

	// 2. Sort the high-entropy candidates by popularity (descending).
	sort.Slice(highEntropyCandidates, func(i, j int) bool {
		return highEntropyCandidates[i].Popularity > highEntropyCandidates[j].Popularity
	})

	// 3. Return the top N most popular, high-entropy candidates.
	return highEntropyCandidates[:count]
}
