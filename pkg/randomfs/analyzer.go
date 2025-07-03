package randomfs

import (
	"math"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

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
// It uses weighted random selection to introduce unpredictability.
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

	// If filtering left us with too few candidates, we can't do a weighted selection.
	// We'll just return what we have (up to the requested count).
	if len(highEntropyCandidates) <= count {
		return highEntropyCandidates
	}

	// 2. Perform weighted random selection without replacement.
	selectedBlocks := make([]BlockCandidate, 0, count)
	for i := 0; i < count; i++ {
		// Calculate total popularity weight of remaining candidates
		totalWeight := 0
		for _, c := range highEntropyCandidates {
			// Add 1 to popularity to ensure even unpopular blocks have a chance.
			totalWeight += c.Popularity + 1
		}

		if totalWeight == 0 {
			// This case should be rare, but if all remaining candidates have 0 popularity,
			// we fall back to a simple random selection from the high-entropy pool.
			idx := rand.Intn(len(highEntropyCandidates))
			selectedBlocks = append(selectedBlocks, highEntropyCandidates[idx])
			// Remove selected element
			highEntropyCandidates = append(highEntropyCandidates[:idx], highEntropyCandidates[idx+1:]...)
			continue
		}

		// Choose a random number within the total weight
		r := rand.Intn(totalWeight)

		// Find the candidate corresponding to the random number
		for j, c := range highEntropyCandidates {
			r -= (c.Popularity + 1)
			if r < 0 {
				selectedBlocks = append(selectedBlocks, c)
				// Remove the selected candidate for the next round (selection without replacement)
				highEntropyCandidates = append(highEntropyCandidates[:j], highEntropyCandidates[j+1:]...)
				break
			}
		}
	}

	return selectedBlocks
}
