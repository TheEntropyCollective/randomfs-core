package randomfs

import (
	"math"
	"math/rand"
	"sort"
	"time"
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

// ContentAnalyzer provides tools for selecting optimal blocks.
type ContentAnalyzer struct {
	// In the future, this could hold classifiers, etc.
}

// BlockCandidate represents a potential block to be used as a randomizer.
type BlockCandidate struct {
	Hash           string
	Data           []byte
	Popularity     int
	Age            time.Duration // How long since block was created
	LastUsed       time.Time     // When block was last used for randomization
	NetworkLatency time.Duration // Network latency to retrieve this block
	Availability   float64       // Availability score (0-1)
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

// selectOptimalBlocks prioritizes blocks with high entropy and high popularity for optimal efficiency.
func (ca *ContentAnalyzer) selectOptimalBlocks(candidates []BlockCandidate, count int, minEntropy float64) []BlockCandidate {
	if len(candidates) == 0 {
		return []BlockCandidate{}
	}

	// If we have fewer candidates than requested, return all available.
	if len(candidates) <= count {
		return candidates
	}

	// Step 1: Score all candidates using OFF System criteria
	scoredCandidates := make([]ScoredCandidate, 0, len(candidates))
	for _, c := range candidates {
		score := 0.0

		entropy := calculateEntropy(c.Data)
		// Entropy component (0-1 scale) - Primary factor
		entropyScore := math.Min(entropy/8.0, 1.0)
		score += entropyScore * 0.4 // 40% weight for entropy

		// Popularity bonus (direct relationship for efficiency)
		popularityBonus := float64(c.Popularity) / (1.0 + float64(c.Popularity))
		score += popularityBonus * 0.25 // 25% weight for popularity

		// Network performance factors
		availabilityScore := c.Availability
		score += availabilityScore * 0.2 // 20% weight for availability

		// Latency penalty (lower latency = higher score)
		latencyScore := 1.0 / (1.0 + c.NetworkLatency.Seconds())
		score += latencyScore * 0.1 // 10% weight for network speed

		// Age factor (prefer blocks that aren't too old or too new)
		ageHours := c.Age.Hours()
		ageFactor := 1.0
		if ageHours < 1 {
			ageFactor = 0.5 // Too new, might not be well-distributed
		} else if ageHours > 168 { // 1 week
			ageFactor = 0.7 // Older blocks might be less available
		}
		score *= ageFactor

		// Recency bonus (recently used blocks are likely still cached)
		timeSinceLastUse := time.Since(c.LastUsed).Hours()
		if timeSinceLastUse < 24 { // Used within last day
			score += 0.05 // 5% bonus for cache efficiency
		}

		// Apply minimum entropy threshold
		if entropy < minEntropy {
			score *= 0.1 // Severely penalize low entropy blocks
		}

		scoredCandidates = append(scoredCandidates, ScoredCandidate{
			Candidate: c,
			Score:     score,
		})
	}

	// Step 2: Sort by score (highest first)
	sort.Slice(scoredCandidates, func(i, j int) bool {
		return scoredCandidates[i].Score > scoredCandidates[j].Score
	})

	// Step 3: Select top candidates with some randomization
	selectedBlocks := make([]BlockCandidate, 0, count)

	// Take the top 70% deterministically, randomize the rest
	deterministicCount := int(float64(count) * 0.7)
	randomCount := count - deterministicCount

	// Add deterministic selections
	for i := 0; i < deterministicCount && i < len(scoredCandidates); i++ {
		selectedBlocks = append(selectedBlocks, scoredCandidates[i].Candidate)
	}

	// Add randomized selections from remaining candidates
	if randomCount > 0 && len(scoredCandidates) > deterministicCount {
		remainingCandidates := scoredCandidates[deterministicCount:]

		// Weighted random selection from remaining candidates
		for i := 0; i < randomCount && len(remainingCandidates) > 0; i++ {
			// Calculate total weight
			totalWeight := 0.0
			for _, sc := range remainingCandidates {
				totalWeight += sc.Score
			}

			if totalWeight == 0 {
				// Fall back to uniform random selection
				idx := rng.Intn(len(remainingCandidates))
				selectedBlocks = append(selectedBlocks, remainingCandidates[idx].Candidate)
				remainingCandidates = append(remainingCandidates[:idx], remainingCandidates[idx+1:]...)
				continue
			}

			// Weighted random selection
			r := rng.Float64() * totalWeight
			for j, sc := range remainingCandidates {
				r -= sc.Score
				if r < 0 {
					selectedBlocks = append(selectedBlocks, sc.Candidate)
					remainingCandidates = append(remainingCandidates[:j], remainingCandidates[j+1:]...)
					break
				}
			}
		}
	}

	return selectedBlocks
}
