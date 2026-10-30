// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"fmt"
	"math"
	"time"
)

type fuzzyKernelResult struct {
	NeedsNewKey   bool
	SelectedKey   string
	SelectedIndex *int // original input index; nil when no survivor
	SelectedScore float32
}

// matchFuzzyCanonical selects a candidate containing every observed fuzzy identifier.
// Inputs are canonical and already validated by the caller.
func matchFuzzyCanonical(incoming []IdentifierValue, views [][]IdentifierValue, candidates []Candidate, policy MatchPolicy) (fuzzyKernelResult, error) {
	fail := fuzzyKernelResult{}
	weights, err := fuzzyWeights(policy)
	if err != nil {
		return fail, err
	}
	observationSet := fuzzySetFromCanonical(incoming, weights)
	result := fuzzyKernelResult{NeedsNewKey: true}
	if len(observationSet) == 0 || len(candidates) == 0 {
		return result, nil
	}
	selectedCandidateIndex := -1
	var selectedScore float32
	var selectedLastSeen time.Time
	for i, candidate := range candidates {
		candidateSet := fuzzySetFromCanonical(views[i], weights)
		if !fuzzySetSubset(observationSet, candidateSet) {
			continue
		}
		score, err := fuzzyIntersectionScore(observationSet, candidateSet, weights, policy.Fuzzy)
		if err != nil {
			return fail, err
		}
		lastSeen := fuzzyInstant(candidate.LastSeen)
		// Exact score/time ties retain the first input row.
		if selectedCandidateIndex < 0 || score > selectedScore || (score == selectedScore && lastSeen.After(selectedLastSeen)) {
			selectedCandidateIndex, selectedScore, selectedLastSeen = i, score, lastSeen
		}
	}
	if selectedCandidateIndex >= 0 {
		index := selectedCandidateIndex
		result.NeedsNewKey = false
		result.SelectedIndex = &index
		result.SelectedKey = candidates[index].AssetKey
		result.SelectedScore = selectedScore
	}
	return result, nil
}

func fuzzyInstant(lastSeen *time.Time) time.Time {
	if lastSeen == nil {
		return time.Unix(0, 0).UTC()
	}
	return lastSeen.UTC().Truncate(time.Second)
}

func fuzzyWeights(policy MatchPolicy) (map[IdentifierType]float32, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	weights := make(map[IdentifierType]float32, len(policy.Fuzzy))
	for _, member := range policy.Fuzzy {
		weights[member.Type] = float32(member.Weight)
	}
	return weights, nil
}

func fuzzySetFromCanonical(normalized []IdentifierValue, weights map[IdentifierType]float32) []IdentifierValue {
	var set []IdentifierValue
	for _, value := range normalized {
		if _, enabled := weights[value.Type]; !enabled {
			continue
		}
		if !fuzzySetContains(set, value) {
			set = append(set, value)
		}
	}
	return set
}

func fuzzySetContains(set []IdentifierValue, value IdentifierValue) bool {
	for _, other := range set {
		if SameRepresentation(value, other) {
			return true
		}
	}
	return false
}

func fuzzySetSubset(subset, superset []IdentifierValue) bool {
	for _, value := range subset {
		if !fuzzySetContains(superset, value) {
			return false
		}
	}
	return true
}

func fuzzyIntersectionScore(observationSet, candidateSet []IdentifierValue, weights map[IdentifierType]float32, members []FuzzyMember) (float32, error) {
	var score float32
	for _, member := range members {
		count := 0
		for _, value := range observationSet {
			if value.Type == member.Type && fuzzySetContains(candidateSet, value) {
				count++
			}
		}
		// Explicit rounding keeps float32 accumulation order independent of fused multiply-add.
		term := float32(float32(count) * weights[member.Type])
		score = float32(score + term)
		if math.IsInf(float64(score), 0) || math.IsNaN(float64(score)) {
			return 0, fmt.Errorf("fuzzy compatibility score is nonfinite")
		}
	}
	return score, nil
}
