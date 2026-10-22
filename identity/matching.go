// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"fmt"
	"slices"
	"sort"
	"time"
)

// MatchingIdentifiers returns distinct canonical matches in incoming order with owned scopes.
// Both views are validated; equality does not establish matching eligibility.
func MatchingIdentifiers(incoming, candidate []IdentifierValue) ([]IdentifierValue, error) {
	incomingValues, err := canonicalMatchingView(incoming)
	if err != nil {
		return nil, fmt.Errorf("incoming: %w", err)
	}
	candidateValues, err := canonicalMatchingView(candidate)
	if err != nil {
		return nil, fmt.Errorf("candidate: %w", err)
	}
	var matches []IdentifierValue
	for _, incomingValue := range incomingValues {
		matched := false
		for _, candidateValue := range candidateValues {
			equal, err := EqualIdentifiers(incomingValue, candidateValue)
			if err != nil {
				return nil, err
			}
			if equal {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		duplicate := false
		for _, existing := range matches {
			if SameRepresentation(incomingValue, existing) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			matches = append(matches, incomingValue.Clone())
		}
	}
	return matches, nil
}

func canonicalMatchingView(input []IdentifierValue) ([]IdentifierValue, error) {
	out := make([]IdentifierValue, len(input))
	for i, v := range input {
		canonical, err := NormalizeIdentifier(v)
		if err != nil {
			return nil, fmt.Errorf("identifier %d: %w", i, err)
		}
		out[i] = canonical
	}
	return out, nil
}

// StrongPriorityMatch reports correspondence at one configured priority.
type StrongPriorityMatch struct {
	Type              IdentifierType
	Priority          int   // zero-based; -1 when no candidate matches
	HasIncomingStrong bool  // independent of candidate correspondence
	CandidateIndices  []int // original input positions
}

// EvaluateStrongPriority reports all matches at the first matching configured priority.
// Callers must supply admitted views. TLS requires equal normalized key sets;
// other strong types match any incoming value.
func EvaluateStrongPriority(p MatchPolicy, incoming []IdentifierValue, candidates [][]IdentifierValue) (StrongPriorityMatch, error) {
	empty := StrongPriorityMatch{Priority: -1}
	if err := p.Validate(); err != nil {
		return empty, err
	}
	incomingValues, err := canonicalMatchingView(incoming)
	if err != nil {
		return empty, fmt.Errorf("incoming: %w", err)
	}
	candidateViews := make([][]IdentifierValue, len(candidates))
	for i, view := range candidates {
		normalized, err := canonicalMatchingView(view)
		if err != nil {
			return empty, fmt.Errorf("candidate %d: %w", i, err)
		}
		candidateViews[i] = normalized
	}
	result := empty
	for _, typ := range p.StrongOrder {
		for _, v := range incomingValues {
			if v.Type == typ {
				result.HasIncomingStrong = true
				break
			}
		}
	}
	for priority, typ := range p.StrongOrder {
		var indices []int
		for i, view := range candidateViews {
			if strongValuesMatch(incomingValues, view, typ) {
				indices = append(indices, i)
			}
		}
		if len(indices) > 0 {
			result.Type = typ
			result.Priority = priority
			result.CandidateIndices = indices
			return result, nil
		}
	}
	return result, nil
}

// Inputs are canonical; only the deciding type participates.
func strongValuesMatch(left, right []IdentifierValue, typ IdentifierType) bool {
	for _, value := range left {
		if value.Type == typ && fuzzySetContains(right, value) {
			return typ != TypeTLSPublicKeyHash || sameTLSIdentifiers(left, right)
		}
	}
	return false
}

// Inputs are canonical. Mutual membership ignores order and duplicate representations.
func sameTLSIdentifiers(left, right []IdentifierValue) bool {
	for _, pair := range [][2][]IdentifierValue{{left, right}, {right, left}} {
		for _, value := range pair[0] {
			if value.Type == TypeTLSPublicKeyHash && !slices.ContainsFunc(pair[1], func(other IdentifierValue) bool {
				return SameRepresentation(value, other)
			}) {
				return false
			}
		}
	}
	return true
}

// StrongRankingCandidate belongs to the matching set at the winning strong priority.
type StrongRankingCandidate struct {
	AssetKey string
	LastSeen *time.Time
}

// RankStrongCandidates orders input indices by newest UTC instant, missing last, then key bytes.
// Duplicate and empty keys are invalid; no merges are authorized.
func RankStrongCandidates(candidates []StrongRankingCandidate) ([]int, error) {
	var order []int
	seenAssetKeys := make(map[string]bool, len(candidates))
	for i, candidate := range candidates {
		if candidate.AssetKey == "" {
			return nil, fmt.Errorf("%w: candidate %d: empty asset key", ErrEmptyCandidateKey, i)
		}
		if seenAssetKeys[candidate.AssetKey] {
			return nil, fmt.Errorf("%w: candidate %d: duplicate asset key", ErrDuplicateCandidateKey, i)
		}
		seenAssetKeys[candidate.AssetKey] = true
		if err := validateLastSeen(candidate.LastSeen); err != nil {
			return nil, fmt.Errorf("candidate %d: %w", i, err)
		}
		order = append(order, i)
	}
	sort.Slice(order, func(i, j int) bool {
		left, right := candidates[order[i]], candidates[order[j]]
		if (left.LastSeen == nil) != (right.LastSeen == nil) {
			return left.LastSeen != nil
		}
		if left.LastSeen != nil {
			leftTime, rightTime := left.LastSeen.UTC(), right.LastSeen.UTC()
			if !leftTime.Equal(rightTime) {
				return leftTime.After(rightTime)
			}
		}
		return left.AssetKey < right.AssetKey
	})
	return order, nil
}

func validateLastSeen(lastSeen *time.Time) error {
	if lastSeen != nil {
		if year := lastSeen.UTC().Year(); year < 1 || year > 9999 {
			return fmt.Errorf("%w: UTC year %d outside 1..9999", ErrInvalidObservationTime, year)
		}
	}
	return nil
}
