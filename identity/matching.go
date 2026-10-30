// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
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
		if fuzzySetContains(candidateValues, incomingValue) && !fuzzySetContains(matches, incomingValue) {
			matches = append(matches, incomingValue.Clone())
		}
	}
	return matches, nil
}

// canonicalMatchingView normalizes a view for matching. Placeholder values are left out. An x509 certificate is kept,
// as its public key hash, only when its subject CN or a DNS SAN names the host: an FQDN or hostname of the same view.
func canonicalMatchingView(input []IdentifierValue) ([]IdentifierValue, error) {
	out := make([]IdentifierValue, 0, len(input))
	var certificates map[int]*x509.Certificate
	var names []string
	for i, v := range input {
		if payload := strings.TrimSpace(v.Value); v.Type == TypeTLSPublicKeyHash && strings.HasPrefix(payload, "x509:") && v.Validate() == nil {
			certificate, err := parseCertificate(payload)
			if err != nil {
				return nil, fmt.Errorf("identifier %d: %s: %w", i, v.Type, err)
			}
			if certificates == nil {
				certificates = make(map[int]*x509.Certificate)
			}
			certificates[len(out)] = certificate
			out = append(out, v.Clone())
			continue
		}
		canonical, err := NormalizeIdentifier(v)
		if errors.Is(err, errPlaceholder) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("identifier %d: %w", i, err)
		}
		if canonical.Type == TypeFQDN || canonical.Type == TypeHostname {
			names = append(names, canonical.Value)
		}
		out = append(out, canonical)
	}
	if len(certificates) == 0 {
		return out, nil
	}
	kept := out[:0]
	for i, v := range out {
		if certificate, ok := certificates[i]; ok {
			if !certificateNamesHost(certificate, names) {
				continue
			}
			v.Value = spkiHash(certificate)
		}
		kept = append(kept, v)
	}
	return kept, nil
}

// StrongPriorityMatch reports reusable candidates at one configured priority.
type StrongPriorityMatch struct {
	Type              IdentifierType
	Priority          int   // zero-based; -1 when no candidate matches
	HasIncomingStrong bool  // independent of candidate correspondence
	CandidateIndices  []int // original input positions
}

// EvaluateStrongPriority reports reusable candidates at the first matching priority.
// Missing types allow lower matches; shared stronger conflicts block them.
// TLS requires equal normalized key sets; other types match any value.
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
	return evaluateStrongPriority(p, incomingValues, candidateViews), nil
}

// evaluateStrongPriority compares canonical views under a validated policy.
func evaluateStrongPriority(p MatchPolicy, incomingValues []IdentifierValue, candidateViews [][]IdentifierValue) StrongPriorityMatch {
	result := StrongPriorityMatch{Priority: -1}
	incomingPriority := firstStrongPriority(incomingValues, p)
	result.HasIncomingStrong = incomingPriority < len(p.StrongOrder)
	if !result.HasIncomingStrong {
		return result
	}
	for i, view := range candidateViews {
		priority, matches := compareStrong(incomingValues, view, p)
		if !matches {
			continue
		}
		if result.Priority < 0 || priority < result.Priority {
			result.Type = p.StrongOrder[priority]
			result.Priority = priority
			result.CandidateIndices = nil
		}
		if priority == result.Priority {
			result.CandidateIndices = append(result.CandidateIndices, i)
		}
	}
	return result
}

func firstStrongType(values []IdentifierValue, policy MatchPolicy) IdentifierType {
	if priority := firstStrongPriority(values, policy); priority < len(policy.StrongOrder) {
		return policy.StrongOrder[priority]
	}
	return ""
}

func firstStrongPriority(values []IdentifierValue, policy MatchPolicy) int {
	for priority, typ := range policy.StrongOrder {
		if hasType(values, typ) {
			return priority
		}
	}
	return len(policy.StrongOrder)
}

// The first type present on both sides decides. Missing types are skipped;
// a shared conflict cannot be bypassed by a lower-priority match.
func compareStrong(left, right []IdentifierValue, policy MatchPolicy) (priority int, matches bool) {
	for priority, typ := range policy.StrongOrder {
		if hasType(left, typ) && hasType(right, typ) {
			return priority, strongValuesMatch(left, right, typ)
		}
	}
	return -1, false
}

func hasType(values []IdentifierValue, typ IdentifierType) bool {
	return slices.ContainsFunc(values, func(value IdentifierValue) bool { return value.Type == typ })
}

func sharesValue(left, right []IdentifierValue, typ IdentifierType) bool {
	for _, value := range left {
		if value.Type == typ && fuzzySetContains(right, value) {
			return true
		}
	}
	return false
}

func strongValuesMatch(left, right []IdentifierValue, typ IdentifierType) bool {
	if !sharesValue(left, right, typ) {
		return false
	}
	return typ != TypeTLSPublicKeyHash || sameTLSIdentifiers(left, right)
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
