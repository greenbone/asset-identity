package identity

import (
	"fmt"
	"sort"
	"time"
)

// MatchingIdentifiers returns distinct canonical values from incoming that are
// semantically equal to any candidate value, in incoming order, with independent
// scope storage. It uses SPEC-001B equality, including exact type and full scope.
// All supplied values are validated even if one side is empty; normalization
// errors propagate with input indices and no partial output. This low-level
// operation neither determines eligibility nor handles unsupported producer data.
func MatchingIdentifiers(incoming, candidate []IdentifierValue) ([]IdentifierValue, error) {
	left, err := canonicalMatchingView(incoming)
	if err != nil {
		return nil, fmt.Errorf("incoming: %w", err)
	}
	right, err := canonicalMatchingView(candidate)
	if err != nil {
		return nil, fmt.Errorf("candidate: %w", err)
	}
	var matches []IdentifierValue
	for _, a := range left {
		matched := false
		for _, b := range right {
			equal, err := EqualIdentifiers(a, b)
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
			if SameRepresentation(a, existing) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			matches = append(matches, a.Clone())
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

// StrongPriorityMatch reports value correspondence, not an identity decision.
// Priority is a zero-based StrongOrder position, or -1 when no candidate matches.
// HasIncomingStrong is independent of candidate correspondence and indicates
// whether the explicitly eligible view contains configured strong evidence.
// CandidateIndices reference original candidate view positions. Multiple indices
// can represent ambiguity or conflicting values; neither is resolved here.
type StrongPriorityMatch struct {
	Type              IdentifierType
	Priority          int
	HasIncomingStrong bool
	CandidateIndices  []int
}

// EvaluateStrongPriority finds the first configured priority with any semantic
// matches and returns ALL matching candidate indices in input order. Inputs must
// be explicit valid matching views already admitted by applicable evidence,
// namespace, provenance, and pairwise candidate rules. No history is unioned.
// Passing syntactically valid identifiers does NOT prove those admission facts.
// No boundary or producer rule is guessed, no survivor selected, and no conflict
// resolved. A union matching different incoming values MUST NOT automatically be
// fed to ranking; same-type compatibility and strong-conflict checks remain pending.
func EvaluateStrongPriority(p MatchPolicy, incoming []IdentifierValue, candidates [][]IdentifierValue) (StrongPriorityMatch, error) {
	empty := StrongPriorityMatch{Priority: -1}
	if err := p.Validate(); err != nil {
		return empty, err
	}
	left, err := canonicalMatchingView(incoming)
	if err != nil {
		return empty, fmt.Errorf("incoming: %w", err)
	}
	right := make([][]IdentifierValue, len(candidates))
	for i, view := range candidates {
		normalized, err := canonicalMatchingView(view)
		if err != nil {
			return empty, fmt.Errorf("candidate %d: %w", i, err)
		}
		right[i] = normalized
	}
	result := empty
	for _, typ := range p.StrongOrder {
		for _, v := range left {
			if v.Type == typ {
				result.HasIncomingStrong = true
				break
			}
		}
	}
	for priority, typ := range p.StrongOrder {
		var indices []int
		for i, view := range right {
			matched := false
			for _, a := range left {
				if a.Type != typ {
					continue
				}
				for _, b := range view {
					if SameRepresentation(a, b) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if matched {
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

// StrongRankingCandidate is an already admitted member of ONE same-value matching
// set at the winning strong priority after strong-conflict checks. It carries no
// identifier or boundary facts and cannot establish admission on its own.
// AssetKey bytes are opaque; LastSeen is explicitly missing when nil.
type StrongRankingCandidate struct {
	AssetKey string
	LastSeen *time.Time
}

// RankStrongCandidates returns original input positions ordered by present time
// before missing, UTC instant newest first at nanosecond precision, and exact
// unsigned-byte asset-key order on ties. The first position identifies the key to
// reuse under the approved ranking contract; this function returns no merge plan.
// Callers must establish the same-value, winning-priority, eligibility, and
// noncontradiction preconditions. Duplicate keys and unkeyed rows are deferred
// with ErrUnresolvedMatchingRule, rather than resolved or silently deduplicated.
// Invalid timestamps return ErrInvalidObservationTime without coercion. Inputs
// are neither mutated nor retained; monotonic readings are ignored.
func RankStrongCandidates(candidates []StrongRankingCandidate) ([]int, error) {
	var order []int
	keys := make(map[string]bool, len(candidates))
	for i, c := range candidates {
		if c.AssetKey == "" {
			return nil, fmt.Errorf("%w: candidate %d: unkeyed row admission", ErrUnresolvedMatchingRule, i)
		}
		if keys[c.AssetKey] {
			return nil, fmt.Errorf("%w: candidate %d: duplicate asset key", ErrUnresolvedMatchingRule, i)
		}
		keys[c.AssetKey] = true
		if c.LastSeen != nil {
			year := c.LastSeen.UTC().Year()
			if year < 1 || year > 9999 {
				return nil, fmt.Errorf("candidate %d: %w: UTC year %d outside 1..9999", i, ErrInvalidObservationTime, year)
			}
		}
		order = append(order, i)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := candidates[order[i]], candidates[order[j]]
		if (a.LastSeen == nil) != (b.LastSeen == nil) {
			return a.LastSeen != nil
		}
		if a.LastSeen != nil {
			at, bt := a.LastSeen.UTC(), b.LastSeen.UTC()
			if !at.Equal(bt) {
				return at.After(bt)
			}
		}
		return a.AssetKey < b.AssetKey
	})
	return order, nil
}
