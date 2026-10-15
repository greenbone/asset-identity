package identity

import (
	"fmt"
	"math"
	"time"
)

// FuzzyObservation is an admitted current matching view for one logical boundary.
type FuzzyObservation struct {
	Identifiers []IdentifierValue
	Boundary    BoundaryContext
}

// FuzzyCandidate is a candidate matching view before boundary admission.
type FuzzyCandidate struct {
	AssetKey    string
	Identifiers []IdentifierValue
	Boundary    BoundaryContext
	LastSeen    *time.Time
}

// FuzzyKernelOptions selects explicit C compatibility assumptions and score order.
type FuzzyKernelOptions struct {
	LegacyCCompatibility bool             // float32 scoring, whole-second times, and empty subsets
	AccumulationOrder    []IdentifierType // each enabled type once; C defaults use MAC, hostname, IP
}

// FuzzyKernelResult reports a proposed survivor and potential merge targets.
// It is non-actionable: independent merge safety must still be checked.
type FuzzyKernelResult struct {
	NeedsNewKey           bool
	SelectedKey           string
	SelectedIndex         *int // original input index; nil when no survivor
	SelectedScore         float32
	PotentialMergeIndices []int // original input order, parallel to PotentialMergeKeys
	PotentialMergeKeys    []string
}

// MatchFuzzyKernel evaluates fuzzy containment using explicit compatibility options.
// Callers must admit evidence and satisfy the strong-stage entry gate beforehand.
func MatchFuzzyKernel(observation FuzzyObservation, candidates []FuzzyCandidate, policy MatchPolicy, options FuzzyKernelOptions) (FuzzyKernelResult, error) {
	fail := FuzzyKernelResult{}
	weights, err := fuzzyCompatibilityWeights(policy, options)
	if err != nil {
		return fail, err
	}
	observationSet, err := fuzzyMatchingSet(observation.Identifiers, weights)
	if err != nil {
		return fail, fmt.Errorf("observation: %w", err)
	}
	result := FuzzyKernelResult{NeedsNewKey: true}
	// Preserve C's empty-observation guard, including no empty-subset sweep.
	if len(observationSet) == 0 || len(candidates) == 0 {
		return result, nil
	}
	eligibleCandidates, err := admitFuzzyCandidates(observation.Boundary, candidates, policy.FuzzyBoundaryMode, weights)
	if err != nil {
		return fail, err
	}
	selectedCandidateIndex := -1
	var selectedScore float32
	for i, candidate := range eligibleCandidates {
		if !fuzzySetSubset(observationSet, candidate.identifiers) {
			continue
		}
		score, err := fuzzyIntersectionScore(observationSet, candidate.identifiers, weights, options.AccumulationOrder)
		if err != nil {
			return fail, err
		}
		// Exact score/time ties retain the first input row, as in C.
		if selectedCandidateIndex < 0 ||
			score > selectedScore ||
			(score == selectedScore && candidate.lastSeen.After(eligibleCandidates[selectedCandidateIndex].lastSeen)) {
			selectedCandidateIndex = i
			selectedScore = score
		}
	}
	addTarget := func(index int) {
		result.PotentialMergeIndices = append(result.PotentialMergeIndices, index)
		result.PotentialMergeKeys = append(result.PotentialMergeKeys, candidates[index].AssetKey)
	}
	if selectedCandidateIndex >= 0 {
		selected := eligibleCandidates[selectedCandidateIndex]
		index := selected.originalIndex
		result.NeedsNewKey = false
		result.SelectedIndex = &index
		result.SelectedKey = candidates[index].AssetKey
		result.SelectedScore = selectedScore
		// Subsets are compared with the survivor, not the observation.
		for _, candidate := range eligibleCandidates {
			if candidate.originalIndex != index && fuzzySetSubset(candidate.identifiers, selected.identifiers) {
				addTarget(candidate.originalIndex)
			}
		}
		return result, nil
	}
	// Contained candidates require a new key, even for a single subset.
	for _, candidate := range eligibleCandidates {
		if fuzzySetSubset(candidate.identifiers, observationSet) {
			addTarget(candidate.originalIndex)
		}
	}
	return result, nil
}

type fuzzyCandidateSet struct {
	originalIndex int
	identifiers   []IdentifierValue
	lastSeen      time.Time
}

func admitFuzzyCandidates(observationBoundary BoundaryContext, candidates []FuzzyCandidate, mode FuzzyBoundaryMode, weights map[IdentifierType]float32) ([]fuzzyCandidateSet, error) {
	var admitted []fuzzyCandidateSet
	seenAssetKeys := make(map[string]bool)
	for i, candidate := range candidates {
		allowed, err := mode.Admit(CompareBoundaries(observationBoundary, candidate.Boundary))
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		if candidate.AssetKey == "" {
			return nil, fmt.Errorf("%w: candidate %d: unkeyed row admission", ErrUnresolvedMatchingRule, i)
		}
		if seenAssetKeys[candidate.AssetKey] {
			return nil, fmt.Errorf("%w: candidate %d: duplicate asset key", ErrUnresolvedMatchingRule, i)
		}
		seenAssetKeys[candidate.AssetKey] = true
		if candidate.LastSeen == nil {
			return nil, fmt.Errorf("%w: candidate %d: missing fuzzy LastSeen", ErrUnresolvedMatchingRule, i)
		}
		instant := candidate.LastSeen.UTC()
		if year := instant.Year(); year < 1 || year > 9999 {
			return nil, fmt.Errorf("candidate %d: %w: UTC year %d", i, ErrInvalidObservationTime, year)
		}
		if instant.Nanosecond() != 0 {
			return nil, fmt.Errorf("%w: candidate %d: subsecond fuzzy LastSeen outside whole-second fixture domain", ErrUnresolvedMatchingRule, i)
		}
		values, err := fuzzyMatchingSet(candidate.Identifiers, weights)
		if err != nil {
			return nil, fmt.Errorf("candidate %d: %w", i, err)
		}
		admitted = append(admitted, fuzzyCandidateSet{originalIndex: i, identifiers: values, lastSeen: instant})
	}
	return admitted, nil
}

func fuzzyCompatibilityWeights(policy MatchPolicy, options FuzzyKernelOptions) (map[IdentifierType]float32, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if !options.LegacyCCompatibility {
		return nil, fmt.Errorf("%w: explicit legacy C fixture assumptions required", ErrUnresolvedMatchingRule)
	}
	if len(options.AccumulationOrder) != len(policy.Fuzzy) {
		return nil, fmt.Errorf("%w: explicit complete fuzzy accumulation order required", ErrUnresolvedMatchingRule)
	}
	weights := make(map[IdentifierType]float32, len(policy.Fuzzy))
	for _, member := range policy.Fuzzy {
		weight := float32(member.Weight)
		if math.IsInf(float64(weight), 0) || weight == 0 {
			return nil, fmt.Errorf("%w: type %q: weight outside positive finite float32 fixture domain", ErrUnresolvedMatchingRule, member.Type)
		}
		weights[member.Type] = weight
	}
	seen := make(map[IdentifierType]bool, len(weights))
	for _, typ := range options.AccumulationOrder {
		if _, enabled := weights[typ]; !enabled || seen[typ] {
			return nil, fmt.Errorf("%w: accumulation order has disabled or duplicate type %q", ErrInvalidMatchPolicy, typ)
		}
		seen[typ] = true
	}
	return weights, nil
}

func fuzzyMatchingSet(input []IdentifierValue, weights map[IdentifierType]float32) ([]IdentifierValue, error) {
	normalized, err := canonicalMatchingView(input)
	if err != nil {
		return nil, err
	}
	var set []IdentifierValue
	for _, value := range normalized {
		if _, enabled := weights[value.Type]; !enabled {
			continue
		}
		if !fuzzySetContains(set, value) {
			set = append(set, value)
		}
	}
	return set, nil
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

func fuzzyIntersectionScore(observationSet, candidateSet []IdentifierValue, weights map[IdentifierType]float32, order []IdentifierType) (float32, error) {
	var score float32
	for _, typ := range order {
		count := 0
		for _, value := range observationSet {
			if value.Type == typ && fuzzySetContains(candidateSet, value) {
				count++
			}
		}
		// Explicit rounding prevents fused multiply-add from changing C scores.
		term := float32(float32(count) * weights[typ])
		score = float32(score + term)
		if math.IsInf(float64(score), 0) || math.IsNaN(float64(score)) {
			return 0, fmt.Errorf("fuzzy compatibility score is nonfinite")
		}
	}
	return score, nil
}
