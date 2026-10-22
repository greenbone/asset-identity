// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

// planMerges compares each source with the destination's complete eligible view.
func planMerges(decision *Decision, observation Observation, candidates []Candidate, policy MatchPolicy) error {
	destination := observation.Identifiers
	if decision.SelectedIndex != nil {
		destination = candidates[*decision.SelectedIndex].Identifiers
	}
	destinationStrong, err := EvaluateStrongPriority(policy, destination, nil)
	if err != nil {
		return err
	}
	// On a strong REUSE, the observation determines the winning priority.
	winningType := IdentifierType("")
	if decision.Stage == StageStrong && decision.SelectedIndex != nil {
		match, err := EvaluateStrongPriority(policy, observation.Identifiers, [][]IdentifierValue{destination})
		if err != nil {
			return err
		}
		winningType = match.Type
	} else if destinationStrong.HasIncomingStrong {
		winningType = firstStrongType(destination, policy)
	}

	weights, err := fuzzyWeights(policy)
	if err != nil {
		return err
	}
	destinationFuzzy, err := fuzzyMatchingSet(destination, weights)
	if err != nil {
		return err
	}
	for i, candidate := range candidates {
		if decision.SelectedIndex != nil && i == *decision.SelectedIndex {
			continue
		}
		sourceStrong, err := EvaluateStrongPriority(policy, candidate.Identifiers, nil)
		if err != nil {
			return err
		}
		if destinationStrong.HasIncomingStrong && sourceStrong.HasIncomingStrong {
			// Compare only the winning type; TLS retains full-set equality.
			match, err := EvaluateStrongPriority(MatchPolicy{StrongOrder: []IdentifierType{winningType}}, destination, [][]IdentifierValue{candidate.Identifiers})
			if err != nil {
				return err
			}
			if len(match.CandidateIndices) == 0 {
				continue
			}
		} else {
			sourceFuzzy, err := fuzzyMatchingSet(candidate.Identifiers, weights)
			if err != nil {
				return err
			}
			if len(destinationFuzzy) == 0 || !fuzzySetSubset(sourceFuzzy, destinationFuzzy) {
				continue
			}
		}
		decision.MergeIndices = append(decision.MergeIndices, i)
		decision.MergeKeys = append(decision.MergeKeys, candidate.AssetKey)
	}
	if !destinationStrong.HasIncomingStrong {
		return excludeConflictingStrongSources(decision, candidates, policy)
	}
	return nil
}

// firstStrongType returns the highest-priority configured type present in a view.
func firstStrongType(values []IdentifierValue, policy MatchPolicy) IdentifierType {
	for _, typ := range policy.StrongOrder {
		for _, value := range values {
			if value.Type == typ {
				return typ
			}
		}
	}
	return ""
}

// A weak destination must not bridge incompatible strong identities. Exclude
// both members of every conflicting pair, independent of candidate order.
func excludeConflictingStrongSources(decision *Decision, candidates []Candidate, policy MatchPolicy) error {
	blocked := make([]bool, len(decision.MergeIndices))
	for i, leftIndex := range decision.MergeIndices {
		left := candidates[leftIndex].Identifiers
		leftType := firstStrongType(left, policy)
		if leftType == "" {
			continue
		}
		for j := i + 1; j < len(decision.MergeIndices); j++ {
			right := candidates[decision.MergeIndices[j]].Identifiers
			rightType := firstStrongType(right, policy)
			if rightType == "" {
				continue
			}
			// Neither source is privileged: compare their highest-priority present type.
			var typ IdentifierType
			for _, member := range policy.StrongOrder {
				if member == leftType || member == rightType {
					typ = member
					break
				}
			}
			match, err := EvaluateStrongPriority(MatchPolicy{StrongOrder: []IdentifierType{typ}}, left, [][]IdentifierValue{right})
			if err != nil {
				return err
			}
			if len(match.CandidateIndices) == 0 {
				blocked[i], blocked[j] = true, true
			}
		}
	}
	var indices []int
	var keys []string
	for i, index := range decision.MergeIndices {
		if !blocked[i] {
			indices = append(indices, index)
			keys = append(keys, decision.MergeKeys[i])
		}
	}
	decision.MergeIndices, decision.MergeKeys = indices, keys
	return nil
}
