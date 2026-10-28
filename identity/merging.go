// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import "slices"

// planMerges lists the candidates that may move under the reused destination: strong matches of the destination, and
// compatible weak sources with sufficient shared evidence that contradict neither a strong-merged source nor each
// other. A weak source never shares a strong type with the destination. CREATE moves nothing: a candidate with
// sufficient evidence would have been reused.
func planMerges(decision *Decision, views [][]IdentifierValue, policy MatchPolicy) error {
	if decision.SelectedIndex == nil {
		return nil
	}
	destination := views[*decision.SelectedIndex]
	weights, err := fuzzyWeights(policy)
	if err != nil {
		return err
	}
	destinationFuzzy := fuzzySetFromCanonical(destination, weights)
	var trusted [][]IdentifierValue
	var weakSources []int
	for i, source := range views {
		if i == *decision.SelectedIndex {
			continue
		}
		switch relation, _ := relateStrong(policy, destination, source); relation {
		case strongMatch:
			decision.MergeIndices = append(decision.MergeIndices, i)
			trusted = append(trusted, source)
		case strongNone:
			sourceFuzzy := fuzzySetFromCanonical(source, weights)
			if fuzzyCompatible(destinationFuzzy, sourceFuzzy, weights) && fuzzySufficient(destinationFuzzy, sourceFuzzy, weights) {
				weakSources = append(weakSources, i)
			}
		}
	}
	excluded := make(map[int]bool, len(weakSources))
	for position, i := range weakSources {
		if contradictsAny(policy, views[i], trusted) {
			excluded[i] = true
		}
		for _, j := range weakSources[position+1:] {
			if relation, _ := relateStrong(policy, views[i], views[j]); relation == strongContradiction {
				excluded[i], excluded[j] = true, true
			}
		}
	}
	for _, i := range weakSources {
		if !excluded[i] {
			decision.MergeIndices = append(decision.MergeIndices, i)
		}
	}
	slices.Sort(decision.MergeIndices)
	return nil
}

func contradictsAny(policy MatchPolicy, view []IdentifierValue, others [][]IdentifierValue) bool {
	for _, other := range others {
		if relation, _ := relateStrong(policy, view, other); relation == strongContradiction {
			return true
		}
	}
	return false
}
