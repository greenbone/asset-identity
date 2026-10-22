// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"slices"
	"strconv"
	"strings"
)

// planMerges compares each source with the destination's complete eligible view.
func planMerges(decision *Decision, observation Observation, candidates []Candidate, policy MatchPolicy) error {
	incoming, err := canonicalMatchingView(observation.Identifiers)
	if err != nil {
		return err
	}
	views := make([][]IdentifierValue, len(candidates))
	for i, candidate := range candidates {
		views[i], err = canonicalMatchingView(candidate.Identifiers)
		if err != nil {
			return err
		}
	}
	destination := incoming
	if decision.SelectedIndex != nil {
		destination = views[*decision.SelectedIndex]
	}
	winningType := firstStrongType(destination, policy)
	if decision.Stage == StageStrong && decision.SelectedIndex != nil {
		for _, typ := range policy.StrongOrder {
			if strongValuesMatch(incoming, destination, typ) {
				winningType = typ
				break
			}
		}
	}
	weights, err := fuzzyWeights(policy)
	if err != nil {
		return err
	}
	destinationFuzzy := fuzzySetFromCanonical(destination, weights)
	for i, source := range views {
		if decision.SelectedIndex != nil && i == *decision.SelectedIndex {
			continue
		}
		if winningType != "" && firstStrongType(source, policy) != "" {
			if !strongValuesMatch(destination, source, winningType) {
				continue
			}
		} else {
			if len(destinationFuzzy) == 0 || !fuzzySetSubset(fuzzySetFromCanonical(source, weights), destinationFuzzy) {
				continue
			}
		}
		decision.MergeIndices = append(decision.MergeIndices, i)
	}
	if winningType == "" {
		excludeConflictingStrongSources(decision, views, policy)
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

type strongMergeGroup struct {
	values    []IdentifierValue
	positions []int // positions in MergeIndices, not candidate indices
}

// Group equal strong sets before comparing them. A conflict excludes every member
// of both groups, preserving the original pairwise rule and input order.
func excludeConflictingStrongSources(decision *Decision, views [][]IdentifierValue, policy MatchPolicy) {
	var groups []strongMergeGroup
	bySet := make(map[string]int)
	var decidingType IdentifierType
	mixedTypes := false
	for position, index := range decision.MergeIndices {
		typ := firstStrongType(views[index], policy)
		if typ == "" {
			continue
		}
		if decidingType == "" {
			decidingType = typ
		}
		mixedTypes = mixedTypes || decidingType != typ
		var values []IdentifierValue
		for _, value := range views[index] {
			if value.Type == typ {
				values = append(values, value)
			}
		}
		key := string(typ) + "\n" + strongSetKey(values)
		group, exists := bySet[key]
		if !exists {
			group = len(groups)
			bySet[key] = group
			groups = append(groups, strongMergeGroup{values: values})
		}
		groups[group].positions = append(groups[group].positions, position)
	}
	if len(groups) < 2 {
		return
	}
	blocked := make([]bool, len(groups))
	if mixedTypes || decidingType == TypeTLSPublicKeyHash {
		// Different highest types cannot match each other. Different TLS groups have
		// unequal complete sets. In either case, every strong group has a conflict.
		for i := range blocked {
			blocked[i] = true
		}
	} else {
		// A shared value makes all groups compatible, including distinct multi-value sets.
		for _, value := range groups[0].values {
			common := true
			for _, group := range groups[1:] {
				if !fuzzySetContains(group.values, value) {
					common = false
					break
				}
			}
			if common {
				return
			}
		}
		blockedCount := 0
		for i := 0; i < len(groups) && blockedCount < len(groups); i++ {
			for j := i + 1; j < len(groups); j++ {
				if blocked[i] && blocked[j] {
					continue
				}
				if !strongValuesMatch(groups[i].values, groups[j].values, decidingType) {
					if !blocked[i] {
						blocked[i] = true
						blockedCount++
					}
					if !blocked[j] {
						blocked[j] = true
						blockedCount++
					}
				}
			}
		}
	}
	excluded := make([]bool, len(decision.MergeIndices))
	for i, group := range groups {
		if blocked[i] {
			for _, position := range group.positions {
				excluded[position] = true
			}
		}
	}
	var indices []int
	for i, index := range decision.MergeIndices {
		if !excluded[i] {
			indices = append(indices, index)
		}
	}
	decision.MergeIndices = indices
}

// Quoting preserves arbitrary opaque bytes. Sorting makes set and scope order
// irrelevant, while the nil marker preserves absent versus empty scope.
func strongSetKey(values []IdentifierValue) string {
	tokens := make([]string, 0, len(values))
	for _, value := range values {
		scope := "nil"
		if value.Scope != nil {
			names := make([]string, 0, len(value.Scope))
			for name := range value.Scope {
				names = append(names, name)
			}
			slices.Sort(names)
			var encoded strings.Builder
			encoded.WriteByte('[')
			for _, name := range names {
				encoded.WriteString(strconv.Quote(name))
				encoded.WriteByte(':')
				encoded.WriteString(strconv.Quote(value.Scope[name]))
				encoded.WriteByte(',')
			}
			encoded.WriteByte(']')
			scope = encoded.String()
		}
		tokens = append(tokens, strconv.Quote(value.Value)+"/"+scope)
	}
	slices.Sort(tokens)
	return strings.Join(slices.Compact(tokens), "\n")
}
