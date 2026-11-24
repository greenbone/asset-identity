// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

func latestStrongViews(candidates []Candidate, views [][]IdentifierValue, policy MatchPolicy) map[string][][]IdentifierValue {
	groups := make(map[string]map[IdentifierType][]int)
	for i, candidate := range candidates {
		if groups[candidate.AssetKey] == nil {
			groups[candidate.AssetKey] = make(map[IdentifierType][]int)
		}
		for _, typ := range policy.StrongOrder {
			if hasType(views[i], typ) {
				groups[candidate.AssetKey][typ] = append(groups[candidate.AssetKey][typ], i)
			}
		}
	}
	result := make(map[string][][]IdentifierValue, len(groups))
	for key, types := range groups {
		for _, typ := range policy.StrongOrder {
			indices := types[typ]
			var newest *time.Time
			for _, i := range indices {
				if seen := candidates[i].LastSeen; seen != nil && (newest == nil || seen.UTC().After(newest.UTC())) {
					newest = seen
				}
			}
			for _, i := range indices {
				seen := candidates[i].LastSeen
				if seen != nil && newest != nil && !seen.UTC().Equal(newest.UTC()) {
					continue
				}
				var values []IdentifierValue
				for _, value := range views[i] {
					if value.Type == typ {
						values = append(values, value)
					}
				}
				result[key] = append(result[key], values)
			}
		}
	}
	return result
}

func compareStrongViews(left, right [][]IdentifierValue, policy MatchPolicy) (int, bool) {
	for priority, typ := range policy.StrongOrder {
		shared := false
		for _, a := range left {
			if !hasType(a, typ) {
				continue
			}
			for _, b := range right {
				if !hasType(b, typ) {
					continue
				}
				shared = true
				if !strongValuesMatch(a, b, typ) {
					return priority, false
				}
			}
		}
		if shared {
			return priority, true
		}
	}
	return -1, false
}

func ranksBefore(leftKey string, leftTime *time.Time, rightKey string, rightTime *time.Time) bool {
	if (leftTime == nil) != (rightTime == nil) {
		return leftTime != nil
	}
	if leftTime != nil && !leftTime.UTC().Equal(rightTime.UTC()) {
		return leftTime.UTC().After(rightTime.UTC())
	}
	return leftKey < rightKey
}

func snapshotBefore(left, right int, candidates []Candidate, views [][]IdentifierValue) bool {
	a, b := candidates[left], candidates[right]
	if ranksBefore(a.AssetKey, a.LastSeen, b.AssetKey, b.LastSeen) {
		return true
	}
	if ranksBefore(b.AssetKey, b.LastSeen, a.AssetKey, a.LastSeen) {
		return false
	}
	return snapshotViewKey(views[left]) < snapshotViewKey(views[right])
}

func snapshotViewKey(values []IdentifierValue) string {
	tokens := make([]string, 0, len(values))
	for _, value := range values {
		tokens = append(tokens, strconv.Quote(string(value.Type))+":"+strconv.Quote(value.Value))
	}
	slices.Sort(tokens)
	return strings.Join(slices.Compact(tokens), "\n")
}

func snapshotMergeIndices(decision Decision, incoming []IdentifierValue, candidates []Candidate, views [][]IdentifierValue, evidence map[string][][]IdentifierValue, policy MatchPolicy) []int {
	if decision.SelectedIndex == nil {
		return nil
	}
	destination := views[*decision.SelectedIndex]
	selectionPriority, _ := compareStrong(incoming, destination, policy)
	sources := make(map[string]int)
	for _, index := range decision.MergeIndices {
		key := candidates[index].AssetKey
		if key == decision.SelectedKey {
			continue
		}
		if previous, ok := sources[key]; !ok || snapshotBefore(index, previous, candidates, views) {
			sources[key] = index
		}
	}
	var indices []int
	for key, index := range sources {
		linked := true
		for _, typ := range policy.StrongOrder {
			present := false
			for _, source := range evidence[key] {
				if !hasType(source, typ) {
					continue
				}
				present = true
				matches := strongValuesMatch(incoming, source, typ)
				for _, target := range evidence[decision.SelectedKey] {
					matches = matches || strongValuesMatch(target, source, typ)
				}
				linked = linked && matches
			}
			if present {
				break
			}
		}
		if !linked {
			continue
		}
		priority, matches := compareStrongViews([][]IdentifierValue{incoming}, evidence[key], policy)
		if priority >= 0 && !matches {
			continue
		}
		priority, matches = compareStrongViews(evidence[decision.SelectedKey], evidence[key], policy)
		if priority >= 0 && priority <= selectionPriority && !matches {
			continue
		}
		indices = append(indices, index)
	}
	slices.Sort(indices)
	return indices
}
