// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"fmt"
	"time"
)

// Observation contains caller-prepared eligible active identifiers.
type Observation struct {
	Identifiers []IdentifierValue
}

// Candidate contains one scan snapshot. Its identifiers were observed together at LastSeen.
type Candidate struct {
	AssetKey    string
	Identifiers []IdentifierValue
	LastSeen    *time.Time
}

// DecisionAction describes whether to create or reuse an asset key.
type DecisionAction string

const (
	ActionCreate DecisionAction = "CREATE"
	ActionReuse  DecisionAction = "REUSE"
)

// MatchingStage identifies the stage that produced a decision.
type MatchingStage string

const (
	StageStrong     MatchingStage = "STRONG"
	StageContinuity MatchingStage = "CONTINUITY"
	StageFuzzy      MatchingStage = "FUZZY"
)

// Decision selects an existing asset key or requests a new key.
type Decision struct {
	Action        DecisionAction
	Stage         MatchingStage
	NeedsNewKey   bool
	SelectedKey   string
	SelectedIndex *int
	MergeIndices  []int // original candidate positions to move to the destination key
}

// ErrDuplicateCandidateKey identifies repeated asset keys passed to RankStrongCandidates.
var ErrDuplicateCandidateKey = errors.New("duplicate candidate asset key")

// ErrEmptyCandidateKey identifies a candidate without an asset key.
var ErrEmptyCandidateKey = errors.New("empty candidate asset key")

// Decide selects a destination key and returns eligible existing keys to merge into it.
// The caller creates any requested key and applies the plan atomically.
func Decide(observation Observation, candidates []Candidate, policy MatchPolicy) (Decision, error) {
	if err := policy.Validate(); err != nil {
		return Decision{}, err
	}
	views := make([][]IdentifierValue, len(candidates))
	for index, candidate := range candidates {
		if candidate.AssetKey == "" {
			return Decision{}, fmt.Errorf("%w: index %d", ErrEmptyCandidateKey, index)
		}
		if err := validateLastSeen(candidate.LastSeen); err != nil {
			return Decision{}, fmt.Errorf("candidate %d: %w", index, err)
		}
	}
	canonicalIncoming, err := canonicalMatchingView(observation.Identifiers)
	if err != nil {
		return Decision{}, fmt.Errorf("incoming: %w", err)
	}
	for i, candidate := range candidates {
		views[i], err = canonicalMatchingView(candidate.Identifiers)
		if err != nil {
			return Decision{}, fmt.Errorf("candidate %d: %w", i, err)
		}
	}
	evidence := latestStrongViews(candidates, views, policy)
	eligible := make([][]IdentifierValue, len(views))
	compatible := make(map[string]bool)
	for i, candidate := range candidates {
		allowed, checked := compatible[candidate.AssetKey]
		if !checked {
			priority, matches := compareStrongViews([][]IdentifierValue{canonicalIncoming}, evidence[candidate.AssetKey], policy)
			allowed = priority < 0 || matches
			compatible[candidate.AssetKey] = allowed
		}
		if allowed {
			eligible[i] = views[i]
		}
	}
	observation.Identifiers = canonicalIncoming
	decision, err := selectKey(observation, candidates, eligible, policy)
	if err != nil {
		return Decision{}, err
	}
	if err := planMerges(&decision, canonicalIncoming, views, policy); err != nil {
		return Decision{}, err
	}
	decision.MergeIndices = snapshotMergeIndices(decision, canonicalIncoming, candidates, views, evidence, policy)
	return decision, nil
}

// selectKey uses canonical views validated by Decide.
func selectKey(observation Observation, candidates []Candidate, views [][]IdentifierValue, policy MatchPolicy) (Decision, error) {
	match := evaluateStrongPriority(policy, observation.Identifiers, views)
	if len(match.CandidateIndices) > 0 {
		index := match.CandidateIndices[0]
		for _, other := range match.CandidateIndices[1:] {
			if snapshotBefore(other, index, candidates, views) {
				index = other
			}
		}
		return Decision{Action: ActionReuse, Stage: StageStrong, SelectedKey: candidates[index].AssetKey, SelectedIndex: &index}, nil
	}
	eligible := make([][]IdentifierValue, len(views))
	var continuityMatches []int
	continuityKeys := make(map[string]bool)
	for i, view := range views {
		priority, matches := compareStrong(observation.Identifiers, view, policy)
		if priority >= 0 && !matches {
			continue
		}
		eligible[i] = view
		for _, typ := range policy.Continuity {
			if sharesValue(observation.Identifiers, view, typ) {
				continuityMatches = append(continuityMatches, i)
				continuityKeys[candidates[i].AssetKey] = true
				break
			}
		}
	}
	if len(continuityKeys) == 1 {
		index := continuityMatches[0]
		for _, other := range continuityMatches[1:] {
			if snapshotBefore(other, index, candidates, views) {
				index = other
			}
		}
		return Decision{Action: ActionReuse, Stage: StageContinuity, SelectedKey: candidates[index].AssetKey, SelectedIndex: &index}, nil
	}
	if len(continuityKeys) > 1 {
		eligible = make([][]IdentifierValue, len(views))
		for _, index := range continuityMatches {
			eligible[index] = views[index]
		}
	}
	result, err := matchFuzzyCanonical(observation.Identifiers, eligible, candidates, policy)
	if err != nil {
		return Decision{}, err
	}
	action := ActionCreate
	if result.SelectedIndex != nil {
		action = ActionReuse
	}
	return Decision{
		Action: action, Stage: StageFuzzy, NeedsNewKey: result.NeedsNewKey,
		SelectedKey: result.SelectedKey, SelectedIndex: result.SelectedIndex,
	}, nil
}
