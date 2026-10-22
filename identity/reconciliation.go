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

// Candidate contains a caller-selected asset's eligible active identifiers.
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
	StageStrong MatchingStage = "STRONG"
	StageFuzzy  MatchingStage = "FUZZY"
)

// Decision selects an existing asset key or requests a new key.
type Decision struct {
	Action        DecisionAction
	Stage         MatchingStage
	NeedsNewKey   bool
	SelectedKey   string
	SelectedIndex *int
	MergeIndices  []int    // original candidate positions to move to the destination key
	MergeKeys     []string // keys corresponding to MergeIndices
}

// ErrDuplicateCandidateKey identifies repeated asset keys in the supplied candidate list.
var ErrDuplicateCandidateKey = errors.New("duplicate candidate asset key")

// ErrEmptyCandidateKey identifies a candidate without an asset key.
var ErrEmptyCandidateKey = errors.New("empty candidate asset key")

// Decide selects a destination key and returns eligible existing keys to merge into it.
// The caller creates any requested key and applies the plan atomically.
func Decide(observation Observation, candidates []Candidate, policy MatchPolicy) (Decision, error) {
	decision, err := selectKey(observation, candidates, policy)
	if err != nil {
		return Decision{}, err
	}
	if err := planMerges(&decision, observation, candidates, policy); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

// selectKey preserves the strong-priority and fuzzy-containment selection rules.
func selectKey(observation Observation, candidates []Candidate, policy MatchPolicy) (Decision, error) {
	if err := policy.Validate(); err != nil {
		return Decision{}, err
	}
	seenKeys := make(map[string]int, len(candidates))
	views := make([][]IdentifierValue, len(candidates))
	for index, candidate := range candidates {
		if candidate.AssetKey == "" {
			return Decision{}, fmt.Errorf("%w: index %d", ErrEmptyCandidateKey, index)
		}
		if previous, exists := seenKeys[candidate.AssetKey]; exists {
			return Decision{}, fmt.Errorf("%w: %q at indices %d and %d", ErrDuplicateCandidateKey, candidate.AssetKey, previous, index)
		}
		if err := validateLastSeen(candidate.LastSeen); err != nil {
			return Decision{}, fmt.Errorf("candidate %d: %w", index, err)
		}
		seenKeys[candidate.AssetKey] = index
		views[index] = candidate.Identifiers
	}
	match, err := EvaluateStrongPriority(policy, observation.Identifiers, views)
	if err != nil {
		return Decision{}, err
	}
	if match.HasIncomingStrong {
		if len(match.CandidateIndices) == 0 {
			return Decision{Action: ActionCreate, Stage: StageStrong, NeedsNewKey: true}, nil
		}
		ranking := make([]StrongRankingCandidate, len(match.CandidateIndices))
		for i, index := range match.CandidateIndices {
			ranking[i] = StrongRankingCandidate{AssetKey: candidates[index].AssetKey, LastSeen: candidates[index].LastSeen}
		}
		order, err := RankStrongCandidates(ranking)
		if err != nil {
			return Decision{}, err
		}
		index := match.CandidateIndices[order[0]]
		return Decision{Action: ActionReuse, Stage: StageStrong, SelectedKey: candidates[index].AssetKey, SelectedIndex: &index}, nil
	}
	result, err := matchFuzzyKernel(observation, candidates, policy)
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
