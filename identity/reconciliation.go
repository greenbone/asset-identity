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
	MergeIndices  []int // original candidate positions to move to the destination key
}

// ErrDuplicateCandidateKey identifies repeated asset keys in the supplied candidate list.
var ErrDuplicateCandidateKey = errors.New("duplicate candidate asset key")

// ErrEmptyCandidateKey identifies a candidate without an asset key.
var ErrEmptyCandidateKey = errors.New("empty candidate asset key")

// Decide selects a destination key and returns eligible existing keys to merge into it.
// The caller creates any requested key and applies the plan atomically.
func Decide(observation Observation, candidates []Candidate, policy MatchPolicy) (Decision, error) {
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
	observation.Identifiers = canonicalIncoming
	decision, err := selectKey(observation, candidates, views, policy)
	if err != nil {
		return Decision{}, err
	}
	if err := planMerges(&decision, views, policy); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

// selectKey uses canonical views validated by Decide. A strong match wins; otherwise candidates sharing no strong
// type with the observation compete on weak evidence. Stage is STRONG unless weak evidence selected the key or the
// observation carries no strong identifier.
func selectKey(observation Observation, candidates []Candidate, views [][]IdentifierValue, policy MatchPolicy) (Decision, error) {
	relations, priorities := strongRelations(policy, observation.Identifiers, views)
	match := strongMatchFromRelations(policy, observation.Identifiers, relations, priorities)
	if len(match.CandidateIndices) > 0 {
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
	eligible := make([]bool, len(views))
	for i, relation := range relations {
		eligible[i] = relation == strongNone
	}
	result, err := matchFuzzyCanonical(observation.Identifiers, views, candidates, eligible, policy)
	if err != nil {
		return Decision{}, err
	}
	if result.SelectedIndex != nil {
		return Decision{Action: ActionReuse, Stage: StageFuzzy, SelectedKey: result.SelectedKey, SelectedIndex: result.SelectedIndex}, nil
	}
	stage := StageFuzzy
	if match.HasIncomingStrong {
		stage = StageStrong
	}
	return Decision{Action: ActionCreate, Stage: stage, NeedsNewKey: true}, nil
}
