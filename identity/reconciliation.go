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

// DecisionAction describes a reconciliation outcome; REVIEW is non-actionable.
type DecisionAction string

const (
	ActionCreate   DecisionAction = "CREATE"
	ActionReuse    DecisionAction = "REUSE"
	ActionConflict DecisionAction = "CONFLICT"
	ActionReview   DecisionAction = "REVIEW"
)

// MatchingStage identifies the stage that produced a decision.
type MatchingStage string

const (
	StageNone   MatchingStage = "NONE"
	StageStrong MatchingStage = "STRONG"
	StageFuzzy  MatchingStage = "FUZZY"
)

// ConflictDetails describes a contradiction established by a defined domain rule.
type ConflictDetails struct {
	Reason           string
	CandidateIndices []int
	Identifiers      []IdentifierValue
}

// Decision separates key selection from potential merge targets, which authorize no merges.
type Decision struct {
	Action                DecisionAction
	Stage                 MatchingStage
	NeedsNewKey           bool
	SelectedKey           string
	SelectedIndex         *int
	PotentialMergeIndices []int
	PotentialMergeKeys    []string
	Conflict              *ConflictDetails
}

// ErrDuplicateCandidateKey identifies repeated asset keys in the supplied candidate list.
var ErrDuplicateCandidateKey = errors.New("duplicate candidate asset key")

// ErrEmptyCandidateKey identifies a candidate without an asset key.
var ErrEmptyCandidateKey = errors.New("empty candidate asset key")

// Decide matches caller-prepared eligible views without authorizing merges.
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
		views[index] = candidate.Identifiers
	}
	match, err := EvaluateStrongPriority(policy, observation.Identifiers, views)
	if err != nil {
		return Decision{}, err
	}
	if match.HasIncomingStrong {
		values, err := MatchingIdentifiers(observation.Identifiers, observation.Identifiers)
		if err != nil {
			return Decision{}, err
		}
		for _, typ := range policy.StrongOrder {
			if match.Type != "" && typ != match.Type {
				continue
			}
			var conflictingValues []IdentifierValue
			for _, value := range values {
				if value.Type == typ {
					conflictingValues = append(conflictingValues, value)
				}
			}
			if len(conflictingValues) > 1 {
				return Decision{
					Action: ActionConflict, Stage: StageStrong,
					Conflict: &ConflictDetails{
						Reason:           fmt.Sprintf("multiple incoming strong values for %q", typ),
						CandidateIndices: match.CandidateIndices,
						Identifiers:      conflictingValues,
					},
				}, nil
			}
		}
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
	if len(result.PotentialMergeIndices) > 0 {
		action = ActionReview
	} else if result.SelectedIndex != nil {
		action = ActionReuse
	}
	return Decision{
		Action: action, Stage: StageFuzzy, NeedsNewKey: result.NeedsNewKey,
		SelectedKey: result.SelectedKey, SelectedIndex: result.SelectedIndex,
		PotentialMergeIndices: result.PotentialMergeIndices, PotentialMergeKeys: result.PotentialMergeKeys,
	}, nil
}
