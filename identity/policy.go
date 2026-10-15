package identity

import (
	"errors"
	"fmt"
	"math"
	"slices"
)

var (
	// ErrInvalidMatchPolicy identifies an invalid foundation policy configuration.
	ErrInvalidMatchPolicy = errors.New("invalid matching policy")
	// ErrUnresolvedMatchingRule identifies a requested operation whose domain rule
	// is pending. It is not an asset conflict or an actionable reconciliation result.
	ErrUnresolvedMatchingRule = errors.New("unresolved matching rule")
)

// FuzzyMember configures a supported type's fuzzy membership and weight.
// Weight is configuration data only. This phase does not compute scores or choose
// the pending accumulation precision, order, overflow, or zero-weight semantics.
type FuzzyMember struct {
	Type   IdentifierType
	Weight float64
}

// MatchPolicy contains the independently specified matching foundations only.
// StrongOrder determines membership and absolute priority; empty disables strong
// participation. Fuzzy membership is independent and disjoint. This type neither
// grants producer eligibility nor represents a complete production Decide policy.
type MatchPolicy struct {
	StrongOrder       []IdentifierType
	Fuzzy             []FuzzyMember
	FuzzyBoundaryMode FuzzyBoundaryMode
}

// GreenboneMatchPolicy returns fresh caller-owned defaults. It does not grant
// strong cross-boundary eligibility, evidence admission, or merge authorization.
func GreenboneMatchPolicy() MatchPolicy {
	return MatchPolicy{
		StrongOrder:       []IdentifierType{TypeGreenboneID, TypeAgentID, TypeMachineID, TypeBIOSUUID, TypeSSHHostKey, TypeTLSPublicKeyHash, TypeCloudIdentifier},
		Fuzzy:             []FuzzyMember{{Type: TypeMAC, Weight: 1}, {Type: TypeIP, Weight: .4}, {Type: TypeHostname, Weight: .4}},
		FuzzyBoundaryMode: FuzzyBoundaryStrict,
	}
}

// Clone returns independent membership slices, preserving nil versus empty.
func (p MatchPolicy) Clone() MatchPolicy {
	p.StrongOrder = slices.Clone(p.StrongOrder)
	p.Fuzzy = slices.Clone(p.Fuzzy)
	return p
}

// Validate checks approved foundation constraints without changing policy.
// Zero-weight fuzzy entries and fuzzy FQDN participation return
// ErrUnresolvedMatchingRule: their behavior needs domain approval. An empty fuzzy
// list is allowed; it defines no fuzzy evidence, not suppression of stage entry.
// Success does not validate pending producer, conflict, history, or merge rules.
func (p MatchPolicy) Validate() error {
	if err := p.FuzzyBoundaryMode.Validate(); err != nil {
		return err
	}
	strong := make(map[IdentifierType]bool, len(p.StrongOrder))
	for i, typ := range p.StrongOrder {
		if err := (IdentifierValue{Type: typ}).Validate(); err != nil {
			return fmt.Errorf("%w: strong member %d: %w", ErrInvalidMatchPolicy, i, err)
		}
		if strong[typ] {
			return fmt.Errorf("%w: duplicate strong type %q", ErrInvalidMatchPolicy, typ)
		}
		strong[typ] = true
	}
	fuzzy := make(map[IdentifierType]bool, len(p.Fuzzy))
	for i, member := range p.Fuzzy {
		if err := (IdentifierValue{Type: member.Type}).Validate(); err != nil {
			return fmt.Errorf("%w: fuzzy member %d: %w", ErrInvalidMatchPolicy, i, err)
		}
		if fuzzy[member.Type] {
			return fmt.Errorf("%w: duplicate fuzzy type %q", ErrInvalidMatchPolicy, member.Type)
		}
		if strong[member.Type] {
			return fmt.Errorf("%w: type %q participates in both stages", ErrInvalidMatchPolicy, member.Type)
		}
		if member.Weight < 0 || math.IsNaN(member.Weight) || math.IsInf(member.Weight, 0) {
			return fmt.Errorf("%w: fuzzy member %d: weight must be finite and nonnegative", ErrInvalidMatchPolicy, i)
		}
		fuzzy[member.Type] = true
	}
	// Check all approved invalid constraints before reporting deferred semantics.
	for i, member := range p.Fuzzy {
		if member.Weight == 0 {
			return fmt.Errorf("%w: fuzzy member %d: zero weight semantics", ErrUnresolvedMatchingRule, i)
		}
		if member.Type == TypeFQDN {
			return fmt.Errorf("%w: fuzzy member %d: FQDN projection and weighting", ErrUnresolvedMatchingRule, i)
		}
	}
	return nil
}
