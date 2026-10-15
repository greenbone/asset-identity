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
	// ErrUnresolvedMatchingRule identifies an operation blocked by a pending domain rule.
	ErrUnresolvedMatchingRule = errors.New("unresolved matching rule")
)

// FuzzyMember configures a fuzzy type and weight; it does not define scoring precision.
type FuzzyMember struct {
	Type   IdentifierType
	Weight float64
}

// MatchPolicy configures matching membership, priority, and fuzzy boundary admission.
// It does not grant evidence eligibility or merge authorization.
type MatchPolicy struct {
	StrongOrder       []IdentifierType
	Fuzzy             []FuzzyMember
	FuzzyBoundaryMode FuzzyBoundaryMode
}

// GreenboneMatchPolicy returns independently owned Greenbone defaults.
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

// Validate checks foundation constraints without mutating policy.
// Unresolved zero-weight or fuzzy FQDN behavior returns ErrUnresolvedMatchingRule.
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
	// Report invalid configuration before deferred semantics.
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
