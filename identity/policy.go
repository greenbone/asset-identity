// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"fmt"
	"math"
	"slices"
)

// ErrInvalidMatchPolicy identifies an invalid matching policy.
var ErrInvalidMatchPolicy = errors.New("invalid matching policy")

// FuzzyMember configures a fuzzy type and weight; entry order controls score accumulation.
type FuzzyMember struct {
	Type   IdentifierType
	Weight float64
}

// MatchPolicy configures strong priority and ordered fuzzy weights.
type MatchPolicy struct {
	StrongOrder []IdentifierType
	Fuzzy       []FuzzyMember
}

// GreenboneMatchPolicy returns independently owned Greenbone defaults.
func GreenboneMatchPolicy() MatchPolicy {
	return MatchPolicy{
		StrongOrder: []IdentifierType{TypeGreenboneID, TypeAgentID, TypeMachineID, TypeBIOSUUID, TypeSSHHostKey, TypeTLSPublicKeyHash, TypeCloudIdentifier},
		Fuzzy:       []FuzzyMember{{Type: TypeMAC, Weight: 1}, {Type: TypeHostname, Weight: .4}, {Type: TypeIP, Weight: .4}, {Type: TypeFQDN, Weight: .4}},
	}
}

// Clone copies membership slices, preserving nil versus empty.
func (p MatchPolicy) Clone() MatchPolicy {
	p.StrongOrder = slices.Clone(p.StrongOrder)
	p.Fuzzy = slices.Clone(p.Fuzzy)
	return p
}

// Validate checks membership and weights without mutating policy.
func (p MatchPolicy) Validate() error {
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
		if member.Weight <= 0 || math.IsNaN(member.Weight) || math.IsInf(member.Weight, 0) {
			return fmt.Errorf("%w: fuzzy member %d: weight must be finite and positive", ErrInvalidMatchPolicy, i)
		}
		weight := float32(member.Weight)
		if math.IsInf(float64(weight), 0) || weight == 0 {
			return fmt.Errorf("%w: fuzzy member %d: weight is not positive finite float32", ErrInvalidMatchPolicy, i)
		}
		fuzzy[member.Type] = true
	}
	return nil
}
