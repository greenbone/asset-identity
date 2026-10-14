// Package identity represents identifier values and their in-memory observations.
// It does not normalize identifier payloads or implement asset matching.
package identity

import (
	"errors"
	"fmt"
	"maps"
	"time"
)

// IdentifierType is a stable, case-sensitive identifier type name.
type IdentifierType string

// Supported type names have no intrinsic classification or priority.
const (
	TypeGreenboneID      IdentifierType = "greenbone_id"
	TypeAgentID          IdentifierType = "agent_id"
	TypeMachineID        IdentifierType = "machine_id"
	TypeBIOSUUID         IdentifierType = "bios_uuid"
	TypeSSHHostKey       IdentifierType = "ssh_host_key"
	TypeTLSPublicKeyHash IdentifierType = "tls_certificate_public_key_hash"
	TypeCloudIdentifier  IdentifierType = "cloud_identifier"
	TypeIP               IdentifierType = "ip"
	TypeFQDN             IdentifierType = "fqdn"
	TypeMAC              IdentifierType = "mac"
	TypeHostname         IdentifierType = "hostname"
)

var (
	// ErrUnknownIdentifierType identifies unsupported or empty type names.
	ErrUnknownIdentifierType = errors.New("unknown identifier type")
	// ErrInvalidScope identifies an empty scope dimension name.
	ErrInvalidScope = errors.New("invalid identifier scope")
	// ErrInvalidObservationTime identifies a UTC instant outside years 1..9999.
	ErrInvalidObservationTime = errors.New("invalid observation time")
)

// Scope contains named namespace dimensions. Nil means absent, while a non-nil
// empty map means explicitly present and empty. Neither means globally unique.
type Scope map[string]string

// IdentifierValue preserves its payload bytes and scope without normalization.
// Its map makes it unsuitable for comparison with Go's == operator.
type IdentifierValue struct {
	Type  IdentifierType
	Value string
	Scope Scope
}

// IdentifierObservation associates a value with a present or missing timestamp.
// A nil ObservedAt means missing; a non-nil zero time is explicitly present.
type IdentifierObservation struct {
	Identifier IdentifierValue
	ObservedAt *time.Time
}

// ObservationHistory is an in-memory sequence, not a retention system.
// Callers control persistence, pruning, and lifetime.
type ObservationHistory []IdentifierObservation

// Validate checks only the supported type and generic scope structure.
// It neither changes input nor certifies type-specific payload validity.
func (v IdentifierValue) Validate() error {
	switch v.Type {
	case TypeGreenboneID, TypeAgentID, TypeMachineID, TypeBIOSUUID,
		TypeSSHHostKey, TypeTLSPublicKeyHash, TypeCloudIdentifier,
		TypeIP, TypeFQDN, TypeMAC, TypeHostname:
	default:
		return fmt.Errorf("%w: %q", ErrUnknownIdentifierType, v.Type)
	}
	if _, exists := v.Scope[""]; exists {
		return fmt.Errorf("%w: empty dimension name", ErrInvalidScope)
	}
	return nil
}

// Clone returns an independent copy, preserving absent versus empty scope.
// It does not validate or normalize.
func (v IdentifierValue) Clone() IdentifierValue {
	v.Scope = maps.Clone(v.Scope)
	return v
}

// SameRepresentation compares exact type, payload bytes, and scope dimensions.
// It does not validate, normalize, or establish semantic identifier equality.
func SameRepresentation(a, b IdentifierValue) bool {
	return a.Type == b.Type && a.Value == b.Value &&
		(a.Scope == nil) == (b.Scope == nil) && maps.Equal(a.Scope, b.Scope)
}

// Validate checks structural validity and the UTC year range 1 through 9999.
// Valid offsets and missing times are accepted without mutating input.
func (o IdentifierObservation) Validate() error {
	if err := o.Identifier.Validate(); err != nil {
		return err
	}
	if o.ObservedAt != nil {
		year := o.ObservedAt.UTC().Year()
		if year < 1 || year > 9999 {
			return fmt.Errorf("%w: UTC year %d outside 1..9999", ErrInvalidObservationTime, year)
		}
	}
	return nil
}

// Clone returns independent scope and timestamp storage without normalization
// or validation. Timestamp presence and timezone are preserved.
func (o IdentifierObservation) Clone() IdentifierObservation {
	o.Identifier = o.Identifier.Clone()
	if o.ObservedAt != nil {
		instant := *o.ObservedAt
		o.ObservedAt = &instant
	}
	return o
}

// Normalize returns a defensive copy with a UTC timestamp and no monotonic
// reading. It does not validate or normalize identifier types, values, or scopes.
func (o IdentifierObservation) Normalize() IdentifierObservation {
	o = o.Clone()
	if o.ObservedAt != nil {
		*o.ObservedAt = o.ObservedAt.UTC()
	}
	return o
}

// NewObservation normalizes a defensive copy and validates it at the input
// boundary. On failure it returns a zero observation and the validation error.
func NewObservation(v IdentifierValue, observedAt *time.Time) (IdentifierObservation, error) {
	o := (IdentifierObservation{Identifier: v, ObservedAt: observedAt}).Normalize()
	if err := o.Validate(); err != nil {
		return IdentifierObservation{}, err
	}
	return o, nil
}

// Validate returns the first structural error with its zero-based entry index.
// It neither mutates input nor applies timestamp normalization.
func (h ObservationHistory) Validate() error {
	for i, o := range h {
		if err := o.Validate(); err != nil {
			return fmt.Errorf("observation %d: %w", i, err)
		}
	}
	return nil
}

// Clone copies the slice, each scope, and each timestamp without normalization
// or validation. Nil versus non-nil empty histories are preserved.
func (h ObservationHistory) Clone() ObservationHistory {
	if h == nil {
		return nil
	}
	out := make(ObservationHistory, len(h))
	for i, o := range h {
		out[i] = o.Clone()
	}
	return out
}

// NewObservationHistory copies, normalizes, and validates supplied observations.
// It preserves entry order and duplicates without imposing a retention policy.
// On failure it returns nil and the first error with its zero-based entry index.
func NewObservationHistory(input ObservationHistory) (ObservationHistory, error) {
	if input == nil {
		return nil, nil
	}
	out := make(ObservationHistory, len(input))
	for i, o := range input {
		owned, err := NewObservation(o.Identifier, o.ObservedAt)
		if err != nil {
			return nil, fmt.Errorf("observation %d: %w", i, err)
		}
		out[i] = owned
	}
	return out, nil
}
