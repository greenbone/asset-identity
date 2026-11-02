// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/greenbone/asset-identity/identity"
)

func TestIdentifierTypes(t *testing.T) {
	types := []struct {
		typ  identity.IdentifierType
		name string
	}{
		{identity.TypeGreenboneID, "greenbone_id"},
		{identity.TypeAgentID, "agent_id"},
		{identity.TypeMachineID, "machine_id"},
		{identity.TypeBIOSUUID, "bios_uuid"},
		{identity.TypeSSHHostKey, "ssh_host_key"},
		{identity.TypeTLSPublicKeyHash, "tls_certificate_public_key_hash"},
		{identity.TypeCloudIdentifier, "cloud_identifier"},
		{identity.TypeIP, "ip"},
		{identity.TypeFQDN, "fqdn"},
		{identity.TypeMAC, "mac"},
		{identity.TypeHostname, "hostname"},
	}
	seen := make(map[identity.IdentifierType]bool)
	for _, tt := range types {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.typ) != tt.name || seen[tt.typ] {
				t.Fatalf("type = %q, want unique %q", tt.typ, tt.name)
			}
			seen[tt.typ] = true
			if err := (identity.IdentifierValue{Type: tt.typ}).Validate(); err != nil {
				t.Fatal(err)
			}
			for _, invalid := range []string{strings.ToUpper(tt.name), " " + tt.name, tt.name + " "} {
				err := (identity.IdentifierValue{Type: identity.IdentifierType(invalid)}).Validate()
				if !errors.Is(err, identity.ErrUnknownIdentifierType) || !strings.Contains(err.Error(), invalid) {
					t.Fatalf("invalid type %q: %v", invalid, err)
				}
			}
		})
	}
	for _, invalid := range []identity.IdentifierType{"", "future_type"} {
		if err := (identity.IdentifierValue{Type: invalid}).Validate(); !errors.Is(err, identity.ErrUnknownIdentifierType) {
			t.Fatalf("unknown type %q: %v", invalid, err)
		}
	}
}

func TestValueValidationIsStructuralOnly(t *testing.T) {
	for _, value := range []string{"", "  MiXeD\x00payload  ", "not an IP"} {
		if err := (identity.IdentifierValue{Type: identity.TypeIP, Value: value}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if err := (identity.IdentifierValue{Type: "unknown", Value: "192.0.2.1"}).Validate(); !errors.Is(err, identity.ErrUnknownIdentifierType) {
		t.Fatalf("unknown type: %v", err)
	}
}

func TestSameRepresentation(t *testing.T) {
	base := identity.IdentifierValue{Type: identity.TypeAgentID, Value: " AbC\x00 "}
	tests := []struct {
		name  string
		other identity.IdentifierValue
		want  bool
	}{
		{"same", identity.IdentifierValue{Type: base.Type, Value: base.Value}, true},
		{"type", identity.IdentifierValue{Type: identity.TypeMachineID, Value: base.Value}, false},
		{"case", identity.IdentifierValue{Type: base.Type, Value: strings.ToLower(base.Value)}, false},
		{"whitespace", identity.IdentifierValue{Type: base.Type, Value: strings.TrimSpace(base.Value)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if identity.SameRepresentation(base, tt.other) != tt.want || identity.SameRepresentation(tt.other, base) != tt.want {
				t.Fatalf("comparison should be symmetric and equal %v", tt.want)
			}
		})
	}
	for _, v := range []identity.IdentifierValue{base, {Type: identity.TypeAgentID, Value: "x"}, {Type: "unknown"}} {
		if !identity.SameRepresentation(v, v) {
			t.Fatal("comparison is not reflexive")
		}
	}
	if identity.SameRepresentation(identity.IdentifierValue{Type: identity.TypeIP, Value: "2001:db8::1"}, identity.IdentifierValue{Type: identity.TypeIP, Value: "2001:0db8::1"}) {
		t.Fatal("structural comparison normalized an IP")
	}
}

func TestObservationTimeValidation(t *testing.T) {
	west := time.FixedZone("west", -3600)
	east := time.FixedZone("east", 3600)
	tests := []struct {
		name    string
		instant time.Time
		valid   bool
	}{
		{"zero", time.Time{}, true},
		{"epoch", time.Unix(0, 0).UTC(), true},
		{"pre epoch", time.Unix(-1, 123456789).UTC(), true},
		{"maximum", time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC), true},
		{"offset", time.Date(2026, 10, 14, 10, 0, 0, 123456789, east), true},
		{"below range", time.Date(0, 12, 31, 23, 0, 0, 0, time.UTC), false},
		{"above range", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"offset moves into minimum", time.Date(0, 12, 31, 23, 30, 0, 0, west), true},
		{"offset moves below minimum", time.Date(1, 1, 1, 0, 30, 0, 0, east), false},
		{"offset moves into maximum", time.Date(10000, 1, 1, 0, 30, 0, 0, east), true},
		{"offset moves above maximum", time.Date(9999, 12, 31, 23, 30, 0, 0, west), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.instant
			observation := identity.IdentifierObservation{Identifier: identity.IdentifierValue{Type: identity.TypeAgentID}, ObservedAt: &tt.instant}
			err := observation.Validate()
			if tt.valid && err != nil || !tt.valid && !errors.Is(err, identity.ErrInvalidObservationTime) {
				t.Fatalf("valid=%v, err=%v", tt.valid, err)
			}
			if tt.instant != original || observation.ObservedAt != &tt.instant {
				t.Fatal("validation mutated the timestamp")
			}
			got, err := identity.NewObservation(observation.Identifier, observation.ObservedAt)
			if !tt.valid {
				if !errors.Is(err, identity.ErrInvalidObservationTime) || got.ObservedAt != nil || got.Identifier.Type != "" {
					t.Fatalf("invalid constructor result: %+v, %v", got, err)
				}
				return
			}
			if err != nil || got.ObservedAt == nil || *got.ObservedAt != original.UTC() || got.ObservedAt == observation.ObservedAt {
				t.Fatalf("constructor did not preserve UTC instant with independent storage: %+v, %v", got, err)
			}
		})
	}
	missing, err := identity.NewObservation(identity.IdentifierValue{Type: identity.TypeAgentID}, nil)
	if err != nil || missing.ObservedAt != nil {
		t.Fatalf("missing timestamp changed: %+v, %v", missing, err)
	}
}

func TestNormalizeIsSeparateFromValidation(t *testing.T) {
	for _, instant := range []time.Time{time.Now(), time.Date(10000, 1, 1, 0, 0, 0, 42, time.FixedZone("east", 7200))} {
		input := identity.IdentifierObservation{Identifier: identity.IdentifierValue{Type: "unknown", Value: " MiXeD "}, ObservedAt: &instant}
		got := input.Normalize()
		if !identity.SameRepresentation(input.Identifier, got.Identifier) || *got.ObservedAt != instant.UTC() {
			t.Fatal("normalization changed value representation or failed to remove monotonic reading and offset")
		}
		if !reflect.DeepEqual(got, got.Normalize()) {
			t.Fatal("timestamp normalization is not idempotent")
		}
		if !errors.Is(got.Validate(), identity.ErrUnknownIdentifierType) {
			t.Fatal("normalization silently accepted or coerced an unknown type")
		}
		*got.ObservedAt = time.Time{}
		if instant.IsZero() {
			t.Fatal("normalization retained caller-owned data")
		}
	}
	missing := (identity.IdentifierObservation{}).Normalize()
	if missing.ObservedAt != nil {
		t.Fatal("normalization supplied a missing time")
	}
}

func TestObservationDefensiveCopy(t *testing.T) {
	instant := time.Date(2026, 10, 14, 10, 0, 0, 7, time.FixedZone("east", 7200))
	input := identity.IdentifierObservation{Identifier: identity.IdentifierValue{Type: identity.TypeAgentID, Value: "x\x00y"}, ObservedAt: &instant}
	clone := input.Clone()
	owned, err := identity.NewObservation(input.Identifier, input.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if *clone.ObservedAt != instant || clone.ObservedAt == input.ObservedAt {
		t.Fatal("clone normalized or aliased time")
	}
	instant = time.Time{}
	for _, got := range []identity.IdentifierObservation{clone, owned} {
		if got.ObservedAt.IsZero() || got.Identifier.Value != "x\x00y" {
			t.Fatalf("retained data changed: %+v", got)
		}
	}
	*clone.ObservedAt = time.Time{}
	if owned.ObservedAt.IsZero() {
		t.Fatal("copies alias one another")
	}
}

func TestHistoryPreservesMultipleValuesAndObservations(t *testing.T) {
	first := time.Unix(100, 0).UTC()
	later := time.Unix(200, 0).UTC()
	v := identity.IdentifierValue{Type: identity.TypeIP, Value: "192.0.2.1"}
	input := identity.ObservationHistory{
		{Identifier: v, ObservedAt: &later},
		{Identifier: v, ObservedAt: &first},
		{Identifier: v, ObservedAt: &first},
		{Identifier: v},
		{Identifier: identity.IdentifierValue{Type: v.Type, Value: "192.0.2.2"}},
		{Identifier: identity.IdentifierValue{Type: v.Type, Value: "192.0.2.3"}},
	}
	got, err := identity.NewObservationHistory(input)
	if err != nil || !reflect.DeepEqual(input, got) {
		t.Fatalf("history lost entries or order: %+v, %v", got, err)
	}
	for i := range 4 {
		if !identity.SameRepresentation(got[0].Identifier, got[i].Identifier) {
			t.Fatal("timestamps changed identifier comparison")
		}
	}
	*got[1].ObservedAt = later
	if *got[2].ObservedAt != first || *input[1].ObservedAt != first {
		t.Fatal("history entries alias caller data or each other")
	}
	cloned := input.Clone()
	input[0].Identifier.Value = "replaced"
	first = time.Time{}
	if cloned[0].Identifier.Value != v.Value || cloned[1].ObservedAt.IsZero() {
		t.Fatal("history clone aliases input")
	}
	// Callers can discard history; no library state requires indefinite retention.
	got = got[:1]
	if len(got) != 1 || len(cloned) != 6 {
		t.Fatal("caller-controlled pruning affected an independent history")
	}
}

func TestHistoryBatchErrors(t *testing.T) {
	for _, bad := range []struct {
		observation identity.IdentifierObservation
		category    error
	}{
		{identity.IdentifierObservation{Identifier: identity.IdentifierValue{Type: "future_type"}}, identity.ErrUnknownIdentifierType},
		{identity.IdentifierObservation{Identifier: identity.IdentifierValue{Type: identity.TypeIP}, ObservedAt: ptrTime(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))}, identity.ErrInvalidObservationTime},
	} {
		input := identity.ObservationHistory{{Identifier: identity.IdentifierValue{Type: identity.TypeIP}}, bad.observation, {Identifier: identity.IdentifierValue{Type: "another_unknown"}}}
		before := input.Clone()
		if err := input.Validate(); !errors.Is(err, bad.category) || !strings.Contains(err.Error(), "observation 1") {
			t.Fatalf("unexpected validation error: %v", err)
		}
		got, err := identity.NewObservationHistory(input)
		if got != nil || !errors.Is(err, bad.category) || !strings.Contains(err.Error(), "observation 1") {
			t.Fatalf("batch returned partial result or wrong error: %+v, %v", got, err)
		}
		if !reflect.DeepEqual(input, before) {
			t.Fatal("batch validation or construction mutated input")
		}
	}
}

func TestHistoryInputBoundaryNormalizesOffsets(t *testing.T) {
	east := time.Date(2026, 10, 14, 10, 0, 0, 123456789, time.FixedZone("east", 7200))
	west := east.In(time.FixedZone("west", -18000))
	input := identity.ObservationHistory{
		{Identifier: identity.IdentifierValue{Type: identity.TypeAgentID, Value: " Opaque "}, ObservedAt: &east},
		{Identifier: identity.IdentifierValue{Type: identity.TypeAgentID, Value: " Opaque "}, ObservedAt: &west},
	}
	before := input.Clone()
	if err := input.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := identity.NewObservationHistory(input)
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range got {
		if *o.ObservedAt != east.UTC() || o.ObservedAt == input[i].ObservedAt || o.Identifier.Value != " Opaque " {
			t.Fatalf("entry %d lost precision, was not normalized, or aliases input: %+v", i, o)
		}
	}
	if !reflect.DeepEqual(input, before) {
		t.Fatal("history boundary changed caller timestamps or payloads")
	}
}

func TestNilAndEmptyCopies(t *testing.T) {
	v := identity.IdentifierValue{Type: identity.TypeIP}
	got, err := identity.NewObservation(v, nil)
	if err != nil || !identity.SameRepresentation(v, got.Identifier) || got.ObservedAt != nil {
		t.Fatalf("timestamp presence lost: %+v, %v", got, err)
	}
	for _, history := range []identity.ObservationHistory{nil, {}} {
		got, err := identity.NewObservationHistory(history)
		if err != nil || !reflect.DeepEqual(history, got) || !reflect.DeepEqual(history, history.Clone()) || history.Validate() != nil {
			t.Fatal("nil or empty history changed")
		}
	}
}

func TestLogicalCopyRoundTrip(t *testing.T) {
	input := identity.ObservationHistory{
		{Identifier: identity.IdentifierValue{Type: identity.TypeMachineID, Value: "a\x00b"}, ObservedAt: ptrTime(time.Time{})},
		{Identifier: identity.IdentifierValue{Type: identity.TypeIP}, ObservedAt: ptrTime(time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC))},
		{Identifier: identity.IdentifierValue{Type: identity.TypeIP}, ObservedAt: ptrTime(time.Unix(-1, 123456789).UTC())},
		{Identifier: identity.IdentifierValue{Type: identity.TypeAgentID}},
	}
	owned, err := identity.NewObservationHistory(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input, owned.Clone()) {
		t.Fatal("logical round trip lost value bytes, history, or timestamp precision")
	}
}

func ptrTime(instant time.Time) *time.Time { return &instant }
