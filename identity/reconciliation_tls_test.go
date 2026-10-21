// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"os"
	"strings"
	"testing"
)

func TestDecideTLSRequiresEqualKeySets(t *testing.T) {
	certificate, err := os.ReadFile("testdata/tls_scanner_certificate.txt")
	if err != nil {
		t.Fatal(err)
	}
	a := fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:1667ab37ba6f84c9c7053970c7557507deccefdbb09c454d9d0ca0e4fe1c3319")
	b := fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("b", 64))
	c := fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("c", 64))
	rawA := fuzzyValue(TypeTLSPublicKeyHash, strings.TrimSpace(string(certificate)))
	upperB := fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("B", 64))
	scopedA := a.Clone()
	scopedA.Scope = Scope{}
	g := fuzzyValue(TypeGreenboneID, "G")
	cloud := fuzzyValue(TypeCloudIdentifier, "cloud")
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	tests := []struct {
		name       string
		incoming   []IdentifierValue
		candidates []Candidate
		key        string
	}{
		{"equal", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, a, b)}, "K"},
		{"subset", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, a)}, ""},
		{"superset", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, a, b, c)}, ""},
		{"partial overlap", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, a, c)}, ""},
		{"disjoint", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, c)}, ""},
		{"no candidate TLS", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, ip)}, ""},
		{"no incoming TLS", []IdentifierValue{g}, []Candidate{fuzzyRow("K", 10, a, b)}, ""},
		{"order", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, b, a)}, "K"},
		{"duplicate observation", []IdentifierValue{a, b, a}, []Candidate{fuzzyRow("K", 10, a, b)}, "K"},
		{"duplicate candidate", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, b, a, b)}, "K"},
		{"raw and canonical duplicates", []IdentifierValue{rawA, a, b}, []Candidate{fuzzyRow("K", 10, upperB, a)}, "K"},
		{"candidate raw certificate", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, b, rawA)}, "K"},
		{"scope differs", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, scopedA, b)}, ""},
		{"additional scope", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K", 10, a, b, scopedA)}, ""},
		{"other types do not affect TLS equality", []IdentifierValue{a, b, ip}, []Candidate{fuzzyRow("K", 10, a, b, cloud)}, "K"},
		{"higher priority remains decisive", []IdentifierValue{g, a, b}, []Candidate{fuzzyRow("K", 10, g, a)}, "K"},
		{"lower priority still considered", []IdentifierValue{a, b, cloud}, []Candidate{fuzzyRow("K", 10, a, cloud)}, "K"},
		{"TLS mismatch never falls back to fuzzy", []IdentifierValue{a, b, ip}, []Candidate{fuzzyRow("K", 10, a, ip)}, ""},
		{"newer partial candidate cannot win", []IdentifierValue{a, b}, []Candidate{fuzzyRow("partial", 30, a), fuzzyRow("exact", 10, a, b)}, "exact"},
		{"equal sets use ranking", []IdentifierValue{a, b}, []Candidate{fuzzyRow("old", 10, a, b), fuzzyRow("new", 20, b, a)}, "new"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Observation{Identifiers: tt.incoming}, tt.candidates, GreenboneMatchPolicy())
			if err != nil || got.Stage != StageStrong || got.SelectedKey != tt.key {
				t.Fatalf("decision=%+v error=%v", got, err)
			}
			if tt.key == "" {
				if got.Action != ActionCreate || !got.NeedsNewKey || got.SelectedIndex != nil {
					t.Fatal(got)
				}
			} else if got.Action != ActionReuse || got.NeedsNewKey || got.SelectedIndex == nil || tt.candidates[*got.SelectedIndex].AssetKey != tt.key {
				t.Fatal(got)
			}
		})
	}
}
