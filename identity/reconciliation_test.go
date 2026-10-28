// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestDecideFQDNWeakMatching(t *testing.T) {
	fqdn := fuzzyValue(TypeFQDN, "server.example.com")
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	tests := []struct {
		name   string
		values []IdentifierValue
		row    Candidate
		action DecisionAction
		merges []int
	}{
		{"normalized name with ip reuses", []IdentifierValue{fuzzyValue(TypeFQDN, "SERVER.EXAMPLE.COM."), ip}, fuzzyRow("K", 1, fqdn, ip), ActionReuse, nil},
		{"fqdn alone is insufficient", []IdentifierValue{fqdn}, fuzzyRow("K", 1, fqdn), ActionCreate, nil},
		{"different names with one shared ip create", []IdentifierValue{ip, fqdn}, fuzzyRow("K", 1, ip, fuzzyValue(TypeFQDN, "other.example.com")), ActionCreate, nil},
		{"hostname is a distinct type", []IdentifierValue{fqdn, ip}, fuzzyRow("K", 1, fuzzyValue(TypeHostname, "server.example.com"), ip), ActionCreate, nil},
		{"a different fqdn does not block a mac match", []IdentifierValue{ip, fqdn, fuzzyValue(TypeMAC, "02:00:00:00:00:01")}, fuzzyRow("K", 1, fuzzyValue(TypeMAC, "02:00:00:00:00:01"), fuzzyValue(TypeFQDN, "other.example.com")), ActionReuse, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Observation{Identifiers: tt.values}, []Candidate{tt.row}, GreenboneMatchPolicy())
			if err != nil || got.Stage != StageFuzzy || got.Action != tt.action || !reflect.DeepEqual(got.MergeIndices, tt.merges) {
				t.Fatalf("decision=%+v error=%v", got, err)
			}
			if tt.action == ActionReuse && (got.SelectedKey != "K" || got.SelectedIndex == nil || *got.SelectedIndex != 0) {
				t.Fatal(got)
			}
		})
	}
}

func TestDecideStrongSelection(t *testing.T) {
	g := fuzzyValue(TypeGreenboneID, "G")
	a := fuzzyValue(TypeAgentID, "A")
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	tests := []struct {
		name     string
		values   []IdentifierValue
		rows     []Candidate
		order    []IdentifierType
		selected int
	}{
		{"default priority", []IdentifierValue{g, a}, []Candidate{fuzzyRow("greenbone", 10, g), fuzzyRow("agent", 20, a)}, GreenboneMatchPolicy().StrongOrder, 0},
		{"custom priority", []IdentifierValue{g, a}, []Candidate{fuzzyRow("greenbone", 10, g), fuzzyRow("agent", 20, a)}, []IdentifierType{TypeAgentID, TypeGreenboneID}, 1},
		{"unmatched higher priority", []IdentifierValue{g, a}, []Candidate{fuzzyRow("agent", 10, a)}, GreenboneMatchPolicy().StrongOrder, 0},
		{"newest same value", []IdentifierValue{g}, []Candidate{fuzzyRow("old", 10, g), fuzzyRow("new", 20, g)}, GreenboneMatchPolicy().StrongOrder, 1},
		{"exact lexical tie", []IdentifierValue{g}, []Candidate{fuzzyRow("asset-2", 20, g), fuzzyRow("asset-10", 20, g)}, GreenboneMatchPolicy().StrongOrder, 1},
		{"weak differences do not veto", []IdentifierValue{g, ip}, []Candidate{fuzzyRow("K", 10, g, fuzzyValue(TypeIP, "192.0.2.2"))}, GreenboneMatchPolicy().StrongOrder, 0},
		{"unmatched strong with insufficient weak evidence creates", []IdentifierValue{g, ip}, []Candidate{fuzzyRow("K", 10, ip)}, GreenboneMatchPolicy().StrongOrder, -1},
		{"differing shared higher type blocks a lower match", []IdentifierValue{g, a}, []Candidate{fuzzyRow("K", 10, fuzzyValue(TypeGreenboneID, "other"), a)}, GreenboneMatchPolicy().StrongOrder, -1},
		{"no candidates", []IdentifierValue{g}, nil, GreenboneMatchPolicy().StrongOrder, -1},
		{"reclassified IP", []IdentifierValue{ip}, []Candidate{fuzzyRow("K", 10, ip)}, []IdentifierType{TypeIP}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Observation{Identifiers: tt.values}, tt.rows, MatchPolicy{StrongOrder: tt.order})
			if err != nil || got.Stage != StageStrong {
				t.Fatalf("decision=%+v error=%v", got, err)
			}
			if tt.selected < 0 {
				if got.Action != ActionCreate || !got.NeedsNewKey || got.SelectedIndex != nil || got.SelectedKey != "" {
					t.Fatal(got)
				}
			} else if got.Action != ActionReuse || got.NeedsNewKey || got.SelectedIndex == nil || *got.SelectedIndex != tt.selected || got.SelectedKey != tt.rows[tt.selected].AssetKey {
				t.Fatal(got)
			}
		})
	}
	instant := time.Unix(200, 2)
	rows := []Candidate{fuzzyRow("A", 200, g), fuzzyRow("B", 200, g)}
	rows[1].LastSeen = &instant
	got, err := Decide(Observation{Identifiers: []IdentifierValue{g}}, rows, GreenboneMatchPolicy())
	if err != nil || got.SelectedKey != "B" {
		t.Fatalf("strong nanoseconds: %+v %v", got, err)
	}
	rows[0].LastSeen = nil
	got, err = Decide(Observation{Identifiers: []IdentifierValue{g}}, rows, GreenboneMatchPolicy())
	if err != nil || got.SelectedKey != "B" {
		t.Fatalf("strong missing-last: %+v %v", got, err)
	}
}

func TestDecideFuzzyCases(t *testing.T) {
	ip1 := fuzzyValue(TypeIP, "192.0.2.1")
	ip2 := fuzzyValue(TypeIP, "192.0.2.2")
	ip3 := fuzzyValue(TypeIP, "192.0.2.3")
	host := fuzzyValue(TypeHostname, "host")
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	tests := []struct {
		name     string
		values   []IdentifierValue
		rows     []Candidate
		action   DecisionAction
		newKey   bool
		selected int
	}{
		{"two shared types reuse", []IdentifierValue{ip1, host}, []Candidate{fuzzyRow("K", 10, ip1, host, ip2)}, ActionReuse, false, 0},
		{"one shared type creates", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K", 10, ip1, ip2)}, ActionCreate, true, -1},
		{"observed extra value does not block", []IdentifierValue{ip1, ip2, host}, []Candidate{fuzzyRow("K", 10, ip1, host)}, ActionReuse, false, 0},
		{"partial overlap of one type creates", []IdentifierValue{ip1, ip3}, []Candidate{fuzzyRow("K", 10, ip1, ip2)}, ActionCreate, true, -1},
		{"highest score wins", []IdentifierValue{mac, ip1, host}, []Candidate{fuzzyRow("newer", 20, mac), fuzzyRow("closer", 10, mac, host)}, ActionReuse, false, 1},
		{"input order breaks fuzzy ties", []IdentifierValue{mac}, []Candidate{fuzzyRow("Z", 20, mac), fuzzyRow("A", 20, mac)}, ActionReuse, false, 0},
		{"empty observation guard", nil, []Candidate{fuzzyRow("K", 10, ip1)}, ActionCreate, true, -1},
		{"empty candidate", []IdentifierValue{mac}, []Candidate{fuzzyRow("K", 10)}, ActionCreate, true, -1},
		{"indices refer to supplied list", []IdentifierValue{mac}, []Candidate{fuzzyRow("unrelated", 1, ip3), fuzzyRow("selected", 20, mac, host), fuzzyRow("other", 10, host)}, ActionReuse, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Observation{Identifiers: tt.values}, tt.rows, GreenboneMatchPolicy())
			if err != nil || got.Action != tt.action || got.Stage != StageFuzzy || got.NeedsNewKey != tt.newKey {
				t.Fatalf("decision=%+v error=%v", got, err)
			}
			if tt.selected < 0 {
				if got.SelectedIndex != nil || got.SelectedKey != "" {
					t.Fatal(got)
				}
			} else if got.SelectedIndex == nil || *got.SelectedIndex != tt.selected || got.SelectedKey != tt.rows[tt.selected].AssetKey {
				t.Fatal(got)
			}
		})
	}
}

func TestDecideFuzzyUsesWholeSeconds(t *testing.T) {
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	rows := []Candidate{fuzzyRow("Z", 200, mac), fuzzyRow("A", 200, mac)}
	newer := time.Unix(200, 999999999)
	rows[1].LastSeen = &newer
	got, err := Decide(Observation{Identifiers: []IdentifierValue{mac}}, rows, GreenboneMatchPolicy())
	if err != nil || got.SelectedKey != "Z" {
		t.Fatalf("whole-second tie: %+v %v", got, err)
	}
}

func TestDecidePreservesScopeIdentity(t *testing.T) {
	for _, typ := range []IdentifierType{TypeGreenboneID, TypeMAC} {
		for _, scope := range []Scope{{}, {"realm": "other"}} {
			value := "G"
			if typ == TypeMAC {
				value = "02:00:00:00:00:01"
			}
			left := IdentifierValue{Type: typ, Value: value}
			right := IdentifierValue{Type: typ, Value: value, Scope: scope}
			got, err := Decide(Observation{Identifiers: []IdentifierValue{left}}, []Candidate{fuzzyRow("K", 10, right)}, GreenboneMatchPolicy())
			if err != nil || got.Action != ActionCreate || got.SelectedIndex != nil {
				t.Fatalf("scope identity changed: %+v %v", got, err)
			}
		}
	}
}

func TestDecideRejectsDuplicateKeysBeforeMatching(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	for _, values := range [][]IdentifierValue{nil, {ip}, {fuzzyValue(TypeGreenboneID, "G")}} {
		got, err := Decide(Observation{Identifiers: values}, []Candidate{fuzzyRow("duplicate", 10, ip), fuzzyRow("duplicate", 20, ip)}, GreenboneMatchPolicy())
		if !errors.Is(err, ErrDuplicateCandidateKey) || !reflect.DeepEqual(got, Decision{}) {
			t.Fatalf("duplicates: %+v %v", got, err)
		}
	}
}

func TestDecideStrongMultiplicity(t *testing.T) {
	g1 := fuzzyValue(TypeGreenboneID, "g1")
	g2 := fuzzyValue(TypeGreenboneID, "g2")
	a1 := fuzzyValue(TypeAgentID, "a1")
	a2 := fuzzyValue(TypeAgentID, "a2")
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	tests := []struct {
		name     string
		values   []IdentifierValue
		rows     []Candidate
		action   DecisionAction
		selected string
	}{
		{"lower priority multiplicity cannot veto", []IdentifierValue{g1, a1, a2}, []Candidate{fuzzyRow("G", 10, g1), fuzzyRow("A1", 20, a1), fuzzyRow("A2", 30, a2)}, ActionReuse, "G"},
		{"winning priority multiplicity", []IdentifierValue{g1, g2, a1}, []Candidate{fuzzyRow("G1", 10, g1), fuzzyRow("G2", 20, g2), fuzzyRow("A", 30, a1)}, ActionReuse, "G2"},
		{"unmatched value at winning priority does not veto", []IdentifierValue{g1, g2}, []Candidate{fuzzyRow("G", 10, g1)}, ActionReuse, "G"},
		{"different values lexical tie", []IdentifierValue{g1, g2}, []Candidate{fuzzyRow("Z", 20, g1), fuzzyRow("A", 20, g2)}, ActionReuse, "A"},
		{"different values missing times", []IdentifierValue{g1, g2}, []Candidate{{AssetKey: "Z", Identifiers: []IdentifierValue{g1}}, {AssetKey: "A", Identifiers: []IdentifierValue{g2}}}, ActionReuse, "A"},
		{"single value multiple candidates ranks", []IdentifierValue{g1}, []Candidate{fuzzyRow("old", 10, g1), fuzzyRow("new", 20, g1)}, ActionReuse, "new"},
		{"no match multiplicity with insufficient weak evidence creates", []IdentifierValue{g1, g2, ip}, []Candidate{fuzzyRow("weak", 10, ip)}, ActionCreate, ""},
		{"no candidates multiplicity creates", []IdentifierValue{g1, g2}, nil, ActionCreate, ""},
		{"no match lower type multiplicity creates", []IdentifierValue{g1, a1, a2}, nil, ActionCreate, ""},
		{"no match single value with insufficient weak evidence creates", []IdentifierValue{g1, ip}, []Candidate{fuzzyRow("weak", 10, ip)}, ActionCreate, ""},
		{"a different value at a shared higher type contradicts", []IdentifierValue{g1, a1}, []Candidate{fuzzyRow("K", 10, g2, a1)}, ActionCreate, ""},
		{"candidate only differing values do not conflict", []IdentifierValue{g1}, []Candidate{fuzzyRow("K", 10, g1, g2)}, ActionReuse, "K"},
		{"unmatched higher multiplicity does not veto lower match", []IdentifierValue{g1, g2, a1}, []Candidate{fuzzyRow("A", 10, a1)}, ActionReuse, "A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Observation{Identifiers: tt.values}, tt.rows, GreenboneMatchPolicy())
			if err != nil || got.Action != tt.action || got.Stage != StageStrong || got.SelectedKey != tt.selected {
				t.Fatalf("decision=%+v error=%v", got, err)
			}
			if got.NeedsNewKey != (tt.action == ActionCreate) || (got.SelectedIndex == nil) != got.NeedsNewKey {
				t.Fatal(got)
			}
		})
	}
}

func TestDecideStrongMultipleValuesPreserveNormalizationAndInputs(t *testing.T) {
	upper := IdentifierValue{Type: TypeBIOSUUID, Value: "00112233445566778899AABBCCDDEEFF", Scope: Scope{"realm": "r"}}
	same := upper.Clone()
	same.Value = "{00112233-4455-6677-8899-aabbccddeeff}"
	other := upper.Clone()
	other.Value = "11112233445566778899aabbccddeeff"
	obs := Observation{Identifiers: []IdentifierValue{upper, same, other}}
	rows := []Candidate{fuzzyRow("K", 10, upper), fuzzyRow("newer", 20, other)}
	before := upper.Clone()
	got, err := Decide(obs, rows, GreenboneMatchPolicy())
	if err != nil || got.Action != ActionReuse || got.SelectedKey != "newer" {
		t.Fatalf("multiple canonical values: %+v %v", got, err)
	}
	*got.SelectedIndex = 99
	again, err := Decide(obs, rows, GreenboneMatchPolicy())
	if err != nil || *again.SelectedIndex != 1 || !reflect.DeepEqual(upper, before) {
		t.Fatal("result or normalization mutates inputs")
	}
}

func TestDecideFuzzyMissingTimeUsesEpoch(t *testing.T) {
	ip := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	tests := []struct {
		name          string
		first, second *time.Time
		selected      string
	}{
		{"nil ties epoch retaining first", nil, new(time.Unix(0, 0)), "first"},
		{"epoch ties nil retaining first", new(time.Unix(0, 0)), nil, "first"},
		{"nil outranks pre epoch", new(time.Unix(-1, 999999999)), nil, "second"},
		{"present post epoch outranks nil", nil, new(time.Unix(1, 0)), "second"},
		{"both missing retain first", nil, nil, "first"},
		{"present Go zero precedes epoch", new(time.Time{}), nil, "second"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := []Candidate{{AssetKey: "first", Identifiers: []IdentifierValue{ip}, LastSeen: tt.first}, {AssetKey: "second", Identifiers: []IdentifierValue{ip}, LastSeen: tt.second}}
			before := make([]*time.Time, 2)
			for i, row := range rows {
				if row.LastSeen != nil {
					before[i] = new(*row.LastSeen)
				}
			}
			got, err := Decide(Observation{Identifiers: []IdentifierValue{ip}}, rows, GreenboneMatchPolicy())
			if err != nil || got.SelectedKey != tt.selected || got.Action != ActionReuse || got.NeedsNewKey {
				t.Fatalf("fuzzy missing time: %+v %v", got, err)
			}
			for i, row := range rows {
				if !reflect.DeepEqual(row.LastSeen, before[i]) {
					t.Fatal("timestamp mutated")
				}
			}
		})
	}
}

func TestDecideRejectsEmptyKeysBeforeMatching(t *testing.T) {
	for _, values := range [][]IdentifierValue{nil, {fuzzyValue(TypeGreenboneID, "g")}, {fuzzyValue(TypeIP, "192.0.2.1")}} {
		got, err := Decide(Observation{Identifiers: values}, []Candidate{{AssetKey: ""}}, GreenboneMatchPolicy())
		if !errors.Is(err, ErrEmptyCandidateKey) || !reflect.DeepEqual(got, Decision{}) {
			t.Fatalf("empty key: %+v %v", got, err)
		}
	}
	row := fuzzyRow("K", 10, fuzzyValue(TypeIP, "192.0.2.1"))
	if _, err := Decide(Observation{}, []Candidate{row, row}, GreenboneMatchPolicy()); !errors.Is(err, ErrDuplicateCandidateKey) {
		t.Fatalf("identical rows accepted: %v", err)
	}
}

func TestDecideDisabledStrongMembership(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	g := fuzzyValue(TypeGreenboneID, "G")
	p := GreenboneMatchPolicy()
	p.StrongOrder = nil
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	got, err := Decide(Observation{Identifiers: []IdentifierValue{g, mac}}, []Candidate{fuzzyRow("K", 10, mac)}, p)
	if err != nil || got.Action != ActionReuse || got.Stage != StageFuzzy {
		t.Fatalf("disabled strong: %+v %v", got, err)
	}
	got, err = Decide(Observation{Identifiers: []IdentifierValue{ip}}, nil, MatchPolicy{})
	if err != nil || got.Action != ActionCreate {
		t.Fatalf("empty policy: %+v %v", got, err)
	}
}

func TestDecideImmutableInputs(t *testing.T) {
	ip := IdentifierValue{Type: TypeMAC, Value: "02-AB-CD-EF-01-23", Scope: Scope{"realm": "r"}}
	before := ip.Clone()
	policy := GreenboneMatchPolicy()
	originalPolicy := policy.Clone()
	rows := []Candidate{fuzzyRow("K1", 20, ip), fuzzyRow("K2", 10, ip)}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 10 {
				got, err := Decide(Observation{Identifiers: []IdentifierValue{ip}}, rows, policy)
				if err != nil {
					t.Error(err)
					return
				}
				*got.SelectedIndex = 100
			}
		})
	}
	wg.Wait()
	if !reflect.DeepEqual(ip, before) || !reflect.DeepEqual(policy, originalPolicy) {
		t.Fatal("mutated input")
	}
}

func TestDecideRejectsUnrepresentableWeightsBeforeMatching(t *testing.T) {
	g := fuzzyValue(TypeGreenboneID, "g")
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	for _, weight := range []float64{math.MaxFloat64, math.SmallestNonzeroFloat64} {
		policy := GreenboneMatchPolicy()
		policy.Fuzzy[0].Weight = weight
		for _, values := range [][]IdentifierValue{nil, {g}, {ip}} {
			got, err := Decide(Observation{Identifiers: values}, []Candidate{fuzzyRow("K", 0, g, ip)}, policy)
			if !errors.Is(err, ErrInvalidMatchPolicy) || !reflect.DeepEqual(got, Decision{}) {
				t.Fatalf("weight=%g values=%v: decision=%+v error=%v", weight, values, got, err)
			}
		}
	}
}

func TestDecideValidatesAllCandidateTimestamps(t *testing.T) {
	g := fuzzyValue(TypeGreenboneID, "g")
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	other := fuzzyValue(TypeIP, "192.0.2.2")
	invalidTimes := []time.Time{
		time.Date(0, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 3600)),
	}
	tests := []struct {
		name        string
		observation []IdentifierValue
		candidates  []Candidate
	}{
		{"empty observation", nil, []Candidate{{AssetKey: "invalid", Identifiers: []IdentifierValue{ip}}}},
		{"strong match", []IdentifierValue{g}, []Candidate{{AssetKey: "invalid", Identifiers: []IdentifierValue{g}}}},
		{"strong no match", []IdentifierValue{g}, []Candidate{{AssetKey: "invalid", Identifiers: []IdentifierValue{ip}}}},
		{"fuzzy match", []IdentifierValue{ip}, []Candidate{{AssetKey: "invalid", Identifiers: []IdentifierValue{ip}}}},
		{"unselected candidate", []IdentifierValue{g}, []Candidate{fuzzyRow("selected", 0, g), {AssetKey: "invalid", Identifiers: []IdentifierValue{other}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, instant := range invalidTimes {
				before := instant
				tt.candidates[len(tt.candidates)-1].LastSeen = &instant
				got, err := Decide(Observation{Identifiers: tt.observation}, tt.candidates, GreenboneMatchPolicy())
				if !errors.Is(err, ErrInvalidObservationTime) || !reflect.DeepEqual(got, Decision{}) {
					t.Fatalf("time=%v: decision=%+v error=%v", instant, got, err)
				}
				if instant != before {
					t.Fatal("timestamp mutated")
				}
			}
		})
	}
}

func TestDecideAcceptsValidCandidateTimestamps(t *testing.T) {
	for _, instant := range []time.Time{time.Unix(0, 0), time.Unix(-1, 999999999), {}, time.Unix(0, 0).In(time.FixedZone("east", 3600))} {
		for _, value := range []IdentifierValue{fuzzyValue(TypeGreenboneID, "g"), fuzzyValue(TypeMAC, "02:00:00:00:00:01")} {
			before := instant
			candidate := Candidate{AssetKey: "K", Identifiers: []IdentifierValue{value}, LastSeen: &instant}
			got, err := Decide(Observation{Identifiers: []IdentifierValue{value}}, []Candidate{candidate}, GreenboneMatchPolicy())
			if err != nil || got.Action != ActionReuse || got.SelectedKey != "K" {
				t.Fatalf("time=%v: decision=%+v error=%v", instant, got, err)
			}
			if instant != before || candidate.LastSeen != &instant {
				t.Fatal("timestamp mutated")
			}
		}
	}
}
