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
		{"eligible no match never falls back", []IdentifierValue{g, ip}, []Candidate{fuzzyRow("K", 10, ip)}, GreenboneMatchPolicy().StrongOrder, -1},
		{"no candidates", []IdentifierValue{g}, nil, GreenboneMatchPolicy().StrongOrder, -1},
		{"reclassified IP", []IdentifierValue{ip}, []Candidate{fuzzyRow("K", 10, ip)}, []IdentifierType{TypeIP}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Observation{Identifiers: tt.values}, tt.rows, MatchPolicy{StrongOrder: tt.order})
			if err != nil || got.Stage != StageStrong || got.Conflict != nil || len(got.PotentialMergeIndices) > 0 {
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
	tests := []struct {
		name     string
		values   []IdentifierValue
		rows     []Candidate
		action   DecisionAction
		newKey   bool
		selected int
		targets  []int
	}{
		{"candidate contains observation", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K", 10, ip1, ip2)}, ActionReuse, false, 0, nil},
		{"observation contains candidate", []IdentifierValue{ip1, ip2}, []Candidate{fuzzyRow("K", 10, ip1)}, ActionReview, true, -1, []int{0}},
		{"partial overlap", []IdentifierValue{ip1, ip3}, []Candidate{fuzzyRow("K", 10, ip1, ip2)}, ActionCreate, true, -1, nil},
		{"subset of survivor need not overlap observation", []IdentifierValue{ip1}, []Candidate{fuzzyRow("selected", 20, ip1, host), fuzzyRow("potential", 10, host)}, ActionReview, false, 0, []int{1}},
		{"input order breaks fuzzy ties", []IdentifierValue{ip1}, []Candidate{fuzzyRow("Z", 20, ip1), fuzzyRow("A", 20, ip1)}, ActionReview, false, 0, []int{1}},
		{"empty observation guard", nil, []Candidate{fuzzyRow("K", 10, ip1)}, ActionCreate, true, -1, nil},
		{"empty candidate subset", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K", 10)}, ActionReview, true, -1, []int{0}},
		{"indices refer to supplied list", []IdentifierValue{ip1}, []Candidate{fuzzyRow("unrelated", 1, ip3), fuzzyRow("selected", 20, ip1, host), fuzzyRow("potential", 10, host)}, ActionReview, false, 1, []int{2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Observation{Identifiers: tt.values}, tt.rows, GreenboneMatchPolicy())
			if err != nil || got.Action != tt.action || got.Stage != StageFuzzy || got.NeedsNewKey != tt.newKey || !reflect.DeepEqual(got.PotentialMergeIndices, tt.targets) {
				t.Fatalf("decision=%+v error=%v", got, err)
			}
			if tt.selected < 0 {
				if got.SelectedIndex != nil || got.SelectedKey != "" {
					t.Fatal(got)
				}
			} else if got.SelectedIndex == nil || *got.SelectedIndex != tt.selected || got.SelectedKey != tt.rows[tt.selected].AssetKey {
				t.Fatal(got)
			}
			var keys []string
			for _, index := range tt.targets {
				keys = append(keys, tt.rows[index].AssetKey)
			}
			if !reflect.DeepEqual(got.PotentialMergeKeys, keys) {
				t.Fatal(got)
			}
		})
	}
}

func TestDecideFuzzyUsesCWholeSeconds(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	rows := []Candidate{fuzzyRow("Z", 200, ip), fuzzyRow("A", 200, ip)}
	newer := time.Unix(200, 999999999)
	rows[1].LastSeen = &newer
	got, err := Decide(Observation{Identifiers: []IdentifierValue{ip}}, rows, GreenboneMatchPolicy())
	if err != nil || got.SelectedKey != "Z" {
		t.Fatalf("whole-second tie: %+v %v", got, err)
	}
}

func TestDecidePreservesScopeIdentity(t *testing.T) {
	for _, typ := range []IdentifierType{TypeGreenboneID, TypeIP} {
		for _, scope := range []Scope{{}, {"realm": "other"}} {
			value := "G"
			if typ == TypeIP {
				value = "192.168.1.10"
			}
			left := IdentifierValue{Type: typ, Value: value}
			right := IdentifierValue{Type: typ, Value: value, Scope: scope}
			got, err := Decide(Observation{Identifiers: []IdentifierValue{left}}, []Candidate{fuzzyRow("K", 10, right)}, GreenboneMatchPolicy())
			if err != nil || got.Action != ActionCreate || got.SelectedIndex != nil || len(got.PotentialMergeIndices) > 0 {
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
		name         string
		values       []IdentifierValue
		rows         []Candidate
		action       DecisionAction
		selected     string
		conflictType IdentifierType
		indices      []int
	}{
		{"lower priority multiplicity cannot veto", []IdentifierValue{g1, a1, a2}, []Candidate{fuzzyRow("G", 10, g1), fuzzyRow("A1", 20, a1), fuzzyRow("A2", 30, a2)}, ActionReuse, "G", "", nil},
		{"winning priority multiplicity", []IdentifierValue{g1, g2, a1}, []Candidate{fuzzyRow("G1", 10, g1), fuzzyRow("G2", 20, g2), fuzzyRow("A", 30, a1)}, ActionConflict, "", TypeGreenboneID, []int{0, 1}},
		{"unmatched value at winning priority still conflicts", []IdentifierValue{g1, g2}, []Candidate{fuzzyRow("G", 10, g1)}, ActionConflict, "", TypeGreenboneID, []int{0}},
		{"single value multiple candidates ranks", []IdentifierValue{g1}, []Candidate{fuzzyRow("old", 10, g1), fuzzyRow("new", 20, g1)}, ActionReuse, "new", "", nil},
		{"no match multiplicity conflicts without fuzzy", []IdentifierValue{g1, g2, ip}, []Candidate{fuzzyRow("weak", 10, ip)}, ActionConflict, "", TypeGreenboneID, nil},
		{"no candidates multiplicity conflicts", []IdentifierValue{g1, g2}, nil, ActionConflict, "", TypeGreenboneID, nil},
		{"no match lower type multiplicity conflicts", []IdentifierValue{g1, a1, a2}, nil, ActionConflict, "", TypeAgentID, nil},
		{"no match single value creates without fuzzy", []IdentifierValue{g1, ip}, []Candidate{fuzzyRow("weak", 10, ip)}, ActionCreate, "", "", nil},
		{"candidate only differing values do not conflict", []IdentifierValue{g1}, []Candidate{fuzzyRow("K", 10, g1, g2)}, ActionReuse, "K", "", nil},
		{"unmatched higher multiplicity does not veto lower match", []IdentifierValue{g1, g2, a1}, []Candidate{fuzzyRow("A", 10, a1)}, ActionReuse, "A", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Observation{Identifiers: tt.values}, tt.rows, GreenboneMatchPolicy())
			if err != nil || got.Action != tt.action || got.Stage != StageStrong || got.SelectedKey != tt.selected || len(got.PotentialMergeIndices) > 0 || len(got.PotentialMergeKeys) > 0 {
				t.Fatalf("decision=%+v error=%v", got, err)
			}
			if tt.action == ActionConflict {
				if got.NeedsNewKey || got.SelectedIndex != nil || got.Conflict == nil || got.Conflict.Reason == "" || len(got.Conflict.Identifiers) != 2 || !reflect.DeepEqual(got.Conflict.CandidateIndices, tt.indices) {
					t.Fatalf("conflict invariants: %+v", got)
				}
				for _, v := range got.Conflict.Identifiers {
					if v.Type != tt.conflictType {
						t.Fatal("wrong conflict evidence")
					}
				}
			} else if got.Conflict != nil || got.NeedsNewKey != (tt.action == ActionCreate) {
				t.Fatal(got)
			}
		})
	}
}

func TestDecideConflictEvidenceIsCanonicalAndOwned(t *testing.T) {
	upper := IdentifierValue{Type: TypeBIOSUUID, Value: "00112233445566778899AABBCCDDEEFF", Scope: Scope{"realm": "r"}}
	same := upper.Clone()
	same.Value = "{00112233-4455-6677-8899-aabbccddeeff}"
	other := upper.Clone()
	other.Value = "11112233445566778899aabbccddeeff"
	obs := Observation{Identifiers: []IdentifierValue{upper, same, other}}
	rows := []Candidate{fuzzyRow("K", 10, upper)}
	got, err := Decide(obs, rows, GreenboneMatchPolicy())
	if err != nil || got.Action != ActionConflict || len(got.Conflict.Identifiers) != 2 {
		t.Fatalf("semantic multiplicity: %+v %v", got, err)
	}
	if got.Conflict.Identifiers[0].Value != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatal("noncanonical evidence")
	}
	got.Conflict.Identifiers[0].Scope["realm"] = "changed"
	got.Conflict.CandidateIndices[0] = 99
	again, err := Decide(obs, rows, GreenboneMatchPolicy())
	if err != nil || again.Conflict.Identifiers[0].Scope["realm"] != "r" || again.Conflict.CandidateIndices[0] != 0 || upper.Scope["realm"] != "r" {
		t.Fatal("conflict evidence aliases input")
	}
	got, err = Decide(Observation{Identifiers: []IdentifierValue{upper, same}}, rows, GreenboneMatchPolicy())
	if err != nil || got.Action != ActionReuse {
		t.Fatalf("semantic duplicate caused conflict: %+v %v", got, err)
	}
}

func TestDecideFuzzyMissingTimeUsesEpoch(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
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
			if err != nil || got.SelectedKey != tt.selected || got.Action != ActionReview || got.NeedsNewKey || len(got.PotentialMergeIndices) != 1 {
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
	got, err := Decide(Observation{Identifiers: []IdentifierValue{g, ip}}, []Candidate{fuzzyRow("K", 10, ip)}, p)
	if err != nil || got.Action != ActionReuse || got.Stage != StageFuzzy {
		t.Fatalf("disabled strong: %+v %v", got, err)
	}
	got, err = Decide(Observation{Identifiers: []IdentifierValue{ip}}, nil, MatchPolicy{})
	if err != nil || got.Action != ActionCreate {
		t.Fatalf("empty policy: %+v %v", got, err)
	}
}

func TestDecideImmutableInputs(t *testing.T) {
	ip := IdentifierValue{Type: TypeIP, Value: "2001:0DB8::1", Scope: Scope{"realm": "r"}}
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
				got.PotentialMergeIndices[0] = 100
				got.PotentialMergeKeys[0] = "changed"
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
	for _, instant := range []time.Time{time.Unix(0, 0), time.Unix(-1, 999999999), time.Time{}, time.Unix(0, 0).In(time.FixedZone("east", 3600))} {
		for _, value := range []IdentifierValue{fuzzyValue(TypeGreenboneID, "g"), fuzzyValue(TypeIP, "192.0.2.1")} {
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
