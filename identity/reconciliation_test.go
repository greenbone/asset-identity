package identity

import (
	"errors"
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

func TestDecideDefersUndefinedContradictions(t *testing.T) {
	g1 := fuzzyValue(TypeGreenboneID, "g1")
	g2 := fuzzyValue(TypeGreenboneID, "g2")
	got, err := Decide(Observation{Identifiers: []IdentifierValue{g1, g2}}, []Candidate{fuzzyRow("K1", 10, g1), fuzzyRow("K2", 20, g2)}, GreenboneMatchPolicy())
	if !errors.Is(err, ErrUnresolvedMatchingRule) || !reflect.DeepEqual(got, Decision{}) {
		t.Fatalf("invented conflict rule: %+v %v", got, err)
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
