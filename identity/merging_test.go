// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"math/rand"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestMergePlan(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	host := fuzzyValue(TypeHostname, "host.example")
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	agent := fuzzyValue(TypeAgentID, "agent")
	otherAgent := fuzzyValue(TypeAgentID, "other")
	tlsA := fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("a", 64))
	tlsB := fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("b", 64))
	tests := []struct {
		name     string
		incoming []IdentifierValue
		rows     []Candidate
		action   DecisionAction
		selected string
		merges   []int
	}{
		{"rich observation combines partial records", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, ip, host), fuzzyRow("K2", 2, ip, mac)}, ActionCreate, "", []int{0, 1}},
		{"reuse merges narrower records", []IdentifierValue{ip}, []Candidate{fuzzyRow("K1", 2, ip, host), fuzzyRow("K2", 1, host)}, ActionReuse, "K1", []int{1}},
		{"partial overlap is insufficient", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K1", 1, ip, mac)}, ActionCreate, "", nil},
		{"same winning strong identifier", []IdentifierValue{agent}, []Candidate{fuzzyRow("K1", 2, agent, ip), fuzzyRow("K2", 1, agent, host)}, ActionReuse, "K1", []int{1}},
		{"different strong identifier blocked", []IdentifierValue{agent, ip}, []Candidate{fuzzyRow("K1", 2, agent, ip), fuzzyRow("K2", 1, otherAgent, ip)}, ActionReuse, "K1", nil},
		{"weak source can join strong destination", []IdentifierValue{agent, ip}, []Candidate{fuzzyRow("K1", 2, agent, ip), fuzzyRow("K2", 1, ip)}, ActionReuse, "K1", []int{1}},
		{"new strong key absorbs contained weak source", []IdentifierValue{agent, ip, host}, []Candidate{fuzzyRow("K1", 1, ip)}, ActionCreate, "", []int{0}},
		{"strong mismatch cannot merge through fuzzy", []IdentifierValue{agent, ip}, []Candidate{fuzzyRow("K1", 1, otherAgent, ip)}, ActionCreate, "", nil},
		{"equal TLS sets merge", []IdentifierValue{tlsA, tlsB}, []Candidate{fuzzyRow("K1", 2, tlsA, tlsB), fuzzyRow("K2", 1, tlsB, tlsA, tlsA)}, ActionReuse, "K1", []int{1}},
		{"unequal TLS sets cannot merge", []IdentifierValue{tlsA, tlsB, ip}, []Candidate{fuzzyRow("K1", 2, tlsA, tlsB, ip), fuzzyRow("K2", 1, tlsA, ip)}, ActionReuse, "K1", nil},
		{"fuzzy reuse respects destination strong ID", []IdentifierValue{ip}, []Candidate{fuzzyRow("K1", 2, agent, ip), fuzzyRow("K2", 1, otherAgent, ip)}, ActionReuse, "K1", nil},
		{"shared observation does not bridge distinct strong IDs", []IdentifierValue{agent, otherAgent}, []Candidate{fuzzyRow("K1", 2, agent), fuzzyRow("K2", 1, otherAgent)}, ActionReuse, "K1", nil},
		{"different strong types do not establish identity", []IdentifierValue{agent, ip}, []Candidate{fuzzyRow("K1", 1, fuzzyValue(TypeGreenboneID, "g"), ip)}, ActionCreate, "", nil},
		{"scope prevents weak containment", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K1", 1, IdentifierValue{Type: TypeIP, Value: ip.Value, Scope: Scope{"network": "other"}})}, ActionCreate, "", nil},
		{"weak observation leaves conflicting strong sources separate", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, agent, ip, host), fuzzyRow("K2", 2, otherAgent, ip, mac)}, ActionCreate, "", nil},
		{"weak observation can still absorb weak sources", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, agent, ip, host), fuzzyRow("K2", 2, otherAgent, ip, mac), fuzzyRow("K3", 3, ip)}, ActionCreate, "", []int{2}},
		{"reversing conflicting candidates changes no merge outcome", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K2", 2, otherAgent, ip, mac), fuzzyRow("K1", 1, agent, ip, host)}, ActionCreate, "", nil},
		{"weak observation cannot bridge unequal TLS sets", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, tlsA, tlsB, ip, host), fuzzyRow("K2", 2, tlsA, ip, mac)}, ActionCreate, "", nil},
		{"weak observation can absorb compatible strong sources", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, agent, ip, host), fuzzyRow("K2", 2, agent, ip, mac)}, ActionCreate, "", []int{0, 1}},
		{"new strong key absorbs multiple contained weak sources", []IdentifierValue{agent, ip, host, mac}, []Candidate{fuzzyRow("K1", 1, ip, host), fuzzyRow("K2", 2, ip, mac)}, ActionCreate, "", []int{0, 1}},
		{"new strong key does not absorb partial weak overlap", []IdentifierValue{agent, ip, host}, []Candidate{fuzzyRow("K1", 1, ip, mac)}, ActionCreate, "", nil},
		{"non-transitive strong overlap keeps only compatible middle source", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K1", 1, agent, ip), fuzzyRow("K2", 2, agent, otherAgent, ip), fuzzyRow("K3", 3, otherAgent, ip)}, ActionCreate, "", []int{1}},
		{"empty observation never merges", nil, []Candidate{fuzzyRow("K1", 1)}, ActionCreate, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Observation{Identifiers: tt.incoming}, tt.rows, GreenboneMatchPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != tt.action || got.SelectedKey != tt.selected || !reflect.DeepEqual(got.MergeIndices, tt.merges) {
				t.Fatalf("unexpected decision: %+v", got)
			}
			if len(got.MergeIndices) > 0 {
				got.MergeIndices[0] = 99
				again, err := Decide(Observation{Identifiers: tt.incoming}, tt.rows, GreenboneMatchPolicy())
				if err != nil || !reflect.DeepEqual(again.MergeIndices, tt.merges) {
					t.Fatalf("output mutation retained: %+v %v", again, err)
				}
			}
		})
	}
}

// Compare the grouped optimization with the original pairwise rule, including
// non-transitive overlaps, scopes, duplicate values, and different strong types.
func TestGroupedMergesMatchPairwiseRule(t *testing.T) {
	policy := GreenboneMatchPolicy()
	random := rand.New(rand.NewSource(42))
	for run := 0; run < 200; run++ {
		views := make([][]IdentifierValue, 20)
		for i := range views {
			for count := random.Intn(5); count > 0; count-- {
				types := []IdentifierType{TypeGreenboneID, TypeAgentID, TypeTLSPublicKeyHash}
				if run%4 != 0 {
					types = []IdentifierType{types[run%4-1]}
				}
				typ := types[random.Intn(len(types))]
				value := []string{"a", "b", "c", "\xff", "\ufffd", "x\ny"}[random.Intn(6)]
				if typ == TypeTLSPublicKeyHash {
					value = "spki-sha256:" + strings.Repeat([]string{"a", "b", "c"}[random.Intn(3)], 64)
				}
				var scope Scope
				switch random.Intn(3) {
				case 1:
					scope = Scope{}
				case 2:
					scope = Scope{"realm": "r"}
				}
				views[i] = append(views[i], IdentifierValue{Type: typ, Value: value, Scope: scope})
			}
		}
		decision := Decision{}
		for i := range views {
			decision.MergeIndices = append(decision.MergeIndices, i)
		}
		blocked := make([]bool, len(views))
		for i, left := range views {
			if firstStrongType(left, policy) == "" {
				continue
			}
			for j := i + 1; j < len(views); j++ {
				right := views[j]
				if firstStrongType(right, policy) == "" {
					continue
				}
				var typ IdentifierType
				for _, member := range policy.StrongOrder {
					if firstStrongType(left, MatchPolicy{StrongOrder: []IdentifierType{member}}) != "" || firstStrongType(right, MatchPolicy{StrongOrder: []IdentifierType{member}}) != "" {
						typ = member
						break
					}
				}
				match, err := EvaluateStrongPriority(MatchPolicy{StrongOrder: []IdentifierType{typ}}, left, [][]IdentifierValue{right})
				if err != nil {
					t.Fatal(err)
				}
				if len(match.CandidateIndices) == 0 {
					blocked[i], blocked[j] = true, true
				}
			}
		}
		var want []int
		for i := range views {
			if !blocked[i] {
				want = append(want, i)
			}
		}
		excludeConflictingStrongSources(&decision, views, policy)
		if !slices.Equal(decision.MergeIndices, want) {
			t.Fatalf("run %d: got %v, want %v", run, decision.MergeIndices, want)
		}
	}
}

func TestStrongSetKeyPreservesRepresentation(t *testing.T) {
	values := []IdentifierValue{
		{Type: TypeAgentID, Value: "a"},
		{Type: TypeAgentID, Value: "a", Scope: Scope{}},
		{Type: TypeAgentID, Value: "\xff"},
		{Type: TypeAgentID, Value: "\ufffd"},
		{Type: TypeAgentID, Value: "a", Scope: Scope{"\xff": "x"}},
		{Type: TypeAgentID, Value: "a", Scope: Scope{"\ufffd": "x"}},
	}
	seen := make(map[string]bool)
	for _, value := range values {
		key := strongSetKey([]IdentifierValue{value})
		if seen[key] {
			t.Fatalf("distinct representations grouped together: %+v", value)
		}
		seen[key] = true
	}
	left := []IdentifierValue{values[0], values[1], values[0]}
	right := []IdentifierValue{values[1], values[0]}
	if strongSetKey(left) != strongSetKey(right) {
		t.Fatal("order or duplicates affect grouping")
	}
}

func BenchmarkMergePlanManyCandidates(b *testing.B) {
	for _, n := range []int{100, 3200} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			ip := fuzzyValue(TypeIP, "192.0.2.1")
			observation := Observation{Identifiers: []IdentifierValue{ip, fuzzyValue(TypeHostname, "host.example")}}
			rows := make([]Candidate, n)
			for i := range rows {
				rows[i] = Candidate{AssetKey: strconv.Itoa(i), Identifiers: []IdentifierValue{ip, fuzzyValue(TypeAgentID, "a")}}
			}
			policy := GreenboneMatchPolicy()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := Decide(observation, rows, policy)
				if err != nil || len(result.MergeIndices) != n {
					b.Fatalf("decision: %+v %v", result, err)
				}
			}
		})
	}
}
