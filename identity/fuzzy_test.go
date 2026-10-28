// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

func fuzzyValue(typ IdentifierType, value string) IdentifierValue {
	return IdentifierValue{Type: typ, Value: value}
}
func fuzzyRow(key string, seconds int64, values ...IdentifierValue) Candidate {
	when := time.Unix(seconds, 0)
	return Candidate{AssetKey: key, LastSeen: &when, Identifiers: values}
}
func TestFuzzyKernelSelection(t *testing.T) {
	ip1 := fuzzyValue(TypeIP, "192.0.2.1")
	ip2 := fuzzyValue(TypeIP, "192.0.2.2")
	ip3 := fuzzyValue(TypeIP, "192.0.2.3")
	host := fuzzyValue(TypeHostname, "host")
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	otherMAC := fuzzyValue(TypeMAC, "02:00:00:00:00:02")
	tests := []struct {
		name        string
		observation []IdentifierValue
		candidates  []Candidate
		selected    int
		score       float32
	}{
		{"anchor alone selects", []IdentifierValue{mac}, []Candidate{fuzzyRow("K1", 10, mac, ip1)}, 0, 1},
		{"two shared types select", []IdentifierValue{ip1, host}, []Candidate{fuzzyRow("K1", 10, ip1, host, ip2)}, 0, .8},
		{"one shared type is insufficient", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", 10, ip1, ip2)}, -1, 0},
		{"observed extra value does not block", []IdentifierValue{ip1, ip2, host}, []Candidate{fuzzyRow("K1", 10, ip1, host)}, 0, .8},
		{"partial overlap of one type is insufficient", []IdentifierValue{ip1, ip3}, []Candidate{fuzzyRow("K1", 10, ip1, ip2)}, -1, 0},
		{"different anchors contradict", []IdentifierValue{mac, ip1, host}, []Candidate{fuzzyRow("K1", 10, otherMAC, ip1, host)}, -1, 0},
		{"anchor on one side only", []IdentifierValue{mac, ip1, host}, []Candidate{fuzzyRow("K1", 10, ip1, host)}, 0, .8},
		{"highest score wins over newest", []IdentifierValue{mac, ip1, host}, []Candidate{fuzzyRow("K1", 20, mac), fuzzyRow("K2", 10, mac, ip1)}, 1, 1.4},
		{"equal score newest wins", []IdentifierValue{mac}, []Candidate{fuzzyRow("K1", 10, mac), fuzzyRow("K2", 20, mac, host)}, 1, 1},
		{"equal score time first row not lexical", []IdentifierValue{mac}, []Candidate{fuzzyRow("Z", 20, mac), fuzzyRow("A", 20, mac)}, 0, 1},
		{"multiple distinct values", []IdentifierValue{ip1, ip2}, []Candidate{fuzzyRow("K1", 10, ip1, ip2, ip3)}, -1, 0},
		{"empty observation guard", nil, []Candidate{fuzzyRow("K1", 10, ip1)}, -1, 0},
		{"empty candidate", []IdentifierValue{mac}, []Candidate{fuzzyRow("K1", 10)}, -1, 0},
		{"no candidates", []IdentifierValue{mac}, nil, -1, 0},
		{"first negative timestamp accepted", []IdentifierValue{mac}, []Candidate{fuzzyRow("K1", -10, mac), fuzzyRow("K2", -20, mac)}, 0, 1},
		{"pre epoch versus epoch", []IdentifierValue{mac}, []Candidate{fuzzyRow("K1", -1, mac), fuzzyRow("K2", 0, mac)}, 1, 1},
		{"hostname and ip weights", []IdentifierValue{host, ip1}, []Candidate{fuzzyRow("K1", 10, host, ip1)}, 0, .8},
		{"mac weight", []IdentifierValue{mac}, []Candidate{fuzzyRow("K1", 10, mac)}, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := Observation{Identifiers: tt.observation}
			got, err := matchFuzzyKernel(obs, tt.candidates, GreenboneMatchPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if got.NeedsNewKey != (tt.selected < 0) || got.SelectedScore != tt.score {
				t.Fatalf("result = %+v", got)
			}
			if tt.selected < 0 {
				if got.SelectedIndex != nil || got.SelectedKey != "" {
					t.Fatal("unexpected survivor")
				}
			} else if got.SelectedIndex == nil || *got.SelectedIndex != tt.selected || got.SelectedKey != tt.candidates[tt.selected].AssetKey {
				t.Fatal("wrong survivor")
			}
		})
	}
}

func TestFuzzyKernelNormalizationAndConfiguration(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	tests := []struct {
		name     string
		incoming []IdentifierValue
		row      []IdentifierValue
		policy   MatchPolicy
		score    float32
		selected bool
	}{
		{"semantic DNS duplicates", []IdentifierValue{fuzzyValue(TypeHostname, "HOST."), fuzzyValue(TypeHostname, "host."), ip}, []IdentifierValue{fuzzyValue(TypeHostname, "host."), ip}, GreenboneMatchPolicy(), .8, true},
		{"semantic IPv6 duplicates", []IdentifierValue{fuzzyValue(TypeIP, "2001:0DB8::1"), fuzzyValue(TypeIP, "2001:db8::1"), fuzzyValue(TypeMAC, "02:ab:cd:ef:01:23")}, []IdentifierValue{fuzzyValue(TypeIP, "2001:db8::1"), fuzzyValue(TypeMAC, "02:ab:cd:ef:01:23")}, GreenboneMatchPolicy(), 1.4, true},
		{"MAC formatting duplicates", []IdentifierValue{fuzzyValue(TypeMAC, "02-AB-CD-EF-01-23"), fuzzyValue(TypeMAC, "02:ab:cd:ef:01:23")}, []IdentifierValue{fuzzyValue(TypeMAC, "02abcdef0123")}, GreenboneMatchPolicy(), 1, true},
		{"one shared type is insufficient", []IdentifierValue{ip, fuzzyValue(TypeFQDN, "host.example.")}, []IdentifierValue{ip}, GreenboneMatchPolicy(), 0, false},
		{"normalized FQDN and IP weights", []IdentifierValue{ip, fuzzyValue(TypeFQDN, "HOST.EXAMPLE.")}, []IdentifierValue{ip, fuzzyValue(TypeFQDN, "host.example")}, GreenboneMatchPolicy(), .8, true},
		{"omitted FQDN projected out, IP as anchor", []IdentifierValue{ip, fuzzyValue(TypeFQDN, "host.example.")}, []IdentifierValue{ip}, MatchPolicy{Fuzzy: []FuzzyMember{{Type: TypeIP, Weight: 1}}}, 1, true},
		{"disabled fuzzy types", []IdentifierValue{ip}, []IdentifierValue{ip}, MatchPolicy{}, 0, false},
		{"configured types and weights", []IdentifierValue{fuzzyValue(TypeAgentID, "a"), ip}, []IdentifierValue{fuzzyValue(TypeAgentID, "a"), ip}, MatchPolicy{Fuzzy: []FuzzyMember{{Type: TypeAgentID, Weight: 2}, {Type: TypeIP, Weight: .25}}}, 2.25, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchFuzzyKernel(Observation{Identifiers: tt.incoming}, []Candidate{fuzzyRow("K1", 10, tt.row...)}, tt.policy)
			if err != nil || got.SelectedScore != tt.score || (got.SelectedIndex != nil) != tt.selected {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
	// Equal payloads with absent, empty, or different scopes are distinct tokens.
	for _, scope := range []Scope{{}, {"realm": "other"}} {
		candidate := ip.Clone()
		candidate.Scope = scope
		got, err := matchFuzzyKernel(Observation{Identifiers: []IdentifierValue{ip}}, []Candidate{fuzzyRow("K1", 10, candidate)}, GreenboneMatchPolicy())
		if err != nil || got.SelectedIndex != nil {
			t.Fatalf("scopes collapsed: %+v, %v", got, err)
		}
	}
}

func TestFuzzyKernelImmutableAndConcurrent(t *testing.T) {
	mac := IdentifierValue{Type: TypeMAC, Value: "02-AB-CD-EF-01-23", Scope: Scope{"network": "n"}}
	obs := Observation{Identifiers: []IdentifierValue{mac}}
	rows := []Candidate{fuzzyRow("survivor", 20, mac), fuzzyRow("potential", 10, mac)}
	p := GreenboneMatchPolicy()
	original := mac.Clone()
	originalTime := *rows[0].LastSeen
	originalPolicy := p.Clone()
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 20 {
				got, err := matchFuzzyKernel(obs, rows, p)
				if err != nil {
					t.Error(err)
					return
				}
				*got.SelectedIndex = 100
			}
		})
	}
	wg.Wait()
	if !reflect.DeepEqual(mac, original) || *rows[0].LastSeen != originalTime || !reflect.DeepEqual(p, originalPolicy) {
		t.Fatal("input mutated")
	}
	got, err := matchFuzzyKernel(obs, rows, p)
	if err != nil || *got.SelectedIndex != 0 {
		t.Fatalf("result aliases retained state: %+v %v", got, err)
	}
}

// The fixtures pin fuzzy key selection, score bits and merge plans for canonical fuzzy-only views.
func TestFuzzyReferenceFixtures(t *testing.T) {
	file, err := os.Open("testdata/fuzzy_reference.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	count := 0
	for {
		var fixture struct {
			Name        string
			Observation []IdentifierValue
			Candidates  []struct {
				AssetKey    string
				LastSeen    int64
				Identifiers []IdentifierValue
			}
			NeedsNewKey           bool
			SelectedIndex         int
			SelectedKey           string
			SelectedScoreBits     uint32
			PotentialMergeIndices []int
		}
		if err := decoder.Decode(&fixture); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		t.Run(fixture.Name, func(t *testing.T) {
			rows := make([]Candidate, len(fixture.Candidates))
			for i, c := range fixture.Candidates {
				rows[i] = fuzzyRow(c.AssetKey, c.LastSeen, c.Identifiers...)
			}
			got, err := matchFuzzyKernel(Observation{Identifiers: fixture.Observation}, rows, GreenboneMatchPolicy())
			if err != nil {
				t.Fatal(err)
			}

			decision, err := Decide(Observation{Identifiers: fixture.Observation}, rows, GreenboneMatchPolicy())
			expectedAction := ActionCreate
			if fixture.SelectedIndex >= 0 {
				expectedAction = ActionReuse
			}
			if err != nil || decision.Action != expectedAction || decision.Stage != StageFuzzy || decision.NeedsNewKey != fixture.NeedsNewKey || decision.SelectedKey != fixture.SelectedKey {
				t.Fatalf("Decide differs from fixture: %+v %v", decision, err)
			}
			if !reflect.DeepEqual(append([]int{}, decision.MergeIndices...), append([]int{}, fixture.PotentialMergeIndices...)) {
				t.Fatalf("merge indices %v differ from fixture %v", decision.MergeIndices, fixture.PotentialMergeIndices)
			}
			selected := -1
			if got.SelectedIndex != nil {
				selected = *got.SelectedIndex
			}
			if got.NeedsNewKey != fixture.NeedsNewKey || selected != fixture.SelectedIndex || got.SelectedKey != fixture.SelectedKey || math.Float32bits(got.SelectedScore) != fixture.SelectedScoreBits {
				t.Fatalf("result %+v differs from fixture %+v", got, fixture)
			}
		})
		count++
	}
	if count != 78 {
		t.Fatalf("fixture count = %d", count)
	}
}

func TestFuzzyKernelFloat32Accumulation(t *testing.T) {
	values := []IdentifierValue{fuzzyValue(TypeMAC, "02:00:00:00:00:01"), fuzzyValue(TypeHostname, "host"), fuzzyValue(TypeIP, "192.0.2.1")}
	tests := []struct {
		name    string
		members []FuzzyMember
		want    float32
	}{
		{"MAC first", []FuzzyMember{{Type: TypeMAC, Weight: 1e8}, {Type: TypeHostname, Weight: 4}, {Type: TypeIP, Weight: 4}}, 100000000},
		{"MAC last", []FuzzyMember{{Type: TypeHostname, Weight: 4}, {Type: TypeIP, Weight: 4}, {Type: TypeMAC, Weight: 1e8}}, 100000008},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := MatchPolicy{Fuzzy: tt.members}
			got, err := matchFuzzyKernel(Observation{Identifiers: values}, []Candidate{fuzzyRow("K", 10, values...)}, p)
			if err != nil || got.SelectedScore != tt.want {
				t.Fatalf("score=%v error=%v", got.SelectedScore, err)
			}
		})
	}
	p := MatchPolicy{Fuzzy: []FuzzyMember{{Type: TypeMAC, Weight: math.MaxFloat32}}}
	values = append(values[:1], fuzzyValue(TypeMAC, "02:00:00:00:00:02"))
	got, err := matchFuzzyKernel(Observation{Identifiers: values}, []Candidate{fuzzyRow("K", 10, values...)}, p)
	if err == nil || !reflect.DeepEqual(got, fuzzyKernelResult{}) {
		t.Fatalf("nonfinite score: %+v %v", got, err)
	}
}

// matchFuzzyKernel keeps raw-input fixtures independent of Decide validation.
func matchFuzzyKernel(observation Observation, candidates []Candidate, policy MatchPolicy) (fuzzyKernelResult, error) {
	weights, err := fuzzyWeights(policy)
	if err != nil {
		return fuzzyKernelResult{}, err
	}
	incoming, err := canonicalMatchingView(observation.Identifiers)
	if err != nil {
		return fuzzyKernelResult{}, fmt.Errorf("observation: %w", err)
	}
	if len(fuzzySetFromCanonical(incoming, weights)) == 0 || len(candidates) == 0 {
		return fuzzyKernelResult{NeedsNewKey: true}, nil
	}
	views := make([][]IdentifierValue, len(candidates))
	for i, candidate := range candidates {
		if candidate.AssetKey == "" {
			return fuzzyKernelResult{}, fmt.Errorf("%w: candidate %d: empty asset key", ErrEmptyCandidateKey, i)
		}
		if err := validateLastSeen(candidate.LastSeen); err != nil {
			return fuzzyKernelResult{}, fmt.Errorf("candidate %d: %w", i, err)
		}
		values, err := canonicalMatchingView(candidate.Identifiers)
		if err != nil {
			return fuzzyKernelResult{}, fmt.Errorf("candidate %d: %w", i, err)
		}
		views[i] = values
	}
	return matchFuzzyCanonical(incoming, views, candidates, nil, policy)
}
