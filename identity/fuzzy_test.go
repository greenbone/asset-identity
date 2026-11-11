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
func TestFuzzyKernelEvidence(t *testing.T) {
	ip1 := fuzzyValue(TypeIP, "192.0.2.1")
	ip2 := fuzzyValue(TypeIP, "192.0.2.2")
	ip3 := fuzzyValue(TypeIP, "192.0.2.3")
	host := fuzzyValue(TypeHostname, "host")
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	tests := []struct {
		name        string
		observation []IdentifierValue
		candidates  []Candidate
		selected    int
		score       float32
	}{
		{"candidate contains observation", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", 10, ip1, ip2)}, 0, .4},
		{"observation contains one", []IdentifierValue{ip1, ip2}, []Candidate{fuzzyRow("K1", 10, ip1)}, 0, .4},
		{"partial overlap", []IdentifierValue{ip1, ip3}, []Candidate{fuzzyRow("K1", 10, ip1, ip2)}, 0, .4},
		{"multiple matches remain ambiguous despite recency", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", 10, ip1), fuzzyRow("K2", 20, ip1, host)}, -1, 0},
		{"multiple contained", []IdentifierValue{ip1, ip2, host}, []Candidate{fuzzyRow("K1", 10, ip1), fuzzyRow("K2", 20, host), fuzzyRow("K3", 30, ip1, ip3)}, -1, 0},
		{"equal scores and times remain ambiguous", []IdentifierValue{ip1}, []Candidate{fuzzyRow("Z", 20, ip1), fuzzyRow("A", 20, ip1)}, -1, 0},
		{"multiple distinct values", []IdentifierValue{ip1, ip2}, []Candidate{fuzzyRow("K1", 10, ip1, ip2, ip3)}, 0, .8},
		{"empty observation guard", nil, []Candidate{fuzzyRow("K1", 10, ip1)}, -1, 0},
		{"empty candidate literal subset", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", 10)}, -1, 0},
		{"no candidates", []IdentifierValue{ip1}, nil, -1, 0},
		{"unrelated candidate does not prevent unique reuse", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", 20, ip1, host), fuzzyRow("K2", 10, host)}, 0, .4},
		{"negative timestamps cannot resolve ambiguity", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", -10, ip1), fuzzyRow("K2", -20, ip1)}, -1, 0},
		{"pre epoch versus epoch", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", -1, ip1), fuzzyRow("K2", 0, ip1)}, -1, 0},
		{"hostname weight", []IdentifierValue{host}, []Candidate{fuzzyRow("K1", 10, host)}, 0, .4},
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
		{"semantic DNS duplicates", []IdentifierValue{fuzzyValue(TypeHostname, "HOST."), fuzzyValue(TypeHostname, "host.")}, []IdentifierValue{fuzzyValue(TypeHostname, "host.")}, GreenboneMatchPolicy(), .4, true},
		{"semantic IPv6 duplicates", []IdentifierValue{fuzzyValue(TypeIP, "2001:0DB8::1"), fuzzyValue(TypeIP, "2001:db8::1")}, []IdentifierValue{fuzzyValue(TypeIP, "2001:db8::1")}, GreenboneMatchPolicy(), .4, true},
		{"MAC formatting duplicates", []IdentifierValue{fuzzyValue(TypeMAC, "02-AB-CD-EF-01-23"), fuzzyValue(TypeMAC, "02:ab:cd:ef:01:23")}, []IdentifierValue{fuzzyValue(TypeMAC, "02abcdef0123")}, GreenboneMatchPolicy(), 1, true},
		{"missing FQDN permits reuse", []IdentifierValue{ip, fuzzyValue(TypeFQDN, "host.example.")}, []IdentifierValue{ip}, GreenboneMatchPolicy(), .4, true},
		{"normalized FQDN weight", []IdentifierValue{fuzzyValue(TypeFQDN, "HOST.EXAMPLE.")}, []IdentifierValue{fuzzyValue(TypeFQDN, "host.example")}, GreenboneMatchPolicy(), .4, true},
		{"FQDN and IP weights", []IdentifierValue{ip, fuzzyValue(TypeFQDN, "host.example.")}, []IdentifierValue{ip, fuzzyValue(TypeFQDN, "host.example")}, GreenboneMatchPolicy(), .8, true},
		{"omitted FQDN projected out", []IdentifierValue{ip, fuzzyValue(TypeFQDN, "host.example.")}, []IdentifierValue{ip}, MatchPolicy{Fuzzy: []FuzzyMember{{Type: TypeIP, Weight: .4}}}, .4, true},
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
}

func TestFuzzyKernelImmutableAndConcurrent(t *testing.T) {
	ip := IdentifierValue{Type: TypeIP, Value: "2001:0DB8::1"}
	obs := Observation{Identifiers: []IdentifierValue{ip}}
	rows := []Candidate{fuzzyRow("survivor", 20, ip), fuzzyRow("unrelated", 10, fuzzyValue(TypeIP, "192.0.2.1"))}
	p := GreenboneMatchPolicy()
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
	if obs.Identifiers[0] != ip || rows[0].Identifiers[0] != ip || *rows[0].LastSeen != originalTime || !reflect.DeepEqual(p, originalPolicy) {
		t.Fatal("input mutated")
	}
	got, err := matchFuzzyKernel(obs, rows, p)
	if err != nil || *got.SelectedIndex != 0 {
		t.Fatalf("result aliases retained state: %+v %v", got, err)
	}
}

func TestFuzzyScoreCReferenceFixtures(t *testing.T) {
	file, err := os.Open("testdata/fuzzy_reference.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	count := 0
	for {
		var fixture struct {
			Name              string
			Observation       []IdentifierValue
			Candidates        []struct{ Identifiers []IdentifierValue }
			SelectedIndex     int
			SelectedScoreBits uint32
		}
		if err := decoder.Decode(&fixture); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		t.Run(fixture.Name, func(t *testing.T) {
			if fixture.SelectedIndex < 0 {
				return
			}
			policy := GreenboneMatchPolicy()
			weights, err := fuzzyWeights(policy)
			if err != nil {
				t.Fatal(err)
			}
			incoming, err := canonicalMatchingView(fixture.Observation)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := canonicalMatchingView(fixture.Candidates[fixture.SelectedIndex].Identifiers)
			if err != nil {
				t.Fatal(err)
			}
			score, err := fuzzyIntersectionScore(fuzzySetFromCanonical(incoming, weights), fuzzySetFromCanonical(stored, weights), weights, policy.Fuzzy)
			if err != nil || math.Float32bits(score) != fixture.SelectedScoreBits {
				t.Fatalf("score=%v error=%v; expected bits=%v", score, err, fixture.SelectedScoreBits)
			}
		})
		count++
	}
	if count != 78 {
		t.Fatalf("C fixture count = %d", count)
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
	return matchFuzzyCanonical(incoming, views, candidates, policy)
}
