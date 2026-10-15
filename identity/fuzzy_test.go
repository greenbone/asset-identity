package identity

import (
	"encoding/json"
	"io"
	"math"
	"os"
	"reflect"
	"slices"
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
func TestFuzzyKernelContainment(t *testing.T) {
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
		targets     []int
		score       float32
	}{
		{"candidate contains observation", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", 10, ip1, ip2)}, 0, nil, .4},
		{"observation contains one", []IdentifierValue{ip1, ip2}, []Candidate{fuzzyRow("K1", 10, ip1)}, -1, []int{0}, 0},
		{"partial overlap", []IdentifierValue{ip1, ip3}, []Candidate{fuzzyRow("K1", 10, ip1, ip2)}, -1, nil, 0},
		{"multiple containing same score newest", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", 10, ip1), fuzzyRow("K2", 20, ip1, host)}, 1, []int{0}, .4},
		{"multiple contained", []IdentifierValue{ip1, ip2, host}, []Candidate{fuzzyRow("K1", 10, ip1), fuzzyRow("K2", 20, host), fuzzyRow("K3", 30, ip1, ip3)}, -1, []int{0, 1}, 0},
		{"equal score time first row not lexical", []IdentifierValue{ip1}, []Candidate{fuzzyRow("Z", 20, ip1), fuzzyRow("A", 20, ip1)}, 0, []int{1}, .4},
		{"multiple distinct values", []IdentifierValue{ip1, ip2}, []Candidate{fuzzyRow("K1", 10, ip1, ip2, ip3)}, 0, nil, .8},
		{"empty observation guard", nil, []Candidate{fuzzyRow("K1", 10, ip1)}, -1, nil, 0},
		{"empty candidate literal subset", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", 10)}, -1, []int{0}, 0},
		{"no candidates", []IdentifierValue{ip1}, nil, -1, nil, 0},
		{"candidate merge without observation overlap", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", 20, ip1, host), fuzzyRow("K2", 10, host)}, 0, []int{1}, .4},
		{"first negative timestamp accepted", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", -10, ip1), fuzzyRow("K2", -20, ip1)}, 0, []int{1}, .4},
		{"pre epoch versus epoch", []IdentifierValue{ip1}, []Candidate{fuzzyRow("K1", -1, ip1), fuzzyRow("K2", 0, ip1)}, 1, []int{0}, .4},
		{"hostname weight", []IdentifierValue{host}, []Candidate{fuzzyRow("K1", 10, host)}, 0, nil, .4},
		{"mac weight", []IdentifierValue{mac}, []Candidate{fuzzyRow("K1", 10, mac)}, 0, nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := Observation{Identifiers: tt.observation}
			got, err := matchFuzzyKernel(obs, tt.candidates, GreenboneMatchPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if got.NeedsNewKey != (tt.selected < 0) || !reflect.DeepEqual(got.PotentialMergeIndices, tt.targets) || got.SelectedScore != tt.score {
				t.Fatalf("result = %+v", got)
			}
			if tt.selected < 0 {
				if got.SelectedIndex != nil || got.SelectedKey != "" {
					t.Fatal("unexpected survivor")
				}
			} else if got.SelectedIndex == nil || *got.SelectedIndex != tt.selected || got.SelectedKey != tt.candidates[tt.selected].AssetKey {
				t.Fatal("wrong survivor")
			}
			var keys []string
			for _, i := range tt.targets {
				keys = append(keys, tt.candidates[i].AssetKey)
			}
			if !reflect.DeepEqual(got.PotentialMergeKeys, keys) {
				t.Fatalf("keys = %v", got.PotentialMergeKeys)
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
		{"unassigned FQDN projected out", []IdentifierValue{ip, fuzzyValue(TypeFQDN, "host.example.")}, []IdentifierValue{ip}, GreenboneMatchPolicy(), .4, true},
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
		if err != nil || got.SelectedIndex != nil || len(got.PotentialMergeIndices) > 0 {
			t.Fatalf("scopes collapsed: %+v, %v", got, err)
		}
	}
}

func TestFuzzyKernelImmutableAndConcurrent(t *testing.T) {
	ip := IdentifierValue{Type: TypeIP, Value: "2001:0DB8::1", Scope: Scope{"network": "n"}}
	obs := Observation{Identifiers: []IdentifierValue{ip}}
	rows := []Candidate{fuzzyRow("survivor", 20, ip), fuzzyRow("potential", 10, ip)}
	p := GreenboneMatchPolicy()
	original := ip.Clone()
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
				got.PotentialMergeIndices[0] = 100
				got.PotentialMergeKeys[0] = "changed"
			}
		})
	}
	wg.Wait()
	if !reflect.DeepEqual(ip, original) || *rows[0].LastSeen != originalTime || !reflect.DeepEqual(p, originalPolicy) {
		t.Fatal("input mutated")
	}
	got, err := matchFuzzyKernel(obs, rows, p)
	if err != nil || *got.SelectedIndex != 0 || !reflect.DeepEqual(got.PotentialMergeIndices, []int{1}) || got.PotentialMergeKeys[0] != "potential" {
		t.Fatalf("result aliases retained state: %+v %v", got, err)
	}
}

// Expected fields were captured by executing the pinned, unmodified C source.
// This regression test consumes data only; Go builds never depend on C or GLib.
func TestFuzzyKernelCReferenceFixtures(t *testing.T) {
	file, err := os.Open("testdata/fuzzy_c_compat.jsonl")
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

			var expectedKeys []string
			for _, index := range fixture.PotentialMergeIndices {
				expectedKeys = append(expectedKeys, fixture.Candidates[index].AssetKey)
			}
			if !slices.Equal(got.PotentialMergeKeys, expectedKeys) {
				t.Fatalf("potential merge keys differ: %v versus %v", got.PotentialMergeKeys, expectedKeys)
			}

			decision, err := Decide(Observation{Identifiers: fixture.Observation}, rows, GreenboneMatchPolicy())
			expectedAction := ActionCreate
			if len(fixture.PotentialMergeIndices) > 0 {
				expectedAction = ActionReview
			} else if fixture.SelectedIndex >= 0 {
				expectedAction = ActionReuse
			}
			if err != nil || decision.Action != expectedAction || decision.Stage != StageFuzzy || decision.NeedsNewKey != fixture.NeedsNewKey || decision.SelectedKey != fixture.SelectedKey || !slices.Equal(decision.PotentialMergeIndices, fixture.PotentialMergeIndices) {
				t.Fatalf("Decide differs from C fixture: %+v %v", decision, err)
			}
			selected := -1
			if got.SelectedIndex != nil {
				selected = *got.SelectedIndex
			}
			if got.NeedsNewKey != fixture.NeedsNewKey || selected != fixture.SelectedIndex || got.SelectedKey != fixture.SelectedKey || math.Float32bits(got.SelectedScore) != fixture.SelectedScoreBits || !slices.Equal(got.PotentialMergeIndices, fixture.PotentialMergeIndices) {
				t.Fatalf("Go result %+v differs from C fixture %+v", got, fixture)
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
