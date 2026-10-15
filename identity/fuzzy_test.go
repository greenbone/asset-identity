package identity_test

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/greenbone/asset-identity/identity"
)

func fuzzyValue(typ identity.IdentifierType, value string) identity.IdentifierValue {
	return identity.IdentifierValue{Type: typ, Value: value}
}
func fuzzyFixtureOptions() identity.FuzzyKernelOptions {
	return identity.FuzzyKernelOptions{LegacyCCompatibility: true, AccumulationOrder: []identity.IdentifierType{identity.TypeMAC, identity.TypeHostname, identity.TypeIP}}
}
func fuzzyRow(key string, seconds int64, values ...identity.IdentifierValue) identity.FuzzyCandidate {
	when := time.Unix(seconds, 0)
	return identity.FuzzyCandidate{AssetKey: key, LastSeen: &when, Identifiers: values, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}
}
func TestFuzzyKernelContainment(t *testing.T) {
	ip1 := fuzzyValue(identity.TypeIP, "192.0.2.1")
	ip2 := fuzzyValue(identity.TypeIP, "192.0.2.2")
	ip3 := fuzzyValue(identity.TypeIP, "192.0.2.3")
	host := fuzzyValue(identity.TypeHostname, "host")
	mac := fuzzyValue(identity.TypeMAC, "02:00:00:00:00:01")
	tests := []struct {
		name        string
		observation []identity.IdentifierValue
		candidates  []identity.FuzzyCandidate
		selected    int
		targets     []int
		score       float32
	}{
		{"candidate contains observation", []identity.IdentifierValue{ip1}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, ip1, ip2)}, 0, nil, .4},
		{"observation contains one", []identity.IdentifierValue{ip1, ip2}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, ip1)}, -1, []int{0}, 0},
		{"partial overlap", []identity.IdentifierValue{ip1, ip3}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, ip1, ip2)}, -1, nil, 0},
		{"multiple containing same score newest", []identity.IdentifierValue{ip1}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, ip1), fuzzyRow("K2", 20, ip1, host)}, 1, []int{0}, .4},
		{"multiple contained", []identity.IdentifierValue{ip1, ip2, host}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, ip1), fuzzyRow("K2", 20, host), fuzzyRow("K3", 30, ip1, ip3)}, -1, []int{0, 1}, 0},
		{"equal score time first row not lexical", []identity.IdentifierValue{ip1}, []identity.FuzzyCandidate{fuzzyRow("Z", 20, ip1), fuzzyRow("A", 20, ip1)}, 0, []int{1}, .4},
		{"multiple distinct values", []identity.IdentifierValue{ip1, ip2}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, ip1, ip2, ip3)}, 0, nil, .8},
		{"empty observation guard", nil, []identity.FuzzyCandidate{fuzzyRow("K1", 10, ip1)}, -1, nil, 0},
		{"empty candidate literal subset", []identity.IdentifierValue{ip1}, []identity.FuzzyCandidate{fuzzyRow("K1", 10)}, -1, []int{0}, 0},
		{"no candidates", []identity.IdentifierValue{ip1}, nil, -1, nil, 0},
		{"candidate merge without observation overlap", []identity.IdentifierValue{ip1}, []identity.FuzzyCandidate{fuzzyRow("K1", 20, ip1, host), fuzzyRow("K2", 10, host)}, 0, []int{1}, .4},
		{"first negative timestamp accepted", []identity.IdentifierValue{ip1}, []identity.FuzzyCandidate{fuzzyRow("K1", -10, ip1), fuzzyRow("K2", -20, ip1)}, 0, []int{1}, .4},
		{"pre epoch versus epoch", []identity.IdentifierValue{ip1}, []identity.FuzzyCandidate{fuzzyRow("K1", -1, ip1), fuzzyRow("K2", 0, ip1)}, 1, []int{0}, .4},
		{"hostname weight", []identity.IdentifierValue{host}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, host)}, 0, nil, .4},
		{"mac weight", []identity.IdentifierValue{mac}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, mac)}, 0, nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := identity.FuzzyObservation{Identifiers: tt.observation, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}
			got, err := identity.MatchFuzzyKernel(obs, tt.candidates, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions())
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
	ip := fuzzyValue(identity.TypeIP, "192.0.2.1")
	tests := []struct {
		name     string
		incoming []identity.IdentifierValue
		row      []identity.IdentifierValue
		policy   identity.MatchPolicy
		order    []identity.IdentifierType
		score    float32
		selected bool
	}{
		{"semantic DNS duplicates", []identity.IdentifierValue{fuzzyValue(identity.TypeHostname, "HOST."), fuzzyValue(identity.TypeHostname, "host.")}, []identity.IdentifierValue{fuzzyValue(identity.TypeHostname, "host.")}, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions().AccumulationOrder, .4, true},
		{"semantic IPv6 duplicates", []identity.IdentifierValue{fuzzyValue(identity.TypeIP, "2001:0DB8::1"), fuzzyValue(identity.TypeIP, "2001:db8::1")}, []identity.IdentifierValue{fuzzyValue(identity.TypeIP, "2001:db8::1")}, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions().AccumulationOrder, .4, true},
		{"MAC formatting duplicates", []identity.IdentifierValue{fuzzyValue(identity.TypeMAC, "02-AB-CD-EF-01-23"), fuzzyValue(identity.TypeMAC, "02:ab:cd:ef:01:23")}, []identity.IdentifierValue{fuzzyValue(identity.TypeMAC, "02abcdef0123")}, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions().AccumulationOrder, 1, true},
		{"unassigned FQDN projected out", []identity.IdentifierValue{ip, fuzzyValue(identity.TypeFQDN, "host.example.")}, []identity.IdentifierValue{ip}, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions().AccumulationOrder, .4, true},
		{"disabled fuzzy types", []identity.IdentifierValue{ip}, []identity.IdentifierValue{ip}, identity.MatchPolicy{FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, nil, 0, false},
		{"configured types and weights", []identity.IdentifierValue{fuzzyValue(identity.TypeAgentID, "a"), ip}, []identity.IdentifierValue{fuzzyValue(identity.TypeAgentID, "a"), ip}, identity.MatchPolicy{Fuzzy: []identity.FuzzyMember{{Type: identity.TypeAgentID, Weight: 2}, {Type: identity.TypeIP, Weight: .25}}, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, []identity.IdentifierType{identity.TypeIP, identity.TypeAgentID}, 2.25, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identity.MatchFuzzyKernel(identity.FuzzyObservation{Identifiers: tt.incoming, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, tt.row...)}, tt.policy, identity.FuzzyKernelOptions{LegacyCCompatibility: true, AccumulationOrder: tt.order})
			if err != nil || got.SelectedScore != tt.score || (got.SelectedIndex != nil) != tt.selected {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
	// Equal payloads with absent, empty, or different scopes are distinct tokens.
	for _, scope := range []identity.Scope{{}, {"realm": "other"}} {
		candidate := ip.Clone()
		candidate.Scope = scope
		got, err := identity.MatchFuzzyKernel(identity.FuzzyObservation{Identifiers: []identity.IdentifierValue{ip}, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}, []identity.FuzzyCandidate{fuzzyRow("K1", 10, candidate)}, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions())
		if err != nil || got.SelectedIndex != nil || len(got.PotentialMergeIndices) > 0 {
			t.Fatalf("scopes collapsed: %+v, %v", got, err)
		}
	}
}

func TestFuzzyKernelBoundariesAndIndices(t *testing.T) {
	ip := fuzzyValue(identity.TypeIP, "192.168.1.10")
	host := fuzzyValue(identity.TypeHostname, "host")
	tests := []struct {
		name                           string
		mode                           identity.FuzzyBoundaryMode
		obsBoundary, candidateBoundary identity.BoundaryContext
		selected                       bool
	}{
		{"same boundary two scanners", identity.FuzzyBoundaryStrict, identity.BoundaryContext{BoundaryID: "resolved/b1", ScannerID: "s1"}, identity.BoundaryContext{BoundaryID: "resolved/b1", ScannerID: "s2"}, true},
		{"private IP incompatible strict", identity.FuzzyBoundaryStrict, identity.BoundaryContext{BoundaryID: "resolved/b1"}, identity.BoundaryContext{BoundaryID: "resolved/b2"}, false},
		{"private IP incompatible legacy", identity.FuzzyBoundaryLegacy, identity.BoundaryContext{BoundaryID: "resolved/b1"}, identity.BoundaryContext{BoundaryID: "resolved/b2"}, false},
		{"missing strict", identity.FuzzyBoundaryStrict, identity.BoundaryContext{}, identity.BoundaryContext{}, false},
		{"missing legacy", identity.FuzzyBoundaryLegacy, identity.BoundaryContext{}, identity.BoundaryContext{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := fuzzyRow("K1", 10, ip)
			row.Boundary = tt.candidateBoundary
			p := identity.GreenboneMatchPolicy()
			p.FuzzyBoundaryMode = tt.mode
			got, err := identity.MatchFuzzyKernel(identity.FuzzyObservation{Identifiers: []identity.IdentifierValue{ip}, Boundary: tt.obsBoundary}, []identity.FuzzyCandidate{row}, p, fuzzyFixtureOptions())
			if err != nil || (got.SelectedIndex != nil) != tt.selected || len(got.PotentialMergeIndices) > 0 {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}
	excluded := fuzzyRow("excluded", 1)
	excluded.Boundary.BoundaryID = "resolved/b2"
	excluded.LastSeen = nil
	rows := []identity.FuzzyCandidate{excluded, fuzzyRow("survivor", 20, ip, host), excluded, fuzzyRow("subset", 10, host)}
	got, err := identity.MatchFuzzyKernel(identity.FuzzyObservation{Identifiers: []identity.IdentifierValue{ip}, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}, rows, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions())
	if err != nil || got.SelectedIndex == nil || *got.SelectedIndex != 1 || !reflect.DeepEqual(got.PotentialMergeIndices, []int{3}) {
		t.Fatalf("index preservation/excluded empty subsets: %+v %v", got, err)
	}

	// Legacy admits UNKNOWN potential merge targets; strict excludes them.
	unknown := fuzzyRow("unknown-subset", 10, host)
	unknown.Boundary = identity.BoundaryContext{}
	for _, mode := range []identity.FuzzyBoundaryMode{identity.FuzzyBoundaryStrict, identity.FuzzyBoundaryLegacy} {
		p := identity.GreenboneMatchPolicy()
		p.FuzzyBoundaryMode = mode
		result, err := identity.MatchFuzzyKernel(identity.FuzzyObservation{Identifiers: []identity.IdentifierValue{ip}, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}, []identity.FuzzyCandidate{fuzzyRow("survivor", 20, ip, host), unknown}, p, fuzzyFixtureOptions())
		var targets []int
		if mode == identity.FuzzyBoundaryLegacy {
			targets = []int{1}
		}
		if err != nil || !reflect.DeepEqual(result.PotentialMergeIndices, targets) {
			t.Fatalf("UNKNOWN merge evaluation %s: %+v %v", mode, result, err)
		}
	}

	// Case B must retain indices as well, and excluded empty rows cannot reappear.
	got, err = identity.MatchFuzzyKernel(identity.FuzzyObservation{Identifiers: []identity.IdentifierValue{ip, host}, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}, []identity.FuzzyCandidate{excluded, fuzzyRow("subset", 1, ip)}, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions())
	if err != nil || !reflect.DeepEqual(got.PotentialMergeIndices, []int{1}) {
		t.Fatalf("Case B: %+v %v", got, err)
	}
}

func TestFuzzyKernelDefersUnresolvedRules(t *testing.T) {
	ip := fuzzyValue(identity.TypeIP, "192.0.2.1")
	obs := identity.FuzzyObservation{Identifiers: []identity.IdentifierValue{ip}, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}
	tests := []struct {
		name    string
		rows    []identity.FuzzyCandidate
		options identity.FuzzyKernelOptions
		policy  identity.MatchPolicy
		want    error
	}{
		{"explicit compatibility required", []identity.FuzzyCandidate{fuzzyRow("K1", 10, ip)}, identity.FuzzyKernelOptions{}, identity.GreenboneMatchPolicy(), identity.ErrUnresolvedMatchingRule},
		{"missing last seen", []identity.FuzzyCandidate{{AssetKey: "K1", Identifiers: []identity.IdentifierValue{ip}, Boundary: obs.Boundary}}, fuzzyFixtureOptions(), identity.GreenboneMatchPolicy(), identity.ErrUnresolvedMatchingRule},
		{"subsecond last seen", []identity.FuzzyCandidate{{AssetKey: "K1", Identifiers: []identity.IdentifierValue{ip}, Boundary: obs.Boundary, LastSeen: new(time.Unix(10, 1))}}, fuzzyFixtureOptions(), identity.GreenboneMatchPolicy(), identity.ErrUnresolvedMatchingRule},
		{"duplicate admitted keys", []identity.FuzzyCandidate{fuzzyRow("K", 10, ip), fuzzyRow("K", 20, ip)}, fuzzyFixtureOptions(), identity.GreenboneMatchPolicy(), identity.ErrUnresolvedMatchingRule},
		{"unkeyed admitted row", []identity.FuzzyCandidate{fuzzyRow("", 10, ip)}, fuzzyFixtureOptions(), identity.GreenboneMatchPolicy(), identity.ErrUnresolvedMatchingRule},
		{"missing accumulation order", []identity.FuzzyCandidate{fuzzyRow("K", 10, ip)}, identity.FuzzyKernelOptions{LegacyCCompatibility: true}, identity.GreenboneMatchPolicy(), identity.ErrUnresolvedMatchingRule},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identity.MatchFuzzyKernel(obs, tt.rows, tt.policy, tt.options)
			if !errors.Is(err, tt.want) || !reflect.DeepEqual(got, identity.FuzzyKernelResult{}) {
				t.Fatalf("partial result or wrong error: %+v %v", got, err)
			}
		})
	}
	for _, order := range [][]identity.IdentifierType{{identity.TypeIP, identity.TypeIP, identity.TypeMAC}, {identity.TypeIP, identity.TypeHostname, identity.TypeAgentID}} {
		if _, err := identity.MatchFuzzyKernel(obs, nil, identity.GreenboneMatchPolicy(), identity.FuzzyKernelOptions{LegacyCCompatibility: true, AccumulationOrder: order}); !errors.Is(err, identity.ErrInvalidMatchPolicy) {
			t.Fatal(err)
		}
	}
	for _, v := range []identity.IdentifierValue{{Type: identity.TypeIP, Value: "malformed"}, {Type: "unknown", Value: "x"}} {
		bad := obs
		bad.Identifiers = []identity.IdentifierValue{v}
		if got, err := identity.MatchFuzzyKernel(bad, nil, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions()); err == nil || !reflect.DeepEqual(got, identity.FuzzyKernelResult{}) {
			t.Fatal("invalid identifier accepted")
		}
	}
	p := identity.GreenboneMatchPolicy()
	p.Fuzzy[0].Weight = math.MaxFloat64
	if _, err := identity.MatchFuzzyKernel(obs, nil, p, fuzzyFixtureOptions()); !errors.Is(err, identity.ErrUnresolvedMatchingRule) {
		t.Fatalf("unsupported float32 conversion = %v", err)
	}
}

func TestFuzzyKernelImmutableAndConcurrent(t *testing.T) {
	ip := identity.IdentifierValue{Type: identity.TypeIP, Value: "2001:0DB8::1", Scope: identity.Scope{"network": "n"}}
	obs := identity.FuzzyObservation{Identifiers: []identity.IdentifierValue{ip}, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}
	rows := []identity.FuzzyCandidate{fuzzyRow("survivor", 20, ip), fuzzyRow("potential", 10, ip)}
	p := identity.GreenboneMatchPolicy()
	options := fuzzyFixtureOptions()
	original := ip.Clone()
	originalTime := *rows[0].LastSeen
	originalPolicy := p.Clone()
	originalOrder := append([]identity.IdentifierType(nil), options.AccumulationOrder...)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 20 {
				got, err := identity.MatchFuzzyKernel(obs, rows, p, options)
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
	if !reflect.DeepEqual(ip, original) || *rows[0].LastSeen != originalTime || !reflect.DeepEqual(p, originalPolicy) || !reflect.DeepEqual(options.AccumulationOrder, originalOrder) {
		t.Fatal("input mutated")
	}
	got, err := identity.MatchFuzzyKernel(obs, rows, p, options)
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
			Observation []identity.IdentifierValue
			Candidates  []struct {
				AssetKey    string
				LastSeen    int64
				Identifiers []identity.IdentifierValue
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
			rows := make([]identity.FuzzyCandidate, len(fixture.Candidates))
			for i, c := range fixture.Candidates {
				rows[i] = fuzzyRow(c.AssetKey, c.LastSeen, c.Identifiers...)
			}
			got, err := identity.MatchFuzzyKernel(identity.FuzzyObservation{Identifiers: fixture.Observation, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}, rows, identity.GreenboneMatchPolicy(), fuzzyFixtureOptions())
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

func TestFuzzyKernelFloat32Compatibility(t *testing.T) {
	values := []identity.IdentifierValue{fuzzyValue(identity.TypeMAC, "02:00:00:00:00:01"), fuzzyValue(identity.TypeHostname, "host"), fuzzyValue(identity.TypeIP, "192.0.2.1")}
	p := identity.GreenboneMatchPolicy()
	p.Fuzzy = []identity.FuzzyMember{{Type: identity.TypeMAC, Weight: 1e8}, {Type: identity.TypeHostname, Weight: 4}, {Type: identity.TypeIP, Weight: 4}}
	tests := []struct {
		name  string
		order []identity.IdentifierType
		want  float32
	}{
		{"MAC first rounds small terms", []identity.IdentifierType{identity.TypeMAC, identity.TypeHostname, identity.TypeIP}, 100000000},
		{"MAC last preserves accumulated small terms", []identity.IdentifierType{identity.TypeHostname, identity.TypeIP, identity.TypeMAC}, 100000008},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identity.MatchFuzzyKernel(identity.FuzzyObservation{Identifiers: values, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}, []identity.FuzzyCandidate{fuzzyRow("K", 10, values...)}, p, identity.FuzzyKernelOptions{LegacyCCompatibility: true, AccumulationOrder: tt.order})
			if err != nil || got.SelectedScore != tt.want {
				t.Fatalf("score=%v error=%v", got.SelectedScore, err)
			}
		})
	}
	// Finite weights can overflow the float32 score.
	p.Fuzzy = []identity.FuzzyMember{{Type: identity.TypeMAC, Weight: math.MaxFloat32}}
	values = append(values[:1], fuzzyValue(identity.TypeMAC, "02:00:00:00:00:02"))
	got, err := identity.MatchFuzzyKernel(identity.FuzzyObservation{Identifiers: values, Boundary: identity.BoundaryContext{BoundaryID: "resolved/b1"}}, []identity.FuzzyCandidate{fuzzyRow("K", 10, values...)}, p, identity.FuzzyKernelOptions{LegacyCCompatibility: true, AccumulationOrder: []identity.IdentifierType{identity.TypeMAC}})
	if err == nil || !reflect.DeepEqual(got, identity.FuzzyKernelResult{}) {
		t.Fatalf("nonfinite score: %+v %v", got, err)
	}
}
