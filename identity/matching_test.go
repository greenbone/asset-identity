package identity_test

import (
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/greenbone/asset-identity/identity"
)

func TestGreenboneMatchPolicy(t *testing.T) {
	p := identity.GreenboneMatchPolicy()
	want := []identity.IdentifierType{identity.TypeGreenboneID, identity.TypeAgentID, identity.TypeMachineID, identity.TypeBIOSUUID, identity.TypeSSHHostKey, identity.TypeTLSPublicKeyHash, identity.TypeCloudIdentifier}
	if !reflect.DeepEqual(p.StrongOrder, want) {
		t.Fatalf("strong order = %v", p.StrongOrder)
	}
	fuzzy := []identity.FuzzyMember{{Type: identity.TypeMAC, Weight: 1}, {Type: identity.TypeIP, Weight: .4}, {Type: identity.TypeHostname, Weight: .4}}
	if !reflect.DeepEqual(p.Fuzzy, fuzzy) || p.FuzzyBoundaryMode != identity.FuzzyBoundaryStrict {
		t.Fatalf("defaults = %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	copy := p.Clone()
	copy.StrongOrder[0] = identity.TypeIP
	copy.Fuzzy[0].Weight = 9
	if !reflect.DeepEqual(p, identity.GreenboneMatchPolicy()) {
		t.Fatal("defaults or clone share storage")
	}
	p.StrongOrder[0] = identity.TypeIP
	p.Fuzzy[0].Weight = 9
	if fresh := identity.GreenboneMatchPolicy(); !reflect.DeepEqual(fresh.StrongOrder, want) || !reflect.DeepEqual(fresh.Fuzzy, fuzzy) {
		t.Fatal("separate default policies share storage")
	}
}

func TestMatchPolicyValidation(t *testing.T) {
	tests := []struct {
		name   string
		policy identity.MatchPolicy
		err    error
	}{
		{"disabled stages", identity.MatchPolicy{FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, nil},
		{"reordered", identity.MatchPolicy{StrongOrder: []identity.IdentifierType{identity.TypeAgentID, identity.TypeGreenboneID}, FuzzyBoundaryMode: identity.FuzzyBoundaryLegacy}, nil},
		{"reclassified", identity.MatchPolicy{StrongOrder: []identity.IdentifierType{identity.TypeIP, identity.TypeFQDN}, Fuzzy: []identity.FuzzyMember{{Type: identity.TypeGreenboneID, Weight: 2}}, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, nil},
		{"duplicate strong", identity.MatchPolicy{StrongOrder: []identity.IdentifierType{identity.TypeAgentID, identity.TypeAgentID}, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, identity.ErrInvalidMatchPolicy},
		{"unknown strong", identity.MatchPolicy{StrongOrder: []identity.IdentifierType{"unknown"}, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, identity.ErrInvalidMatchPolicy},
		{"duplicate fuzzy", identity.MatchPolicy{Fuzzy: []identity.FuzzyMember{{Type: identity.TypeIP, Weight: 1}, {Type: identity.TypeIP, Weight: 2}}, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, identity.ErrInvalidMatchPolicy},
		{"unknown fuzzy", identity.MatchPolicy{Fuzzy: []identity.FuzzyMember{{Type: "unknown", Weight: 1}}, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, identity.ErrInvalidMatchPolicy},
		{"overlap", identity.MatchPolicy{StrongOrder: []identity.IdentifierType{identity.TypeIP}, Fuzzy: []identity.FuzzyMember{{Type: identity.TypeIP, Weight: 1}}, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, identity.ErrInvalidMatchPolicy},
		{"missing mode", identity.MatchPolicy{}, identity.ErrInvalidMatchPolicy},
		{"unknown mode", identity.MatchPolicy{FuzzyBoundaryMode: "wildcard"}, identity.ErrInvalidMatchPolicy},
		{"fqdn deferred", identity.MatchPolicy{Fuzzy: []identity.FuzzyMember{{Type: identity.TypeFQDN, Weight: 1}}, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, identity.ErrUnresolvedMatchingRule},
	}
	for _, weight := range []float64{-1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		tests = append(tests, struct {
			name   string
			policy identity.MatchPolicy
			err    error
		}{"invalid weight", identity.MatchPolicy{Fuzzy: []identity.FuzzyMember{{Type: identity.TypeMAC, Weight: weight}}, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, identity.ErrInvalidMatchPolicy})
	}
	for _, members := range [][]identity.FuzzyMember{{{Type: identity.TypeIP, Weight: 0}}, {{Type: identity.TypeIP, Weight: 0}, {Type: identity.TypeMAC, Weight: 1}}} {
		tests = append(tests, struct {
			name   string
			policy identity.MatchPolicy
			err    error
		}{"zero semantics deferred", identity.MatchPolicy{Fuzzy: members, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}, identity.ErrUnresolvedMatchingRule})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := tt.policy.Clone()
			err := tt.policy.Validate()
			if !errors.Is(err, tt.err) {
				t.Fatalf("error = %v, want %v", err, tt.err)
			}
			// Compare float bits to preserve NaN and signed-zero representations.
			if !reflect.DeepEqual(tt.policy.StrongOrder, before.StrongOrder) || tt.policy.FuzzyBoundaryMode != before.FuzzyBoundaryMode || len(tt.policy.Fuzzy) != len(before.Fuzzy) {
				t.Fatal("validation mutated input")
			}
			for i, member := range tt.policy.Fuzzy {
				if member.Type != before.Fuzzy[i].Type || math.Float64bits(member.Weight) != math.Float64bits(before.Fuzzy[i].Weight) {
					t.Fatal("validation mutated fuzzy input")
				}
			}
		})
	}
}

func TestBoundaryFoundations(t *testing.T) {
	// These illustrative keys are asserted caller-resolved compatibility classes,
	// not examples of a library-validated qualification grammar.
	tests := []struct {
		name string
		a, b identity.BoundaryContext
		want identity.BoundaryCompatibility
	}{
		{"same", identity.BoundaryContext{BoundaryID: "realm/b1"}, identity.BoundaryContext{BoundaryID: "realm/b1"}, identity.BoundaryCompatible},
		{"two scanners", identity.BoundaryContext{BoundaryID: "realm/b1", ScannerID: "s1"}, identity.BoundaryContext{BoundaryID: "realm/b1", ScannerID: "s2"}, identity.BoundaryCompatible},
		{"same scanner different namespace", identity.BoundaryContext{BoundaryID: "realm/b1", ScannerID: "s1"}, identity.BoundaryContext{BoundaryID: "realm/b2", ScannerID: "s1"}, identity.BoundaryIncompatible},
		{"qualified realm differs", identity.BoundaryContext{BoundaryID: "realm/b1"}, identity.BoundaryContext{BoundaryID: "other/b1"}, identity.BoundaryIncompatible},
		{"one missing", identity.BoundaryContext{BoundaryID: "realm/b1"}, identity.BoundaryContext{}, identity.BoundaryUnknown},
		{"both missing same scanner", identity.BoundaryContext{ScannerID: "s1"}, identity.BoundaryContext{ScannerID: "s1"}, identity.BoundaryUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := tt.a, tt.b
			if got := identity.CompareBoundaries(a, b); got != tt.want {
				t.Fatalf("compatibility = %s", got)
			}
			if got := identity.CompareBoundaries(b, a); got != tt.want {
				t.Fatal("asymmetric")
			}
			if a != tt.a || b != tt.b {
				t.Fatal("mutated boundaries")
			}
			for _, mode := range []identity.FuzzyBoundaryMode{identity.FuzzyBoundaryStrict, identity.FuzzyBoundaryLegacy} {
				got, err := mode.Admit(tt.want)
				want := tt.want == identity.BoundaryCompatible || (mode == identity.FuzzyBoundaryLegacy && tt.want == identity.BoundaryUnknown)
				if err != nil || got != want {
					t.Fatalf("mode %s: %v, %v", mode, got, err)
				}
			}
		})
	}
	for _, tt := range []struct {
		mode   identity.FuzzyBoundaryMode
		compat identity.BoundaryCompatibility
	}{{"", identity.BoundaryCompatible}, {"invalid", identity.BoundaryUnknown}, {identity.FuzzyBoundaryLegacy, "invalid"}} {
		if admitted, err := tt.mode.Admit(tt.compat); err == nil || admitted {
			t.Fatal("invalid admission must return error and false")
		}
	}
}

func TestMatchingIdentifiers(t *testing.T) {
	tests := []struct {
		name        string
		left, right identity.IdentifierValue
		want        bool
	}{
		{"bios canonical", identity.IdentifierValue{Type: identity.TypeBIOSUUID, Value: "{00112233-4455-6677-8899-AABBCCDDEEFF}"}, identity.IdentifierValue{Type: identity.TypeBIOSUUID, Value: "00112233445566778899aabbccddeeff"}, true},
		{"opaque distinct case", identity.IdentifierValue{Type: identity.TypeAgentID, Value: "A"}, identity.IdentifierValue{Type: identity.TypeAgentID, Value: "a"}, false},
		{"scope differs", identity.IdentifierValue{Type: identity.TypeGreenboneID, Value: "G", Scope: identity.Scope{"issuer": "a"}}, identity.IdentifierValue{Type: identity.TypeGreenboneID, Value: "G", Scope: identity.Scope{"issuer": "b"}}, false},
		{"nil versus empty", identity.IdentifierValue{Type: identity.TypeAgentID, Value: "A"}, identity.IdentifierValue{Type: identity.TypeAgentID, Value: "A", Scope: identity.Scope{}}, false},
		{"different types", identity.IdentifierValue{Type: identity.TypeGreenboneID, Value: "A"}, identity.IdentifierValue{Type: identity.TypeAgentID, Value: "A"}, false},
		{"scope insertion order", identity.IdentifierValue{Type: identity.TypeGreenboneID, Value: "G", Scope: identity.Scope{"a": "1", "b": "2"}}, identity.IdentifierValue{Type: identity.TypeGreenboneID, Value: "G", Scope: identity.Scope{"b": "2", "a": "1"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			left, right := tt.left.Clone(), tt.right.Clone()
			matches, err := identity.MatchingIdentifiers([]identity.IdentifierValue{tt.left, tt.left}, []identity.IdentifierValue{tt.right, tt.right})
			if err != nil || (len(matches) == 1) != tt.want || len(matches) > 1 {
				t.Fatalf("matches = %+v, %v", matches, err)
			}
			if !reflect.DeepEqual(left, tt.left) || !reflect.DeepEqual(right, tt.right) {
				t.Fatal("inputs changed")
			}
			if tt.want {
				expected, err := identity.NormalizeIdentifier(tt.left)
				if err != nil {
					t.Fatal(err)
				}
				if !identity.SameRepresentation(matches[0], expected) {
					t.Fatal("not canonical")
				}
				if matches[0].Scope != nil {
					matches[0].Scope["new"] = "changed"
					if !reflect.DeepEqual(left, tt.left) {
						t.Fatal("output aliases scope")
					}
				}
			}
		})
	}
	for _, invalid := range []identity.IdentifierValue{{Type: "unknown", Value: "a"}, {Type: identity.TypeIP, Value: "invalid"}, {Type: identity.TypeMachineID, Value: "a"}} {
		for _, sides := range [][2][]identity.IdentifierValue{{{invalid}, nil}, {nil, {invalid}}} {
			matches, err := identity.MatchingIdentifiers(sides[0], sides[1])
			if err == nil || matches != nil {
				t.Fatal("invalid supplied value must not produce partial matches")
			}
		}
	}
}

func TestStrongPriorityEvaluation(t *testing.T) {
	g := identity.IdentifierValue{Type: identity.TypeGreenboneID, Value: "G"}
	a := identity.IdentifierValue{Type: identity.TypeAgentID, Value: "A"}
	ip := identity.IdentifierValue{Type: identity.TypeIP, Value: "192.0.2.1"}
	bios1 := identity.IdentifierValue{Type: identity.TypeBIOSUUID, Value: "{00112233-4455-6677-8899-AABBCCDDEEFF}"}
	bios2 := identity.IdentifierValue{Type: identity.TypeBIOSUUID, Value: "00112233445566778899aabbccddeeff"}
	tests := []struct {
		name       string
		order      []identity.IdentifierType
		incoming   []identity.IdentifierValue
		candidates [][]identity.IdentifierValue
		typ        identity.IdentifierType
		priority   int
		indices    []int
		strong     bool
	}{
		{"highest default", identity.GreenboneMatchPolicy().StrongOrder, []identity.IdentifierValue{a, g, ip}, [][]identity.IdentifierValue{{a}, {g}}, identity.TypeGreenboneID, 0, []int{1}, true},
		{"custom", []identity.IdentifierType{identity.TypeAgentID, identity.TypeGreenboneID}, []identity.IdentifierValue{g, a}, [][]identity.IdentifierValue{{g}, {a}}, identity.TypeAgentID, 0, []int{1}, true},
		{"unmatched higher", []identity.IdentifierType{identity.TypeGreenboneID, identity.TypeAgentID}, []identity.IdentifierValue{g, a}, [][]identity.IdentifierValue{{a}}, identity.TypeAgentID, 1, []int{0}, true},
		{"disabled", nil, []identity.IdentifierValue{g, ip}, [][]identity.IdentifierValue{{g, ip}}, "", -1, nil, false},
		{"reclassified IP", []identity.IdentifierType{identity.TypeIP}, []identity.IdentifierValue{g, ip}, [][]identity.IdentifierValue{{ip}}, identity.TypeIP, 0, []int{0}, true},
		{"no match still incoming strong", []identity.IdentifierType{identity.TypeGreenboneID}, []identity.IdentifierValue{g, ip}, [][]identity.IdentifierValue{{ip}}, "", -1, nil, true},
		{"no candidates", []identity.IdentifierType{identity.TypeAgentID}, []identity.IdentifierValue{a}, nil, "", -1, nil, true},
		{"no incoming", []identity.IdentifierType{identity.TypeAgentID}, nil, [][]identity.IdentifierValue{{a}}, "", -1, nil, false},
		{"all same priority matches", []identity.IdentifierType{identity.TypeGreenboneID, identity.TypeAgentID}, []identity.IdentifierValue{g, a}, [][]identity.IdentifierValue{{g}, {g, a}, {a}}, identity.TypeGreenboneID, 0, []int{0, 1}, true},
		{"semantic equality", []identity.IdentifierType{identity.TypeBIOSUUID}, []identity.IdentifierValue{bios1}, [][]identity.IdentifierValue{{bios2}}, identity.TypeBIOSUUID, 0, []int{0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := identity.MatchPolicy{StrongOrder: tt.order, FuzzyBoundaryMode: identity.FuzzyBoundaryStrict}
			got, err := identity.EvaluateStrongPriority(p, tt.incoming, tt.candidates)
			if err != nil || got.Type != tt.typ || got.Priority != tt.priority || !reflect.DeepEqual(got.CandidateIndices, tt.indices) || got.HasIncomingStrong != tt.strong {
				t.Fatalf("result = %+v, %v", got, err)
			}
			if len(got.CandidateIndices) > 0 {
				got.CandidateIndices[0] = 100
				again, err := identity.EvaluateStrongPriority(p, tt.incoming, tt.candidates)
				if err != nil || !reflect.DeepEqual(again.CandidateIndices, tt.indices) {
					t.Fatal("result retained")
				}
			}
		})
	}
	// Multiple values are reportable correspondence, never a selected survivor.
	result, err := identity.EvaluateStrongPriority(identity.GreenboneMatchPolicy(), []identity.IdentifierValue{g, {Type: identity.TypeGreenboneID, Value: "other"}}, [][]identity.IdentifierValue{{g}, {{Type: identity.TypeGreenboneID, Value: "other"}}})
	if err != nil || !reflect.DeepEqual(result.CandidateIndices, []int{0, 1}) {
		t.Fatalf("correspondence = %+v %v", result, err)
	}
	// Policy errors precede matching; malformed evidence has no partial result.
	if _, err := identity.EvaluateStrongPriority(identity.MatchPolicy{}, nil, nil); !errors.Is(err, identity.ErrInvalidMatchPolicy) {
		t.Fatal(err)
	}
	if result, err := identity.EvaluateStrongPriority(identity.GreenboneMatchPolicy(), []identity.IdentifierValue{{Type: identity.TypeGreenboneID, Value: ""}}, nil); err == nil || result.HasIncomingStrong {
		t.Fatal("invalid evidence returned correspondence")
	}
}

func TestRankStrongCandidates(t *testing.T) {
	stamp := func(t time.Time) *time.Time { return &t }
	zero := time.Time{}
	earlier := time.Unix(-1, 0)
	instant := time.Date(2026, 10, 14, 12, 0, 0, 2, time.UTC)
	offset := instant.In(time.FixedZone("offset", 7200))
	monotonic := time.Now()
	wallOnly := monotonic.UTC()
	tests := []struct {
		name       string
		candidates []identity.StrongRankingCandidate
		want       []int
		err        error
	}{
		{"empty", nil, nil, nil},
		{"newest", []identity.StrongRankingCandidate{{AssetKey: "A", LastSeen: stamp(instant.Add(-time.Second))}, {AssetKey: "B", LastSeen: &instant}}, []int{1, 0}, nil},
		{"nanoseconds", []identity.StrongRankingCandidate{{AssetKey: "A", LastSeen: stamp(instant.Add(-time.Nanosecond))}, {AssetKey: "B", LastSeen: &instant}}, []int{1, 0}, nil},
		{"equal offsets", []identity.StrongRankingCandidate{{AssetKey: "B", LastSeen: &instant}, {AssetKey: "A", LastSeen: &offset}}, []int{1, 0}, nil},
		{"equal wall time ignores monotonic", []identity.StrongRankingCandidate{{AssetKey: "B", LastSeen: &monotonic}, {AssetKey: "A", LastSeen: &wallOnly}}, []int{1, 0}, nil},
		{"pre epoch before missing", []identity.StrongRankingCandidate{{AssetKey: "A"}, {AssetKey: "B", LastSeen: &earlier}}, []int{1, 0}, nil},
		{"zero before missing", []identity.StrongRankingCandidate{{AssetKey: "A"}, {AssetKey: "B", LastSeen: &zero}}, []int{1, 0}, nil},
		{"all missing lexical", []identity.StrongRankingCandidate{{AssetKey: "asset-2"}, {AssetKey: "asset-10"}}, []int{1, 0}, nil},
		{"equal timestamps exact bytes", []identity.StrongRankingCandidate{{AssetKey: "a", LastSeen: &instant}, {AssetKey: "Z", LastSeen: &instant}}, []int{1, 0}, nil},
		{"large range no UnixNano overflow", []identity.StrongRankingCandidate{{AssetKey: "A", LastSeen: &zero}, {AssetKey: "B", LastSeen: stamp(time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC))}}, []int{1, 0}, nil},
		{"duplicate key deferred", []identity.StrongRankingCandidate{{AssetKey: "A"}, {AssetKey: "A", LastSeen: &instant}}, nil, identity.ErrUnresolvedMatchingRule},
		{"unkeyed deferred", []identity.StrongRankingCandidate{{}}, nil, identity.ErrUnresolvedMatchingRule},
		{"invalid time", []identity.StrongRankingCandidate{{AssetKey: "A", LastSeen: stamp(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))}}, nil, identity.ErrInvalidObservationTime},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := make([]identity.StrongRankingCandidate, len(tt.candidates))
			copy(before, tt.candidates)
			got, err := identity.RankStrongCandidates(tt.candidates)
			if !errors.Is(err, tt.err) || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("order = %v, error %v", got, err)
			}
			for i, c := range tt.candidates {
				if c != before[i] {
					t.Fatal("ranking mutated input")
				}
			}
			if err == nil && len(got) > 1 {
				reverse := append([]identity.StrongRankingCandidate(nil), tt.candidates...)
				for i, j := 0, len(reverse)-1; i < j; i, j = i+1, j-1 {
					reverse[i], reverse[j] = reverse[j], reverse[i]
				}
				order, err := identity.RankStrongCandidates(reverse)
				if err != nil || reverse[order[0]].AssetKey != tt.candidates[got[0]].AssetKey {
					t.Fatal("permutation changed selected key")
				}
			}
		})
	}
}

func TestMatchingFoundationsConcurrentImmutableInputs(t *testing.T) {
	p := identity.GreenboneMatchPolicy()
	value := identity.IdentifierValue{Type: identity.TypeGreenboneID, Value: "G", Scope: identity.Scope{"issuer": "a"}}
	incoming := []identity.IdentifierValue{value}
	candidates := [][]identity.IdentifierValue{{value}}
	when := time.Now()
	ranking := []identity.StrongRankingCandidate{{AssetKey: "A", LastSeen: &when}, {AssetKey: "B"}}
	before := value.Clone()
	timeBefore := when
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 20 {
				if _, err := identity.EvaluateStrongPriority(p, incoming, candidates); err != nil {
					t.Error(err)
				}
				if _, err := identity.MatchingIdentifiers(incoming, candidates[0]); err != nil {
					t.Error(err)
				}
				if _, err := identity.RankStrongCandidates(ranking); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if !reflect.DeepEqual(value, before) || when != timeBefore || !reflect.DeepEqual(p, identity.GreenboneMatchPolicy()) {
		t.Fatal("shared input mutated")
	}
}
