// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// These matrices exercise Decide, including normalization and merge planning.
// Expected containment uses fixture bit masks, never the matching implementation.
// Bits 0..3 stand for IP, hostname, MAC and FQDN respectively.
func countingWeakValues(mask int, different bool) []IdentifierValue {
	values := []IdentifierValue{
		fuzzyValue(TypeIP, "192.0.2.1"),
		fuzzyValue(TypeHostname, "host-x"),
		fuzzyValue(TypeMAC, "02:00:00:00:00:01"),
		fuzzyValue(TypeFQDN, "host-x.example.com"),
	}
	if different {
		values = []IdentifierValue{
			fuzzyValue(TypeIP, "192.0.2.2"),
			fuzzyValue(TypeHostname, "host-y"),
			fuzzyValue(TypeMAC, "02:00:00:00:00:02"),
			fuzzyValue(TypeFQDN, "host-y.example.com"),
		}
	}
	var result []IdentifierValue
	for bit, value := range values {
		if mask&(1<<bit) != 0 {
			result = append(result, value)
		}
	}
	return result
}

type countingStrongFixture struct {
	name         string
	value, other IdentifierValue
}

func countingStrongFixtures() []countingStrongFixture {
	// SSH wire data: algorithm string followed by a 32-byte Ed25519 public key.
	sshPrefix := "\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
	sshKey := func(fill string) string {
		return "ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte(sshPrefix+strings.Repeat(fill, 32)))
	}
	return []countingStrongFixture{
		{"cloud", fuzzyValue(TypeCloudIdentifier, "provider/instance-1"), fuzzyValue(TypeCloudIdentifier, "provider/instance-2")},
		{"greenbone", fuzzyValue(TypeGreenboneID, "G1"), fuzzyValue(TypeGreenboneID, "G2")},
		{"linux_machine", IdentifierValue{Type: TypeMachineID, Value: strings.Repeat("a", 32), Scope: Scope{"kind": "linux_machine_id"}}, IdentifierValue{Type: TypeMachineID, Value: strings.Repeat("b", 32), Scope: Scope{"kind": "linux_machine_id"}}},
		{"windows_machine", IdentifierValue{Type: TypeMachineID, Value: "00112233-4455-6677-8899-aabbccddeeff", Scope: Scope{"kind": "windows_machine_guid"}}, IdentifierValue{Type: TypeMachineID, Value: "11112233-4455-6677-8899-aabbccddeeff", Scope: Scope{"kind": "windows_machine_guid"}}},
		{"bios", fuzzyValue(TypeBIOSUUID, "00112233-4455-6677-8899-aabbccddeeff"), fuzzyValue(TypeBIOSUUID, "11112233-4455-6677-8899-aabbccddeeff")},
		{"agent", fuzzyValue(TypeAgentID, "A1"), fuzzyValue(TypeAgentID, "A2")},
		{"ssh", fuzzyValue(TypeSSHHostKey, sshKey("a")), fuzzyValue(TypeSSHHostKey, sshKey("b"))},
		{"tls", fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("a", 64)), fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("b", 64))},
	}
}

func TestCountingWeakMatrix(t *testing.T) {
	var cases []countingCase
	for incomingMask := 0; incomingMask < 16; incomingMask++ {
		for state := 0; state < 81; state++ {
			matching, conflicting := 0, 0
			remaining := state
			for bit := 0; bit < 4; bit++ {
				switch remaining % 3 {
				case 1:
					matching |= 1 << bit
				case 2:
					conflicting |= 1 << bit
				}
				remaining /= 3
			}
			stored := append(countingWeakValues(matching, false), countingWeakValues(conflicting, true)...)
			tt := countingCase{
				name:     fmt.Sprintf("incoming_%04b/equal_%04b_different_%04b", incomingMask, matching, conflicting),
				incoming: countingWeakValues(incomingMask, false), candidates: []Candidate{fuzzyRow("K", 10, stored...)},
				action: ActionCreate, stage: StageFuzzy,
			}
			if incomingMask != 0 {
				switch {
				case incomingMask&matching == incomingMask:
					tt.action, tt.selected = ActionReuse, "K"
				case conflicting == 0 && matching&incomingMask == matching:
					// Main also treats an empty source as a contained merge source.
					tt.merges = []int{0}
				}
			}
			cases = append(cases, tt)
		}
	}
	runCountingCases(t, GreenboneMatchPolicy(), cases)
}

func TestCountingStrongWeakMatrix(t *testing.T) {
	// Every strong fixture x four strong relationships x all 16x16 weak
	// subsets. Matching strong evidence wins even when weak values are missing.
	for _, strong := range countingStrongFixtures() {
		t.Run(strong.name, func(t *testing.T) {
			for _, relation := range []string{"same", "different", "incoming_only", "stored_only"} {
				t.Run(relation, func(t *testing.T) {
					var cases []countingCase
					for incomingMask := 0; incomingMask < 16; incomingMask++ {
						for storedMask := 0; storedMask < 16; storedMask++ {
							incoming := countingWeakValues(incomingMask, false)
							stored := countingWeakValues(storedMask, false)
							if relation != "stored_only" {
								incoming = append(incoming, strong.value)
							}
							if relation == "different" {
								stored = append(stored, strong.other)
							} else if relation != "incoming_only" {
								stored = append(stored, strong.value)
							}
							tt := countingCase{
								name:     fmt.Sprintf("incoming_%04b/stored_%04b", incomingMask, storedMask),
								incoming: incoming, candidates: []Candidate{fuzzyRow("K", 10, stored...)}, action: ActionCreate, stage: StageStrong,
							}
							switch relation {
							case "same":
								tt.action, tt.selected = ActionReuse, "K"
							case "incoming_only":
								if incomingMask != 0 && storedMask&incomingMask == storedMask {
									tt.merges = []int{0}
								}
							case "stored_only":
								tt.stage = StageFuzzy
								if incomingMask != 0 {
									if incomingMask&storedMask == incomingMask {
										tt.action, tt.selected = ActionReuse, "K"
									} else if storedMask&incomingMask == storedMask {
										tt.merges = []int{0}
									}
								}
							}
							cases = append(cases, tt)
						}
					}
					runCountingCases(t, GreenboneMatchPolicy(), cases)
				})
			}
		})
	}
}

func TestCountingStrongPriorityMatrix(t *testing.T) {
	// Fixture order states the agreed priority independently of the policy.
	strong := countingStrongFixtures()
	for i, higher := range strong {
		for _, lower := range strong[i+1:] {
			if higher.value.Type == lower.value.Type {
				continue // Linux and Windows machine IDs share one priority.
			}
			t.Run(higher.name+"_before_"+lower.name, func(t *testing.T) {
				cases := []countingCase{
					{"priority beats freshness and incoming links the records", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("lower", 30, lower.value), fuzzyRow("higher", 10, higher.value)}, ActionReuse, StageStrong, "higher", []int{0}},
					{"stronger incoming identity enriches existing key", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("lower", 30, lower.value)}, ActionReuse, StageStrong, "lower", nil},
					{"weaker incoming identity reuses richer record", []IdentifierValue{lower.value}, []Candidate{fuzzyRow("higher", 10, higher.value, lower.value)}, ActionReuse, StageStrong, "higher", nil},
					{"conflicting higher blocks lower match", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("lower", 30, higher.other, lower.value)}, ActionCreate, StageStrong, "", nil},
					{"matching higher overrides lower conflict", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("higher", 10, higher.value, lower.other)}, ActionReuse, StageStrong, "higher", nil},
					{"higher match prevents lower merge", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("higher", 10, higher.value), fuzzyRow("lower", 30, higher.other, lower.value)}, ActionReuse, StageStrong, "higher", nil},
					{"reuse rich key and merge lower record", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("lower", 30, lower.value), fuzzyRow("higher", 10, higher.value, lower.value)}, ActionReuse, StageStrong, "higher", []int{0}},
					{"reuse skips conflicting source and preserves indices", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("conflict", 30, higher.other, lower.value), fuzzyRow("lower", 20, lower.value), fuzzyRow("also-lower", 10, lower.value)}, ActionReuse, StageStrong, "lower", []int{2}},
					{"reversed rows preserve the rich destination and source index", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("higher", 10, higher.value, lower.value), fuzzyRow("lower", 30, lower.value)}, ActionReuse, StageStrong, "higher", []int{1}},
				}
				runCountingCases(t, GreenboneMatchPolicy(), cases)
				custom := GreenboneMatchPolicy()
				custom.StrongOrder = []IdentifierType{lower.value.Type, higher.value.Type}
				tt := cases[0]
				tt.name, tt.selected, tt.merges = "custom priority reverses winner", "lower", []int{1}
				runCountingCases(t, custom, []countingCase{tt})
				runCountingCases(t, custom, []countingCase{
					{"custom higher match overrides default higher conflict", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("lower", 30, higher.other, lower.value)}, ActionReuse, StageStrong, "lower", nil},
					{"custom priority still reuses a lower match", []IdentifierValue{higher.value, lower.value}, []Candidate{fuzzyRow("higher", 10, higher.value)}, ActionReuse, StageStrong, "higher", nil},
				})
			})
		}
	}
}

func TestCountingStrongValueSetMatrix(t *testing.T) {
	for _, strong := range countingStrongFixtures() {
		t.Run(strong.name, func(t *testing.T) {
			sets := [][]IdentifierValue{{strong.value}, {strong.other}, {strong.value, strong.other}, {strong.other, strong.value, strong.value}}
			masks := []int{1, 2, 3, 3}
			var cases []countingCase
			for i, incoming := range sets {
				for j, stored := range sets {
					tt := countingCase{
						name: fmt.Sprintf("incoming_set_%d/stored_set_%d", i, j), incoming: incoming,
						candidates: []Candidate{fuzzyRow("K", 10, stored...)}, action: ActionCreate, stage: StageStrong,
					}
					matches := masks[i]&masks[j] != 0
					if strong.value.Type == TypeTLSPublicKeyHash {
						matches = masks[i] == masks[j] // TLS needs the complete set.
					}
					if matches {
						tt.action, tt.selected = ActionReuse, "K"
					}
					cases = append(cases, tt)
				}
			}
			runCountingCases(t, GreenboneMatchPolicy(), cases)
			// Incoming multi-values report correspondence, not permission to join
			// conflicting stored identities at the same deciding priority.
			tt := countingCase{
				name:       "multiple incoming values do not bridge stored identities",
				incoming:   []IdentifierValue{strong.value, strong.other},
				candidates: []Candidate{fuzzyRow("K0", 30, strong.value), fuzzyRow("K1", 10, strong.other)},
				action:     ActionReuse, stage: StageStrong, selected: "K0",
			}
			if strong.value.Type == TypeTLSPublicKeyHash {
				tt.action, tt.selected = ActionCreate, ""
			}
			runCountingCases(t, GreenboneMatchPolicy(), []countingCase{tt})
		})
	}
}

func TestCountingScopeMatrix(t *testing.T) {
	var values []IdentifierValue
	values = append(values, countingWeakValues(15, false)...)
	for _, strong := range countingStrongFixtures() {
		values = append(values, strong.value)
	}
	for index, value := range values {
		t.Run(fmt.Sprintf("%s_%d", value.Type, index), func(t *testing.T) {
			var cases []countingCase
			for _, incomingScanner := range []string{"scanner-a", "scanner-b"} {
				for _, storedScanner := range []string{"scanner-a", "scanner-b"} {
					incoming, stored := value.Clone(), value.Clone()
					if incoming.Scope == nil {
						incoming.Scope = Scope{}
						stored.Scope = Scope{}
					}
					incoming.Scope["scanner"], stored.Scope["scanner"] = incomingScanner, storedScanner
					tt := countingCase{
						name: incomingScanner + "/" + storedScanner, incoming: []IdentifierValue{incoming},
						candidates: []Candidate{fuzzyRow("K", 10, stored)}, action: ActionCreate, stage: StageStrong,
					}
					if index < 4 {
						tt.stage = StageFuzzy
					}
					if incomingScanner == storedScanner {
						tt.action, tt.selected = ActionReuse, "K"
					}
					cases = append(cases, tt)
				}
			}
			runCountingCases(t, GreenboneMatchPolicy(), cases)
		})
	}
}

func TestCountingCandidateOrderMatrix(t *testing.T) {
	ip, host, mac := countingWeakValues(1, false)[0], countingWeakValues(2, false)[0], countingWeakValues(4, false)[0]
	otherIP := countingWeakValues(1, true)[0]
	permutations := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, strong := range countingStrongFixtures() {
		t.Run(strong.name, func(t *testing.T) {
			cases := []countingCase{
				{"strong reuse merges equal strong evidence", []IdentifierValue{strong.value, ip, host}, []Candidate{fuzzyRow("K0", 30, strong.value, ip, host), fuzzyRow("K1", 20, strong.value, otherIP), fuzzyRow("K2", 10, strong.other, ip)}, ActionReuse, StageStrong, "K0", []int{1}},
				{"strong create absorbs weak subsets", []IdentifierValue{strong.value, ip, host, mac}, []Candidate{fuzzyRow("K0", 30, ip, host), fuzzyRow("K1", 20, ip, mac), fuzzyRow("K2", 10, strong.other, ip)}, ActionCreate, StageStrong, "", []int{0, 1}},
				{"weak create absorbs compatible strong sources", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K0", 30, strong.value, ip, host), fuzzyRow("K1", 20, strong.value, ip, mac), fuzzyRow("K2", 10, mac)}, ActionCreate, StageFuzzy, "", []int{0, 1, 2}},
				{"weak create excludes conflicting strong sources", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K0", 30, strong.value, ip, host), fuzzyRow("K1", 20, strong.other, ip, mac), fuzzyRow("K2", 10, mac)}, ActionCreate, StageFuzzy, "", []int{2}},
				{"weak reuse respects destination strong evidence", []IdentifierValue{ip}, []Candidate{fuzzyRow("K0", 30, strong.value, ip, host), fuzzyRow("K1", 20, strong.other, ip), fuzzyRow("K2", 10, host)}, ActionReuse, StageFuzzy, "K0", []int{2}},
				{"reuse merge uses stored destination evidence", []IdentifierValue{strong.value, ip, host}, []Candidate{fuzzyRow("K0", 30, strong.value, ip), fuzzyRow("K1", 20, host), fuzzyRow("K2", 10, ip)}, ActionReuse, StageStrong, "K0", []int{2}},
			}
			for _, base := range cases {
				for _, order := range permutations {
					tt := base
					tt.name = fmt.Sprintf("%s/order_%d%d%d", base.name, order[0], order[1], order[2])
					tt.candidates, tt.merges = nil, nil
					for newIndex, oldIndex := range order {
						tt.candidates = append(tt.candidates, base.candidates[oldIndex])
						if slices.Contains(base.merges, oldIndex) {
							tt.merges = append(tt.merges, newIndex)
						}
					}
					runCountingCases(t, GreenboneMatchPolicy(), []countingCase{tt})
				}
			}
		})
	}
}

func TestCountingProgressiveStrongMatrix(t *testing.T) {
	ip, host, mac := countingWeakValues(1, false)[0], countingWeakValues(2, false)[0], countingWeakValues(4, false)[0]
	otherIP := countingWeakValues(1, true)[0]
	for _, strong := range countingStrongFixtures() {
		t.Run(strong.name, func(t *testing.T) {
			scans := []struct {
				incoming []IdentifierValue
				action   DecisionAction
				stage    MatchingStage
				selected string
				merges   []int
				count    int
			}{
				{[]IdentifierValue{ip}, ActionCreate, StageFuzzy, "", nil, 1},
				{[]IdentifierValue{ip, host}, ActionCreate, StageFuzzy, "", []int{0}, 1},
				{[]IdentifierValue{strong.value, ip, host, mac}, ActionCreate, StageStrong, "", []int{0}, 1},
				{[]IdentifierValue{strong.value, otherIP}, ActionReuse, StageStrong, "K2", nil, 1},
				{[]IdentifierValue{ip}, ActionReuse, StageFuzzy, "K2", nil, 1},
				{[]IdentifierValue{strong.other, ip}, ActionCreate, StageStrong, "", nil, 2},
				{[]IdentifierValue{ip}, ActionReuse, StageFuzzy, "K5", nil, 2},
				{[]IdentifierValue{strong.value, ip}, ActionReuse, StageStrong, "K2", nil, 2},
			}
			var candidates []Candidate
			for step, scan := range scans {
				t.Run(fmt.Sprintf("scan_%d", step), func(t *testing.T) {
					decision := decideCountingCase(t, GreenboneMatchPolicy(), countingCase{
						incoming: scan.incoming, candidates: candidates, action: scan.action,
						stage: scan.stage, selected: scan.selected, merges: scan.merges,
					})
					candidates = applyCountingDecision(scan.incoming, candidates, decision, step)
					if len(candidates) != scan.count {
						t.Fatalf("got %d assets, want %d", len(candidates), scan.count)
					}
				})
				if t.Failed() {
					break // Later scans depend on the preceding inventory.
				}
			}
		})
	}
}

func TestCountingProgressiveStrongEnrichmentMatrix(t *testing.T) {
	agent := fuzzyValue(TypeAgentID, "agent")
	machine := countingStrongFixtures()[2]
	scans := []struct {
		incoming []IdentifierValue
		action   DecisionAction
		selected string
		merges   []int
		count    int
	}{
		{[]IdentifierValue{agent}, ActionCreate, "", nil, 1},
		{[]IdentifierValue{machine.value, agent}, ActionReuse, "K0", nil, 1},
		{[]IdentifierValue{agent}, ActionReuse, "K0", nil, 1},
		{[]IdentifierValue{machine.other, agent}, ActionCreate, "", nil, 2},
		{[]IdentifierValue{machine.value, agent}, ActionReuse, "K0", nil, 2},
	}
	var candidates []Candidate
	for step, scan := range scans {
		t.Run(fmt.Sprintf("scan_%d", step), func(t *testing.T) {
			decision := decideCountingCase(t, GreenboneMatchPolicy(), countingCase{
				incoming: scan.incoming, candidates: candidates, action: scan.action,
				stage: StageStrong, selected: scan.selected, merges: scan.merges,
			})
			candidates = applyCountingDecision(scan.incoming, candidates, decision, step)
			if len(candidates) != scan.count {
				t.Fatalf("got %d assets, want %d", len(candidates), scan.count)
			}
		})
		if t.Failed() {
			break
		}
	}
}

// Model the caller applying the plan, retaining evidence and untouched assets.
func applyCountingDecision(incoming []IdentifierValue, candidates []Candidate, decision Decision, step int) []Candidate {
	key := decision.SelectedKey
	values := slices.Clone(incoming)
	if decision.NeedsNewKey {
		key = fmt.Sprintf("K%d", step)
	}
	var remaining []Candidate
	for index, candidate := range candidates {
		if candidate.AssetKey == decision.SelectedKey || slices.Contains(decision.MergeIndices, index) {
			values = append(values, candidate.Identifiers...)
		} else {
			remaining = append(remaining, candidate)
		}
	}
	return append(remaining, fuzzyRow(key, int64(step+1), values...))
}
