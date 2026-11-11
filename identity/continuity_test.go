// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"slices"
	"testing"
)

func TestContinuityDecisions(t *testing.T) {
	f := countingStrongFixtures()
	cloud, otherCloud := f[0].value, f[0].other
	machine, otherMachine := f[2].value, f[2].other
	agent, otherAgent := f[5].value, f[5].other
	ssh, otherSSH := f[6].value, f[6].other
	a, b := f[7].value, f[7].other
	c := fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	ip := fuzzyValue(TypeIP, "192.0.2.10")
	nextIP := fuzzyValue(TypeIP, "192.0.2.20")
	mac := fuzzyValue(TypeMAC, "02:ab:cd:ef:01:23")
	otherMAC := fuzzyValue(TypeMAC, "02:ab:cd:ef:01:24")
	fqdn := fuzzyValue(TypeFQDN, "server.example.com")
	cases := []countingCase{
		{"agent survives ip change", []IdentifierValue{agent, nextIP}, []Candidate{fuzzyRow("K0", 1, agent, ip)}, ActionReuse, StageContinuity, "K0", nil},
		{"ssh survives ip change", []IdentifierValue{ssh, nextIP}, []Candidate{fuzzyRow("K0", 1, ssh, ip)}, ActionReuse, StageContinuity, "K0", nil},
		{"retained ssh overrides changed tls", []IdentifierValue{ssh, b}, []Candidate{fuzzyRow("K0", 1, ssh, a)}, ActionReuse, StageContinuity, "K0", nil},
		{"retained tls overrides changed ssh", []IdentifierValue{otherSSH, a}, []Candidate{fuzzyRow("K0", 1, ssh, a)}, ActionReuse, StageContinuity, "K0", nil},
		{"retained tls overrides changed agent", []IdentifierValue{otherAgent, a}, []Candidate{fuzzyRow("K0", 1, agent, a)}, ActionReuse, StageContinuity, "K0", nil},
		{"all service keys rotate with fuzzy fallback", []IdentifierValue{otherSSH, b, nextIP, mac, fqdn}, []Candidate{fuzzyRow("K0", 1, ssh, a, ip, mac, fqdn)}, ActionReuse, StageFuzzy, "K0", nil},
		{"ssh rotation alone permits fuzzy reuse", []IdentifierValue{otherSSH, nextIP, mac, fqdn}, []Candidate{fuzzyRow("K0", 1, ssh, ip, mac, fqdn)}, ActionReuse, StageFuzzy, "K0", nil},
		{"tls rotation alone permits fuzzy reuse", []IdentifierValue{b, nextIP, mac, fqdn}, []Candidate{fuzzyRow("K0", 1, a, ip, mac, fqdn)}, ActionReuse, StageFuzzy, "K0", nil},
		{"all service keys rotate without evidence", []IdentifierValue{otherSSH, b}, []Candidate{fuzzyRow("K0", 1, ssh, a)}, ActionCreate, StageFuzzy, "", nil},
		{"tls partial rotation", []IdentifierValue{a, c}, []Candidate{fuzzyRow("K0", 1, a, b)}, ActionReuse, StageContinuity, "K0", nil},
		{"tls partial observation", []IdentifierValue{a}, []Candidate{fuzzyRow("K0", 1, a, b)}, ActionReuse, StageContinuity, "K0", nil},
		{"tls newly discovered key", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K0", 1, a)}, ActionReuse, StageContinuity, "K0", nil},
		{"tls ordering and duplicates", []IdentifierValue{b, a, a}, []Candidate{fuzzyRow("K0", 1, a, b, b)}, ActionReuse, StageContinuity, "K0", nil},
		{"tls disjoint sets", []IdentifierValue{c}, []Candidate{fuzzyRow("K0", 1, a, b)}, ActionCreate, StageFuzzy, "", nil},
		{"shared ssh is ambiguous", []IdentifierValue{ssh}, []Candidate{fuzzyRow("K0", 999, ssh), fuzzyRow("K1", 1, ssh)}, ActionCreate, StageFuzzy, "", nil},
		{"shared tls is ambiguous", []IdentifierValue{a}, []Candidate{fuzzyRow("K0", 999, a), fuzzyRow("K1", 1, a)}, ActionCreate, StageFuzzy, "", nil},
		{"shared agent is ambiguous", []IdentifierValue{agent}, []Candidate{fuzzyRow("K0", 999, agent), fuzzyRow("K1", 1, agent)}, ActionCreate, StageFuzzy, "", nil},
		{"tls overlap does not chain identities", []IdentifierValue{a, b}, []Candidate{fuzzyRow("K0", 999, a), fuzzyRow("K1", 2, a, b), fuzzyRow("K2", 1, b)}, ActionCreate, StageFuzzy, "", nil},
		{"strong conflict excludes continuity", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("K0", 1, otherMachine, agent)}, ActionCreate, StageFuzzy, "", nil},
		{"strong conflict excludes fuzzy", []IdentifierValue{machine, ip, mac}, []Candidate{fuzzyRow("K0", 1, otherMachine, ip, mac)}, ActionCreate, StageFuzzy, "", nil},
		{"strong match wins with rotated keys", []IdentifierValue{machine, otherSSH, b}, []Candidate{fuzzyRow("K0", 1, machine, ssh, a)}, ActionReuse, StageStrong, "K0", nil},
		{"strong match beats newer continuity", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("K0", 1, machine), fuzzyRow("K1", 999, agent)}, ActionReuse, StageStrong, "K0", []int{1}},
		{"strong priority beats recency", []IdentifierValue{cloud, machine}, []Candidate{fuzzyRow("K0", 1, cloud), fuzzyRow("K1", 999, machine)}, ActionReuse, StageStrong, "K0", []int{1}},
		{"higher strong conflict cannot be bypassed", []IdentifierValue{cloud, machine, agent}, []Candidate{fuzzyRow("K0", 1, otherCloud, machine, agent)}, ActionCreate, StageFuzzy, "", nil},
		{"multiple continuity matches resolved by fuzzy", []IdentifierValue{ssh, ip, mac}, []Candidate{fuzzyRow("K0", 999, ssh, nextIP, otherMAC), fuzzyRow("K1", 1, ssh, ip, mac)}, ActionReuse, StageFuzzy, "K1", nil},
		{"multiple continuity types have no priority", []IdentifierValue{agent, ssh}, []Candidate{fuzzyRow("K0", 999, agent), fuzzyRow("K1", 1, ssh)}, ActionCreate, StageFuzzy, "", nil},
		{"fuzzy cannot escape continuity candidates", []IdentifierValue{ssh, ip}, []Candidate{fuzzyRow("K0", 999, ssh, nextIP), fuzzyRow("K1", 2, ssh, nextIP), fuzzyRow("K2", 1, ip)}, ActionCreate, StageFuzzy, "", nil},
		{"unique continuity wins despite weak conflict", []IdentifierValue{ssh, nextIP, mac}, []Candidate{fuzzyRow("K0", 1, ssh, ip, otherMAC)}, ActionReuse, StageContinuity, "K0", nil},
		{"missing stored strong identifier permits continuity", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("K0", 1, agent)}, ActionReuse, StageContinuity, "K0", nil},
		{"missing incoming strong identifier permits continuity", []IdentifierValue{agent}, []Candidate{fuzzyRow("K0", 1, machine, agent)}, ActionReuse, StageContinuity, "K0", nil},
		{"missing stored strong identifier permits fuzzy", []IdentifierValue{machine, ip, mac}, []Candidate{fuzzyRow("K0", 1, ip, mac)}, ActionReuse, StageFuzzy, "K0", nil},
		{"excluded candidate preserves original indices", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("K0", 999, otherMachine, agent), fuzzyRow("K1", 1, agent)}, ActionReuse, StageContinuity, "K1", nil},
		{"strong selection links continuity source through incoming evidence", []IdentifierValue{machine, agent, ip}, []Candidate{fuzzyRow("K0", 1, machine, agent, ip), fuzzyRow("K1", 999, agent, ip)}, ActionReuse, StageStrong, "K0", []int{1}},
		{"strong selection still absorbs contained weak records", []IdentifierValue{machine, ip, mac}, []Candidate{fuzzyRow("K0", 1, machine, ip, mac), fuzzyRow("K1", 999, ip, mac)}, ActionReuse, StageStrong, "K0", []int{1}},
		{"strong incoming evidence links a tls-only source", []IdentifierValue{machine, a, b}, []Candidate{fuzzyRow("K0", 1, machine), fuzzyRow("K1", 999, a, b)}, ActionReuse, StageStrong, "K0", []int{1}},
		{"strong matching machines still merge", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("K0", 999, machine, agent), fuzzyRow("K1", 1, machine, otherAgent)}, ActionReuse, StageStrong, "K0", []int{1}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			for range 2 {
				decideCountingCase(t, GreenboneMatchPolicy(), tt)
				slices.Reverse(tt.candidates)
				for j, index := range tt.merges {
					tt.merges[j] = len(tt.candidates) - 1 - index
				}
				slices.Sort(tt.merges)
			}
		})
	}
}

func TestContinuityPolicyValidation(t *testing.T) {
	for _, p := range []MatchPolicy{
		{Continuity: []IdentifierType{TypeAgentID, TypeAgentID}},
		{Continuity: []IdentifierType{"unknown"}},
		{StrongOrder: []IdentifierType{TypeAgentID}, Continuity: []IdentifierType{TypeAgentID}},
		{Continuity: []IdentifierType{TypeAgentID}, Fuzzy: []FuzzyMember{{Type: TypeAgentID, Weight: 1}}},
	} {
		if err := p.Validate(); !errors.Is(err, ErrInvalidMatchPolicy) {
			t.Fatalf("policy=%+v err=%v", p, err)
		}
	}
	for _, membership := range [][]IdentifierType{nil, {}} {
		p := MatchPolicy{Continuity: membership}
		clone := p.Clone()
		if (clone.Continuity == nil) != (membership == nil) {
			t.Fatal("clone changed membership presence")
		}
	}
	p := GreenboneMatchPolicy()
	p.Continuity = nil
	a := fuzzyValue(TypeAgentID, "A")
	decideCountingCase(t, p, countingCase{incoming: []IdentifierValue{a}, candidates: []Candidate{fuzzyRow("K0", 1, a)}, action: ActionCreate, stage: StageFuzzy})
}
