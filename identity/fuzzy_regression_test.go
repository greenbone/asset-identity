// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"slices"
	"testing"
)

func TestIssue11WeakReuseAndAmbiguity(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.10")
	nextIP := fuzzyValue(TypeIP, "192.0.2.20")
	unknownIP := fuzzyValue(TypeIP, "192.0.2.30")
	mac := fuzzyValue(TypeMAC, "02:ab:cd:ef:01:23")
	otherMAC := fuzzyValue(TypeMAC, "02:ab:cd:ef:01:24")
	fqdn := fuzzyValue(TypeFQDN, "server.example.com")
	otherFQDN := fuzzyValue(TypeFQDN, "other.example.com")
	host := fuzzyValue(TypeHostname, "server")
	otherHost := fuzzyValue(TypeHostname, "other")
	agent := fuzzyValue(TypeAgentID, "A")
	otherAgent := fuzzyValue(TypeAgentID, "B")
	cases := []countingCase{
		{"dhcp retains mac and fqdn", []IdentifierValue{nextIP, mac, fqdn}, []Candidate{fuzzyRow("K0", 1, ip, mac, fqdn)}, ActionReuse, StageFuzzy, "K0", nil},
		{"dhcp retains mac without fqdn", []IdentifierValue{nextIP, mac}, []Candidate{fuzzyRow("K0", 1, ip, mac)}, ActionReuse, StageFuzzy, "K0", nil},
		{"changed ip with only shared fqdn is insufficient", []IdentifierValue{nextIP, fqdn}, []Candidate{fuzzyRow("K0", 1, ip, fqdn)}, ActionCreate, StageFuzzy, "", nil},
		{"same mac does not override different fqdn", []IdentifierValue{nextIP, mac, fqdn}, []Candidate{fuzzyRow("K0", 1, ip, mac, otherFQDN)}, ActionCreate, StageFuzzy, "", nil},
		{"same mac does not override different hostname", []IdentifierValue{nextIP, mac, host}, []Candidate{fuzzyRow("K0", 1, ip, mac, otherHost)}, ActionCreate, StageFuzzy, "", nil},
		{"same ip does not override different mac", []IdentifierValue{ip, mac}, []Candidate{fuzzyRow("K0", 1, ip, otherMAC)}, ActionCreate, StageFuzzy, "", nil},
		{"missing stored names and mac permit reuse", []IdentifierValue{ip, mac, fqdn}, []Candidate{fuzzyRow("K0", 1, ip)}, ActionReuse, StageFuzzy, "K0", nil},
		{"ip only reuses one richer asset", []IdentifierValue{ip}, []Candidate{fuzzyRow("K0", 1, agent, ip, mac, fqdn)}, ActionReuse, StageFuzzy, "K0", nil},
		{"unknown ip creates without merging", []IdentifierValue{unknownIP}, []Candidate{fuzzyRow("K0", 1, ip, mac, fqdn)}, ActionCreate, StageFuzzy, "", nil},
		{"retired ip is not matched through last seen", []IdentifierValue{ip}, []Candidate{fuzzyRow("K0", 999, nextIP, mac, fqdn)}, ActionCreate, StageFuzzy, "", nil},
		{"mac identifies reassigned address", []IdentifierValue{ip, otherMAC}, []Candidate{fuzzyRow("K0", 999, agent, ip, mac), fuzzyRow("K1", 1, otherAgent, ip, otherMAC)}, ActionReuse, StageFuzzy, "K1", nil},
		{"ip only cannot distinguish reassigned address", []IdentifierValue{ip}, []Candidate{fuzzyRow("K0", 999, agent, ip, mac), fuzzyRow("K1", 1, otherAgent, ip, otherMAC)}, ActionCreate, StageFuzzy, "", nil},
		{"same mac on multiple assets remains ambiguous", []IdentifierValue{unknownIP, mac}, []Candidate{fuzzyRow("K0", 999, ip, mac), fuzzyRow("K1", 1, nextIP, mac)}, ActionCreate, StageFuzzy, "", nil},
		{"higher score cannot resolve multiple compatible assets", []IdentifierValue{ip, mac, fqdn}, []Candidate{fuzzyRow("K0", 999, ip, mac, fqdn), fuzzyRow("K1", 1, ip)}, ActionCreate, StageFuzzy, "", nil},
		{"fuzzy reuse does not merge unrelated narrower record", []IdentifierValue{ip}, []Candidate{fuzzyRow("K0", 1, ip, fqdn), fuzzyRow("K1", 999, fqdn)}, ActionReuse, StageFuzzy, "K0", nil},
		{"weak combined interfaces cannot consolidate records", []IdentifierValue{ip, mac, nextIP, otherMAC}, []Candidate{fuzzyRow("K0", 999, ip, mac), fuzzyRow("K1", 1, nextIP, otherMAC)}, ActionCreate, StageFuzzy, "", nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			for range 2 {
				decision := decideCountingCase(t, GreenboneMatchPolicy(), tt)
				after := applyCountingDecision(tt.incoming, tt.candidates, decision, 1000)
				wantCount := len(tt.candidates)
				if tt.action == ActionCreate {
					wantCount++
				}
				if len(after) != wantCount {
					t.Fatalf("asset count=%d want=%d", len(after), wantCount)
				}
				slices.Reverse(tt.candidates)
			}
		})
	}
}

func TestIssue11ProgressiveDHCPPreservesKeyAndCount(t *testing.T) {
	mac := fuzzyValue(TypeMAC, "02:ab:cd:ef:01:23")
	fqdn := fuzzyValue(TypeFQDN, "server.example.com")
	var rows []Candidate
	for step, address := range []string{"192.0.2.10", "192.0.2.20", "192.0.2.30"} {
		incoming := []IdentifierValue{fuzzyValue(TypeIP, address), mac, fqdn}
		expected := countingCase{incoming: incoming, candidates: rows, action: ActionReuse, stage: StageFuzzy, selected: "K0"}
		if step == 0 {
			expected.action, expected.selected = ActionCreate, ""
		}
		decision := decideCountingCase(t, GreenboneMatchPolicy(), expected)
		rows = applyCountingDecision(incoming, rows, decision, step)
		if len(rows) != 1 || rows[0].AssetKey != "K0" {
			t.Fatalf("step=%d inventory=%+v", step, rows)
		}
		rows[0].Identifiers = incoming
	}
}
