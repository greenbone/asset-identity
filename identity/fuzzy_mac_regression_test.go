// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"fmt"
	"slices"
	"testing"
)

func TestIssue19MACDoesNotIdentifyRoutedHosts(t *testing.T) {
	ip1 := fuzzyValue(TypeIP, "10.1.0.3")
	ip2 := fuzzyValue(TypeIP, "10.1.0.4")
	ip3 := fuzzyValue(TypeIP, "10.1.0.5")
	routerMAC := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	realMAC := fuzzyValue(TypeMAC, "02:00:00:00:00:02")
	host := fuzzyValue(TypeHostname, "srv-a")
	otherHost := fuzzyValue(TypeHostname, "srv-b")
	fqdn := fuzzyValue(TypeFQDN, "srv-a.example.com")
	vrrpMAC := fuzzyValue(TypeMAC, "00:00:5e:00:01:01")
	hsrpMAC := fuzzyValue(TypeMAC, "00:00:0c:07:ac:01")
	cases := []countingCase{
		{"second routed host with missing stored hostname", []IdentifierValue{ip2, routerMAC, otherHost}, []Candidate{fuzzyRow("srv-a", 1, ip1, routerMAC)}, ActionCreate, StageFuzzy, "", nil},
		{"vrrp pair shares virtual mac", []IdentifierValue{fuzzyValue(TypeIP, "10.1.0.2"), vrrpMAC}, []Candidate{fuzzyRow("fw1", 1, fuzzyValue(TypeIP, "10.1.0.1"), vrrpMAC)}, ActionCreate, StageFuzzy, "", nil},
		{"hsrp pair shares virtual mac", []IdentifierValue{ip2, hsrpMAC}, []Candidate{fuzzyRow("fw1", 1, ip1, hsrpMAC)}, ActionCreate, StageFuzzy, "", nil},
		{"same host local then routed scan", []IdentifierValue{ip1, routerMAC, host}, []Candidate{fuzzyRow("srv-a", 1, ip1, realMAC, host)}, ActionReuse, StageFuzzy, "srv-a", nil},
		{"same host routed then local scan", []IdentifierValue{ip1, realMAC, host}, []Candidate{fuzzyRow("srv-a", 1, ip1, routerMAC, host)}, ActionReuse, StageFuzzy, "srv-a", nil},
		{"third routed host", []IdentifierValue{ip3, routerMAC}, []Candidate{fuzzyRow("srv-a", 1, ip1, routerMAC), fuzzyRow("srv-b", 999, ip2, routerMAC)}, ActionCreate, StageFuzzy, "", nil},
		{"ip only reuses one eligible asset", []IdentifierValue{ip1}, []Candidate{fuzzyRow("srv-a", 1, ip1, realMAC, host)}, ActionReuse, StageFuzzy, "srv-a", nil},
		{"changed ip retains fqdn and mac", []IdentifierValue{ip2, realMAC, fqdn}, []Candidate{fuzzyRow("srv-a", 1, ip1, realMAC, fqdn)}, ActionReuse, StageFuzzy, "srv-a", nil},
		{"changed ip and shared short hostname with same mac", []IdentifierValue{ip2, realMAC, host}, []Candidate{fuzzyRow("srv-a", 1, ip1, realMAC, host)}, ActionCreate, StageFuzzy, "", nil},
		{"changed ip and shared short hostname without mac", []IdentifierValue{ip2, host}, []Candidate{fuzzyRow("srv-a", 1, ip1, host)}, ActionCreate, StageFuzzy, "", nil},
		{"changed ip and shared fqdn without mac", []IdentifierValue{ip2, fqdn}, []Candidate{fuzzyRow("srv-a", 1, ip1, fqdn)}, ActionReuse, StageFuzzy, "srv-a", nil},
		{"changed ip and shared fqdn with different mac", []IdentifierValue{ip2, routerMAC, fqdn}, []Candidate{fuzzyRow("srv-a", 1, ip1, realMAC, fqdn)}, ActionReuse, StageFuzzy, "srv-a", nil},
		{"changed ip and fqdn cannot override hostname conflict", []IdentifierValue{ip2, fqdn, otherHost}, []Candidate{fuzzyRow("srv-a", 1, ip1, fqdn, host)}, ActionCreate, StageFuzzy, "", nil},
		{"same ip with different mac and no name", []IdentifierValue{ip1, routerMAC}, []Candidate{fuzzyRow("srv-a", 1, ip1, realMAC)}, ActionReuse, StageFuzzy, "srv-a", nil},
		{"shared mac alone", []IdentifierValue{routerMAC}, []Candidate{fuzzyRow("srv-a", 1, routerMAC)}, ActionCreate, StageFuzzy, "", nil},
		{"shared mac cannot override fqdn conflict", []IdentifierValue{ip1, routerMAC, fqdn}, []Candidate{fuzzyRow("srv-a", 1, ip1, routerMAC, fuzzyValue(TypeFQDN, "srv-b.example.com"))}, ActionCreate, StageFuzzy, "", nil},
		{"multiple ip matches use observation time", []IdentifierValue{ip1}, []Candidate{fuzzyRow("srv-a", 1, ip1, realMAC), fuzzyRow("other", 999, ip1, routerMAC)}, ActionReuse, StageFuzzy, "other", nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			for range 2 {
				decideCountingCase(t, GreenboneMatchPolicy(), tt)
				slices.Reverse(tt.candidates)
			}
		})
	}
}

func TestIssue19RouterMACCandidateCountAndOrder(t *testing.T) {
	routerMAC := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	for _, count := range []int{1, 2, 16} {
		t.Run(fmt.Sprintf("candidates_%d", count), func(t *testing.T) {
			var rows []Candidate
			for i := 0; i < count; i++ {
				rows = append(rows, fuzzyRow(fmt.Sprintf("K%d", i), int64(i), fuzzyValue(TypeIP, fmt.Sprintf("10.1.0.%d", i+1)), routerMAC))
			}
			for _, incoming := range []countingCase{
				{name: "unknown ip is not absorbed", incoming: []IdentifierValue{fuzzyValue(TypeIP, "10.1.0.200"), routerMAC}, candidates: rows, action: ActionCreate, stage: StageFuzzy},
				{name: "exact ip is not obscured by other router mac matches", incoming: []IdentifierValue{fuzzyValue(TypeIP, "10.1.0.1"), routerMAC}, candidates: rows, action: ActionReuse, stage: StageFuzzy, selected: "K0"},
			} {
				t.Run(incoming.name, func(t *testing.T) {
					for range 2 {
						decideCountingCase(t, GreenboneMatchPolicy(), incoming)
						slices.Reverse(incoming.candidates)
					}
				})
			}
		})
	}
}

func TestIssue19ConfiguredFuzzyEvidence(t *testing.T) {
	ip1 := fuzzyValue(TypeIP, "192.0.2.1")
	ip2 := fuzzyValue(TypeIP, "192.0.2.2")
	fqdn := fuzzyValue(TypeFQDN, "host.example.com")
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	for _, members := range [][]FuzzyMember{
		{{Type: TypeMAC, Weight: 1}},
		{{Type: TypeMAC, Weight: 1}, {Type: TypeIP, Weight: .4}},
	} {
		policy := MatchPolicy{Fuzzy: members}
		decideCountingCase(t, policy, countingCase{
			name: "omitted fqdn cannot support changed ip", incoming: []IdentifierValue{ip2, mac, fqdn},
			candidates: []Candidate{fuzzyRow("K0", 1, ip1, mac, fqdn)}, action: ActionCreate, stage: StageFuzzy,
		})
	}
}

func TestIssue19PreservesStrongMatchingAndMergeSafeguards(t *testing.T) {
	machineX := fuzzyValue(TypeMachineID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	machineY := fuzzyValue(TypeMachineID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	agent := fuzzyValue(TypeAgentID, "A")
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	mac1 := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	mac2 := fuzzyValue(TypeMAC, "02:00:00:00:00:02")
	for _, tt := range []countingCase{
		{"strong conflict blocks weak agreement", []IdentifierValue{machineX, ip, mac2}, []Candidate{fuzzyRow("K0", 1, machineY, ip, mac1)}, ActionCreate, StageFuzzy, "", nil},
		{"strong match wins despite changed mac", []IdentifierValue{machineX, ip, mac2}, []Candidate{fuzzyRow("K0", 1, machineX, ip, mac1)}, ActionReuse, StageStrong, "K0", nil},
		{"continuity match wins despite changed mac", []IdentifierValue{agent, ip, mac2}, []Candidate{fuzzyRow("K0", 1, agent, ip, mac1)}, ActionReuse, StageContinuity, "K0", nil},
		{"strong merge still rejects different source mac", []IdentifierValue{machineX, ip, mac1}, []Candidate{fuzzyRow("K0", 1, machineX, ip, mac1), fuzzyRow("K1", 2, ip, mac2)}, ActionReuse, StageStrong, "K0", nil},
		{"strong merge still accepts contained weak record", []IdentifierValue{machineX, ip, mac1}, []Candidate{fuzzyRow("K0", 1, machineX, ip, mac1), fuzzyRow("K1", 2, ip, mac1)}, ActionReuse, StageStrong, "K0", []int{1}},
	} {
		t.Run(tt.name, func(t *testing.T) { decideCountingCase(t, GreenboneMatchPolicy(), tt) })
	}
}
