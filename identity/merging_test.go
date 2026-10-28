// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"reflect"
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
		{"best weak record is reused, a record sharing one type stays apart", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, ip, host), fuzzyRow("K2", 2, ip, mac)}, ActionReuse, "K2", nil},
		{"reuse merges a weak record sharing the anchor", []IdentifierValue{mac}, []Candidate{fuzzyRow("K1", 2, mac, host), fuzzyRow("K2", 1, mac)}, ActionReuse, "K1", []int{1}},
		{"one shared type is insufficient", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K1", 1, ip, mac)}, ActionCreate, "", nil},
		{"same winning strong identifier", []IdentifierValue{agent}, []Candidate{fuzzyRow("K1", 2, agent, ip), fuzzyRow("K2", 1, agent, host)}, ActionReuse, "K1", []int{1}},
		{"different strong identifier blocked", []IdentifierValue{agent, ip}, []Candidate{fuzzyRow("K1", 2, agent, ip), fuzzyRow("K2", 1, otherAgent, ip)}, ActionReuse, "K1", nil},
		{"weak source joins a strong destination with sufficient evidence", []IdentifierValue{agent, ip}, []Candidate{fuzzyRow("K1", 2, agent, ip, host), fuzzyRow("K2", 1, ip, host)}, ActionReuse, "K1", []int{1}},
		{"weak source sharing one type with a strong destination stays apart", []IdentifierValue{agent, ip}, []Candidate{fuzzyRow("K1", 2, agent, ip), fuzzyRow("K2", 1, ip)}, ActionReuse, "K1", nil},
		{"strong observation reuses a weak record", []IdentifierValue{agent, ip, host}, []Candidate{fuzzyRow("K1", 1, ip, host)}, ActionReuse, "K1", nil},
		{"strong mismatch cannot merge through fuzzy", []IdentifierValue{agent, ip, host}, []Candidate{fuzzyRow("K1", 1, otherAgent, ip, host)}, ActionCreate, "", nil},
		{"equal TLS sets merge", []IdentifierValue{tlsA, tlsB}, []Candidate{fuzzyRow("K1", 2, tlsA, tlsB), fuzzyRow("K2", 1, tlsB, tlsA, tlsA)}, ActionReuse, "K1", []int{1}},
		{"unequal TLS sets cannot merge", []IdentifierValue{tlsA, tlsB, ip}, []Candidate{fuzzyRow("K1", 2, tlsA, tlsB, ip), fuzzyRow("K2", 1, tlsA, ip)}, ActionReuse, "K1", nil},
		{"weak observation reuses the newest of conflicting strong records", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K1", 2, agent, ip, host), fuzzyRow("K2", 1, otherAgent, ip, host)}, ActionReuse, "K1", nil},
		{"shared observation does not bridge distinct strong IDs", []IdentifierValue{agent, otherAgent}, []Candidate{fuzzyRow("K1", 2, agent), fuzzyRow("K2", 1, otherAgent)}, ActionReuse, "K1", nil},
		{"different strong types do not establish identity", []IdentifierValue{agent, ip}, []Candidate{fuzzyRow("K1", 1, fuzzyValue(TypeGreenboneID, "g"), ip)}, ActionCreate, "", nil},
		{"scope prevents a weak match", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K1", 1, IdentifierValue{Type: TypeIP, Value: ip.Value, Scope: Scope{"network": "other"}}, host)}, ActionCreate, "", nil},
		{"weak observation leaves conflicting strong sources separate", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, agent, ip, host), fuzzyRow("K2", 2, otherAgent, ip, mac)}, ActionReuse, "K2", nil},
		{"weak sources with sufficient shared evidence join", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, agent, ip, host), fuzzyRow("K2", 2, otherAgent, ip, mac), fuzzyRow("K3", 3, ip, mac)}, ActionReuse, "K3", []int{1}},
		{"reversing conflicting candidates changes no merge outcome", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K2", 2, otherAgent, ip, mac), fuzzyRow("K1", 1, agent, ip, host)}, ActionReuse, "K2", nil},
		{"weak observation cannot bridge unequal TLS sets", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, tlsA, tlsB, ip, host), fuzzyRow("K2", 2, tlsA, ip, mac)}, ActionReuse, "K2", nil},
		{"weak observation can absorb compatible strong sources", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K1", 1, agent, ip, host), fuzzyRow("K2", 2, agent, ip, mac)}, ActionReuse, "K2", []int{0}},
		{"strong observation reuses the best weak record", []IdentifierValue{agent, ip, host, mac}, []Candidate{fuzzyRow("K1", 1, ip, host), fuzzyRow("K2", 2, ip, mac)}, ActionReuse, "K2", nil},
		{"insufficient weak overlap creates", []IdentifierValue{agent, ip, host}, []Candidate{fuzzyRow("K1", 1, ip, mac)}, ActionCreate, "", nil},
		{"non-transitive strong overlap keeps only the compatible middle source", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K0", 4, ip, host), fuzzyRow("K1", 1, agent, ip, host), fuzzyRow("K2", 2, agent, otherAgent, ip, host), fuzzyRow("K3", 3, otherAgent, ip, host)}, ActionReuse, "K0", []int{2}},
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
