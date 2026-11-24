// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"reflect"
	"slices"
	"testing"
)

func TestSnapshotDecisions(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	otherIP := fuzzyValue(TypeIP, "192.0.2.2")
	machine := fuzzyValue(TypeMachineID, "0123456789abcdef0123456789abcdef")
	otherMachine := fuzzyValue(TypeMachineID, "fedcba9876543210fedcba9876543210")
	agent := fuzzyValue(TypeAgentID, "agent-a")
	bios := fuzzyValue(TypeBIOSUUID, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	fqdn := fuzzyValue(TypeFQDN, "host.example.org")
	host := fuzzyValue(TypeHostname, "host")
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	otherMAC := fuzzyValue(TypeMAC, "02:00:00:00:00:02")
	tests := []struct {
		name     string
		incoming []IdentifierValue
		rows     []Candidate
		stage    MatchingStage
		key      string
		merges   []string
	}{
		{"IP reassignment", []IdentifierValue{ip}, []Candidate{fuzzyRow("A", 1, ip, mac), fuzzyRow("B", 14, ip, otherMAC), fuzzyRow("A", 15, otherIP, mac)}, StageFuzzy, "B", nil},
		{"machine reassignment excludes changed asset", []IdentifierValue{machine}, []Candidate{fuzzyRow("X", 1, machine), fuzzyRow("Y", 14, machine), fuzzyRow("X", 15, otherMachine)}, StageStrong, "Y", nil},
		{"unrelated newer snapshot preserves machine evidence", []IdentifierValue{machine}, []Candidate{fuzzyRow("X", 1, machine), fuzzyRow("Y", 14, machine), fuzzyRow("X", 15, otherIP)}, StageStrong, "Y", []string{"X"}},
		{"same key continuity is unique", []IdentifierValue{agent}, []Candidate{fuzzyRow("K", 1, agent), fuzzyRow("K", 2, agent, otherIP)}, StageContinuity, "K", nil},
		{"same key fuzzy", []IdentifierValue{ip}, []Candidate{fuzzyRow("K", 1, ip), fuzzyRow("K", 2, ip, host)}, StageFuzzy, "K", nil},
		{"old agent cannot hide current conflict", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("K", 1, agent), fuzzyRow("K", 2, otherMachine, agent)}, StageFuzzy, "", nil},
		{"old IP cannot hide current conflict", []IdentifierValue{machine, ip}, []Candidate{fuzzyRow("K", 1, ip), fuzzyRow("K", 2, otherMachine)}, StageFuzzy, "", nil},
		{"equal conflicting evidence", []IdentifierValue{machine}, []Candidate{fuzzyRow("K", 2, machine), fuzzyRow("K", 2, otherMachine)}, StageFuzzy, "", nil},
		{"missing conflicting evidence", []IdentifierValue{machine}, []Candidate{{AssetKey: "K", Identifiers: []IdentifierValue{otherMachine}}, fuzzyRow("K", 2, machine)}, StageFuzzy, "", nil},
		{"new matching evidence supersedes old conflict", []IdentifierValue{machine}, []Candidate{fuzzyRow("K", 1, otherMachine), fuzzyRow("K", 2, machine)}, StageStrong, "K", nil},
		{"new unrelated observation keeps old conflict", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("K", 1, otherMachine), fuzzyRow("K", 2, agent)}, StageFuzzy, "", nil},
		{"per type evidence preserves higher priority", []IdentifierValue{machine, bios}, []Candidate{fuzzyRow("K", 1, otherMachine), fuzzyRow("K", 2, bios)}, StageFuzzy, "", nil},
		{"priority precedes freshness", []IdentifierValue{machine, bios}, []Candidate{fuzzyRow("A", 1, machine), fuzzyRow("B", 20, bios)}, StageStrong, "A", []string{"B"}},
		{"source old agent cannot bypass machine conflict", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("D", 3, machine), fuzzyRow("K", 1, agent), fuzzyRow("K", 2, otherMachine, agent)}, StageStrong, "D", nil},
		{"incoming link merges one source key", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("D", 3, machine), fuzzyRow("D", 2, machine), fuzzyRow("K", 1, agent), fuzzyRow("K", 2, agent)}, StageStrong, "D", []string{"K"}},
		{"FQDN permits changed IP", []IdentifierValue{otherIP, fqdn, mac}, []Candidate{fuzzyRow("K", 1, ip, fqdn, otherMAC)}, StageFuzzy, "K", nil},
		{"hostname and MAC do not permit changed IP", []IdentifierValue{otherIP, host, mac}, []Candidate{fuzzyRow("K", 1, ip, host, mac)}, StageFuzzy, "", nil},
		{"MAC difference does not veto IP", []IdentifierValue{ip, mac}, []Candidate{fuzzyRow("K", 1, ip, otherMAC)}, StageFuzzy, "K", nil},
		{"MAC alone is insufficient", []IdentifierValue{mac}, []Candidate{fuzzyRow("K", 1, mac)}, StageFuzzy, "", nil},
		{"repeated continuity keys use qualifying fuzzy snapshot", []IdentifierValue{agent, ip}, []Candidate{fuzzyRow("A", 1, agent, ip), fuzzyRow("A", 20, agent, otherIP), fuzzyRow("B", 14, agent, ip)}, StageFuzzy, "B", nil},
		{"several continuity keys without weak evidence still create", []IdentifierValue{agent}, []Candidate{fuzzyRow("A", 1, agent), fuzzyRow("A", 20, agent), fuzzyRow("B", 14, agent)}, StageFuzzy, "", nil},
		{"source current higher type must be linked", []IdentifierValue{machine, agent}, []Candidate{fuzzyRow("D", 3, machine), fuzzyRow("K", 1, agent), fuzzyRow("K", 2, fuzzyValue(TypeCloudIdentifier, "cloud/other"))}, StageStrong, "D", nil},
		{"destination evidence protects other snapshots", []IdentifierValue{bios}, []Candidate{fuzzyRow("D", 3, bios), fuzzyRow("D", 4, machine), fuzzyRow("K", 1, bios), fuzzyRow("K", 2, otherMachine)}, StageStrong, "D", nil},
		{"equal selected snapshot times have stable merge results", []IdentifierValue{machine}, []Candidate{fuzzyRow("D", 3, machine, ip), fuzzyRow("D", 3, machine, host), fuzzyRow("H", 1, host), fuzzyRow("I", 2, ip)}, StageStrong, "D", []string{"H"}},
		{"partial snapshots do not invent a combined match", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K", 1, ip, fuzzyValue(TypeHostname, "other")), fuzzyRow("K", 2, otherIP, host)}, StageFuzzy, "", nil},
		{"newer lower score snapshot wins", []IdentifierValue{ip, fqdn, mac}, []Candidate{fuzzyRow("A", 1, ip, fqdn, mac), fuzzyRow("B", 14, ip)}, StageFuzzy, "B", nil},
		{"multiple merge keys remain unique", []IdentifierValue{machine, agent, ip}, []Candidate{fuzzyRow("D", 3, machine, ip), fuzzyRow("K", 1, agent), fuzzyRow("K", 2, agent), fuzzyRow("L", 4, ip)}, StageStrong, "D", []string{"K", "L"}},
		{"fuzzy timestamps equal", []IdentifierValue{ip}, []Candidate{fuzzyRow("B", 1, ip), fuzzyRow("A", 1, ip)}, StageFuzzy, "A", nil},
		{"fuzzy timestamps missing", []IdentifierValue{ip}, []Candidate{{AssetKey: "B", Identifiers: []IdentifierValue{ip}}, {AssetKey: "A", Identifiers: []IdentifierValue{ip}}}, StageFuzzy, "A", nil},
		{"known before missing", []IdentifierValue{ip}, []Candidate{{AssetKey: "A", Identifiers: []IdentifierValue{ip}}, fuzzyRow("B", 1, ip)}, StageFuzzy, "B", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var visit func(int)
			rows := slices.Clone(tt.rows)
			visit = func(position int) {
				if position < len(rows) {
					for i := position; i < len(rows); i++ {
						rows[position], rows[i] = rows[i], rows[position]
						visit(position + 1)
						rows[position], rows[i] = rows[i], rows[position]
					}
					return
				}
				got, err := Decide(Observation{Identifiers: tt.incoming}, rows, GreenboneMatchPolicy())
				if err != nil {
					t.Fatalf("%v: %v", rows, err)
				}
				action := ActionReuse
				if tt.key == "" {
					action = ActionCreate
				}
				if got.Action != action || got.Stage != tt.stage || got.SelectedKey != tt.key || got.NeedsNewKey != (tt.key == "") {
					t.Fatalf("rows=%+v decision=%+v", rows, got)
				}
				if tt.key != "" && (got.SelectedIndex == nil || rows[*got.SelectedIndex].AssetKey != tt.key) {
					t.Fatalf("selected index: %+v", got)
				}
				if tt.name == "incoming link merges one source key" {
					if rows[*got.SelectedIndex].LastSeen.Unix() != 3 || len(got.MergeIndices) != 1 || rows[got.MergeIndices[0]].LastSeen.Unix() != 2 {
						t.Fatalf("wrong representative snapshot: %+v", got)
					}
				}
				var keys []string
				for _, i := range got.MergeIndices {
					if rows[i].AssetKey == got.SelectedKey {
						t.Fatalf("self merge: %+v", got)
					}
					keys = append(keys, rows[i].AssetKey)
				}
				slices.Sort(keys)
				if !reflect.DeepEqual(keys, tt.merges) {
					t.Fatalf("rows=%+v decision=%+v merge keys=%v want=%v", rows, got, keys, tt.merges)
				}
			}
			visit(0)
		})
	}
}

func TestSelectedIndexIdentifiesNewestQualifyingSnapshot(t *testing.T) {
	for _, value := range []IdentifierValue{
		fuzzyValue(TypeIP, "192.0.2.1"),
		fuzzyValue(TypeAgentID, "agent-a"),
		fuzzyValue(TypeMachineID, "0123456789abcdef0123456789abcdef"),
	} {
		rows := []Candidate{fuzzyRow("K", 1, value), fuzzyRow("K", 2, value, fuzzyValue(TypeIP, "192.0.2.2"))}
		for range 2 {
			got, err := Decide(Observation{Identifiers: []IdentifierValue{value}}, rows, GreenboneMatchPolicy())
			if err != nil || got.SelectedIndex == nil || rows[*got.SelectedIndex].LastSeen.Unix() != 2 || len(got.MergeIndices) != 0 {
				t.Fatalf("type=%s decision=%+v error=%v", value.Type, got, err)
			}
			slices.Reverse(rows)
		}
	}
}
