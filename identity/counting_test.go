// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These regressions cover containment and upgrades to stronger identity evidence.

type countingCase struct {
	name       string
	incoming   []IdentifierValue
	candidates []Candidate
	action     DecisionAction
	stage      MatchingStage
	selected   string
	merges     []int
}

func runCountingCases(t *testing.T, policy MatchPolicy, cases []countingCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			decideCountingCase(t, policy, tt)
		})
	}
}

func decideCountingCase(t *testing.T, policy MatchPolicy, tt countingCase) Decision {
	t.Helper()
	got, err := Decide(Observation{Identifiers: tt.incoming}, tt.candidates, policy)
	if err != nil || got.Action != tt.action || got.Stage != tt.stage || got.SelectedKey != tt.selected || !reflect.DeepEqual(got.MergeIndices, tt.merges) {
		t.Fatalf("got decision=%+v error=%v; want action=%s stage=%s key=%q merges=%v; incoming=%+v candidates=%+v", got, err, tt.action, tt.stage, tt.selected, tt.merges, tt.incoming, tt.candidates)
	}
	if got.NeedsNewKey != (tt.action == ActionCreate) || (got.SelectedIndex == nil) != got.NeedsNewKey {
		t.Fatalf("decision=%+v", got)
	}
	if got.SelectedIndex != nil {
		index := *got.SelectedIndex
		if index < 0 || index >= len(tt.candidates) || tt.candidates[index].AssetKey != tt.selected {
			t.Fatalf("selected index %d does not refer to expected key %q", index, tt.selected)
		}
	}
	return got
}

func TestCountingContainment(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	otherIP := fuzzyValue(TypeIP, "192.0.2.2")
	host := fuzzyValue(TypeHostname, "host-x")
	otherHost := fuzzyValue(TypeHostname, "host-y")
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	otherMAC := fuzzyValue(TypeMAC, "02:00:00:00:00:02")
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"exact ip", []IdentifierValue{ip}, []Candidate{fuzzyRow("K0", 1, ip)}, ActionReuse, StageFuzzy, "K0", nil},
		{"add hostname", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K0", 1, ip)}, ActionCreate, StageFuzzy, "", []int{0}},
		{"observation subset", []IdentifierValue{ip}, []Candidate{fuzzyRow("K0", 1, ip, host)}, ActionReuse, StageFuzzy, "K0", nil},
		{"exact ip and hostname", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K0", 1, ip, host)}, ActionReuse, StageFuzzy, "K0", nil},
		{"different hostname", []IdentifierValue{ip, otherHost}, []Candidate{fuzzyRow("K0", 1, ip, host)}, ActionCreate, StageFuzzy, "", nil},
		{"same mac new ip", []IdentifierValue{otherIP, mac}, []Candidate{fuzzyRow("K0", 1, ip, mac)}, ActionCreate, StageFuzzy, "", nil},
		{"add hostname to mac", []IdentifierValue{ip, mac, host}, []Candidate{fuzzyRow("K0", 1, ip, mac)}, ActionCreate, StageFuzzy, "", []int{0}},
		{"different mac", []IdentifierValue{ip, otherMAC}, []Candidate{fuzzyRow("K0", 1, ip, mac)}, ActionCreate, StageFuzzy, "", nil},
		{"same mac changed host", []IdentifierValue{ip, mac, otherHost}, []Candidate{fuzzyRow("K0", 1, ip, mac, host)}, ActionCreate, StageFuzzy, "", nil},
		{"two prior candidates", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K0", 2, ip), fuzzyRow("K1", 1, host)}, ActionCreate, StageFuzzy, "", []int{0, 1}},
		{"richer candidate", []IdentifierValue{ip}, []Candidate{fuzzyRow("K0", 2, ip, host), fuzzyRow("K1", 1, ip)}, ActionReuse, StageFuzzy, "K0", []int{1}},
		{"identical candidates", []IdentifierValue{ip, host}, []Candidate{fuzzyRow("K0", 2, ip, host), fuzzyRow("K1", 1, ip, host)}, ActionReuse, StageFuzzy, "K0", []int{1}},
		{"rich observation consolidates two nics", []IdentifierValue{ip, mac, otherIP, otherMAC}, []Candidate{fuzzyRow("K0", 2, ip, mac), fuzzyRow("K1", 1, otherIP, otherMAC)}, ActionCreate, StageFuzzy, "", []int{0, 1}},
	})
}

func TestCountingStrongRules(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	host := fuzzyValue(TypeHostname, "host")
	otherMAC := fuzzyValue(TypeMAC, "02:00:00:00:00:02")
	g := fuzzyValue(TypeGreenboneID, "g")
	otherG := fuzzyValue(TypeGreenboneID, "other")
	agent := fuzzyValue(TypeAgentID, "a")
	cloud := fuzzyValue(TypeCloudIdentifier, "c")
	tlsA := fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("a", 64))
	tlsB := fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("b", 64))
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"cloud priority beats newer greenbone match", []IdentifierValue{cloud, g}, []Candidate{fuzzyRow("K0", 20, g), fuzzyRow("K1", 10, cloud)}, ActionReuse, StageStrong, "K1", nil},
		{"conflicting higher type blocks a lower match", []IdentifierValue{g, agent}, []Candidate{fuzzyRow("K0", 1, otherG, agent)}, ActionCreate, StageStrong, "", nil},
		{"new agent creates a key and absorbs weak record", []IdentifierValue{agent, ip, mac}, []Candidate{fuzzyRow("K0", 1, ip, mac)}, ActionCreate, StageStrong, "", []int{0}},
		{"conflicting incoming greenbone id is not merged", []IdentifierValue{g, ip, mac}, []Candidate{fuzzyRow("K0", 20, ip, mac), fuzzyRow("K1", 10, otherG, ip, mac)}, ActionCreate, StageStrong, "", []int{0}},
		{"conflicting incoming mac is not merged", []IdentifierValue{ip, host, mac}, []Candidate{fuzzyRow("K0", 20, ip, host), fuzzyRow("K1", 10, ip, host, otherMAC)}, ActionCreate, StageFuzzy, "", []int{0}},
		{"tls mismatch does not fall back to weak evidence", []IdentifierValue{tlsA, tlsB, ip, mac}, []Candidate{fuzzyRow("K0", 1, tlsA, ip, mac)}, ActionCreate, StageStrong, "", nil},
	})
}

func TestCountingStrongUpgradeSafeguards(t *testing.T) {
	agentA := fuzzyValue(TypeAgentID, "A")
	agentB := fuzzyValue(TypeAgentID, "B")
	machineX := IdentifierValue{Type: TypeMachineID, Value: strings.Repeat("a", 32), Scope: Scope{"kind": "linux_machine_id"}}
	machineY := IdentifierValue{Type: TypeMachineID, Value: strings.Repeat("b", 32), Scope: Scope{"kind": "linux_machine_id"}}
	cloud := fuzzyValue(TypeCloudIdentifier, "instance")
	otherScope := machineX.Clone()
	otherScope.Scope["realm"] = "other"
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"machine id upgrades an agent-only key", []IdentifierValue{machineX, agentA}, []Candidate{fuzzyRow("K0", 10, agentA)}, ActionCreate, StageStrong, "", []int{0}},
		{"agent-only scan reuses a machine key", []IdentifierValue{agentA}, []Candidate{fuzzyRow("K0", 10, machineX, agentA)}, ActionReuse, StageStrong, "K0", nil},
		{"different machines stay separate despite matching agent", []IdentifierValue{machineX, agentA}, []Candidate{fuzzyRow("K0", 10, machineY, agentA)}, ActionCreate, StageStrong, "", nil},
		{"same machine overrides different agent", []IdentifierValue{machineX, agentB}, []Candidate{fuzzyRow("K0", 10, machineX, agentA)}, ActionReuse, StageStrong, "K0", nil},
		{"reuse richer asset and absorb agent-only record", []IdentifierValue{machineX, agentA}, []Candidate{fuzzyRow("K0", 30, agentA), fuzzyRow("K1", 10, machineX, agentA)}, ActionReuse, StageStrong, "K1", []int{0}},
		{"create absorbs only the compatible source", []IdentifierValue{machineX, agentA}, []Candidate{fuzzyRow("K0", 30, machineY, agentA), fuzzyRow("K1", 10, agentA)}, ActionCreate, StageStrong, "", []int{1}},
		{"richer stored identity can share a lower type", []IdentifierValue{machineX, agentA}, []Candidate{fuzzyRow("K0", 10, cloud, agentA)}, ActionReuse, StageStrong, "K0", nil},
		{"merge cannot reintroduce an incoming machine conflict", []IdentifierValue{machineX, agentA}, []Candidate{fuzzyRow("K0", 10, cloud, agentA), fuzzyRow("K1", 30, cloud, machineY, agentA)}, ActionReuse, StageStrong, "K0", nil},
		{"different machine scopes cannot fall back to agent", []IdentifierValue{machineX, agentA}, []Candidate{fuzzyRow("K0", 10, otherScope, agentA)}, ActionCreate, StageStrong, "", nil},
		{"shared agent does not prove a missing cloud id", []IdentifierValue{machineX, agentA}, []Candidate{fuzzyRow("K0", 10, machineX, agentA), fuzzyRow("K1", 30, cloud, agentA)}, ActionReuse, StageStrong, "K0", nil},
	})
}

func TestCountingProgressiveDiscovery(t *testing.T) {
	ip := fuzzyValue(TypeIP, "192.0.2.1")
	host := fuzzyValue(TypeHostname, "host")
	mac := fuzzyValue(TypeMAC, "02:00:00:00:00:01")
	agent := fuzzyValue(TypeAgentID, "agent")
	scans := []struct {
		values []IdentifierValue
		action DecisionAction
		merges []int
	}{
		{[]IdentifierValue{ip}, ActionCreate, nil},
		{[]IdentifierValue{ip, host}, ActionCreate, []int{0}},
		{[]IdentifierValue{ip, host, mac}, ActionCreate, []int{0}},
		{[]IdentifierValue{ip}, ActionReuse, nil},
		{[]IdentifierValue{ip}, ActionReuse, nil},
		{[]IdentifierValue{agent, ip, host, mac}, ActionCreate, []int{0}},
		{[]IdentifierValue{ip}, ActionReuse, nil},
	}
	var candidates []Candidate
	for step, scan := range scans {
		decision, err := Decide(Observation{Identifiers: scan.values}, candidates, GreenboneMatchPolicy())
		if err != nil {
			t.Fatal(err)
		}
		if decision.Action != scan.action || !reflect.DeepEqual(decision.MergeIndices, scan.merges) {
			t.Fatalf("scan %d: %+v", step, decision)
		}

		// Apply the decision as a caller would, retaining evidence from every moved record.
		key := decision.SelectedKey
		values := append([]IdentifierValue(nil), scan.values...)
		if decision.NeedsNewKey {
			key = fmt.Sprintf("K%d", step)
		} else {
			values = append(values, candidates[*decision.SelectedIndex].Identifiers...)
		}
		for _, index := range decision.MergeIndices {
			values = append(values, candidates[index].Identifiers...)
		}
		count := len(candidates) - len(decision.MergeIndices)
		if decision.NeedsNewKey {
			count++
		}
		if count != 1 {
			t.Fatalf("scan %d left %d assets", step, count)
		}
		candidates = []Candidate{fuzzyRow(key, int64(step), values...)}
	}
}

func TestCountingTLSEligibility(t *testing.T) {
	ip1 := fuzzyValue(TypeIP, "192.0.2.1")
	fqdn2 := fuzzyValue(TypeFQDN, "other.example.com")
	certificate := testCertificate(t, "web01.example.com", "alt.example.com", "web01")
	wildcard := testCertificate(t, "*.example.com")
	hash, err := NormalizeIdentifier(fuzzyValue(TypeTLSPublicKeyHash, certificate))
	if err != nil {
		t.Fatal(err)
	}
	tls := fuzzyValue(TypeTLSPublicKeyHash, certificate)
	wildcardTLS := fuzzyValue(TypeTLSPublicKeyHash, wildcard)
	fqdn := fuzzyValue(TypeFQDN, "WEB01.example.com.")
	alt := fuzzyValue(TypeFQDN, "alt.example.com")
	host := fuzzyValue(TypeHostname, "WEB01")
	// Test certificate admission independently of weak fallback and merge containment.
	runCountingCases(t, MatchPolicy{StrongOrder: GreenboneMatchPolicy().StrongOrder}, []countingCase{
		{"a certificate issued to the host's fqdn is strong evidence", []IdentifierValue{tls, fqdn}, []Candidate{fuzzyRow("A", 1, hash)}, ActionReuse, StageStrong, "A", nil},
		{"a san naming the host counts", []IdentifierValue{tls, alt}, []Candidate{fuzzyRow("A", 1, hash)}, ActionReuse, StageStrong, "A", nil},
		{"a san equal to the hostname counts", []IdentifierValue{tls, host}, []Candidate{fuzzyRow("A", 1, hash)}, ActionReuse, StageStrong, "A", nil},
		{"a non-ascii name never matches", []IdentifierValue{testTLS(t, "\u212aube.example.com"), fuzzyValue(TypeFQDN, "kube.example.com")}, []Candidate{fuzzyRow("A", 1, hash)}, ActionCreate, StageFuzzy, "", nil},
		{"a certificate without the host's name is not evidence", []IdentifierValue{tls, fqdn2}, []Candidate{fuzzyRow("A", 1, hash)}, ActionCreate, StageFuzzy, "", nil},
		{"an observation without a host name does not use the certificate", []IdentifierValue{tls, ip1}, []Candidate{fuzzyRow("A", 1, hash, ip1)}, ActionCreate, StageFuzzy, "", nil},
		{"a wildcard certificate never names the host", []IdentifierValue{wildcardTLS, fqdn}, []Candidate{fuzzyRow("A", 1, wildcardTLS, fqdn)}, ActionCreate, StageFuzzy, "", nil},
		{"a stored hash stays eligible", []IdentifierValue{hash}, []Candidate{fuzzyRow("A", 1, hash)}, ActionReuse, StageStrong, "A", nil},
		{"the candidate side is checked too", []IdentifierValue{hash}, []Candidate{fuzzyRow("A", 1, tls, fqdn2)}, ActionCreate, StageStrong, "", nil},
	})
	broken := "x509:" + certificate[5:20] + "\n" + certificate[20:]
	for _, names := range [][]IdentifierValue{nil, {fqdn}} {
		for _, bad := range []string{"x509:!!!!", broken} {
			_, err := Decide(Observation{Identifiers: append([]IdentifierValue{fuzzyValue(TypeTLSPublicKeyHash, bad)}, names...)}, nil, GreenboneMatchPolicy())
			if !errors.Is(err, ErrInvalidIdentifierValue) {
				t.Fatalf("names %v: an undecodable certificate must fail the decision: %v", names, err)
			}
		}
	}
	strong, err := EvaluateStrongPriority(GreenboneMatchPolicy(), []IdentifierValue{tls}, [][]IdentifierValue{{tls}})
	if err != nil || len(strong.CandidateIndices) != 0 {
		t.Fatalf("EvaluateStrongPriority must apply the certificate name rule: %+v %v", strong, err)
	}
	matches, err := MatchingIdentifiers([]IdentifierValue{tls}, []IdentifierValue{tls})
	if err != nil || len(matches) != 0 {
		t.Fatalf("MatchingIdentifiers must apply the certificate name rule: %v %v", matches, err)
	}
}

func testTLS(t *testing.T, commonName string) IdentifierValue {
	return fuzzyValue(TypeTLSPublicKeyHash, testCertificate(t, commonName))
}

func testCertificate(t *testing.T, commonName string, dnsNames ...string) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return "x509:" + base64.StdEncoding.EncodeToString(der)
}
