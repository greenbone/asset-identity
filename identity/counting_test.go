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
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Tests for the rules of the Confluence page "Asset Identification & Counting".

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
			got, err := Decide(Observation{Identifiers: tt.incoming}, tt.candidates, policy)
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != tt.action || got.Stage != tt.stage || got.SelectedKey != tt.selected || !reflect.DeepEqual(got.MergeIndices, tt.merges) {
				t.Fatalf("decision=%+v", got)
			}
			if got.NeedsNewKey != (tt.action == ActionCreate) || (got.SelectedIndex == nil) != got.NeedsNewKey {
				t.Fatalf("decision=%+v", got)
			}
			if got.Action == ActionCreate && len(got.MergeIndices) > 0 {
				t.Fatalf("create never merges: %+v", got)
			}
		})
	}
}

func scanned(typ IdentifierType, value string) IdentifierValue {
	return IdentifierValue{Type: typ, Value: value, Scope: Scope{"scanner": "s1"}}
}

func machineID(value string) IdentifierValue {
	return IdentifierValue{Type: TypeMachineID, Value: value, Scope: Scope{"kind": "linux_machine_id"}}
}

var (
	ip1   = scanned(TypeIP, "10.0.0.5")
	ip2   = scanned(TypeIP, "10.0.0.9")
	mac1  = scanned(TypeMAC, "00:11:22:33:44:55")
	mac2  = scanned(TypeMAC, "00:11:22:33:44:66")
	fqdn1 = scanned(TypeFQDN, "h.example.com")
	fqdn2 = scanned(TypeFQDN, "other.example.com")
	host1 = fuzzyValue(TypeHostname, "web01")
	cloud = fuzzyValue(TypeCloudIdentifier, "i-1")
	mid1  = machineID("0123456789abcdef0123456789abcdef")
	mid2  = machineID("fedcba9876543210fedcba9876543210")
	bios  = fuzzyValue(TypeBIOSUUID, "00112233-4455-6677-8899-aabbccddeeff")
	agent = fuzzyValue(TypeAgentID, "agent-1")
	ssh1  = fuzzyValue(TypeSSHHostKey, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxRDQ1oFkdnTbrDeUOXKt1pRrz6xcXZZ2fPKbBe3Hdb")
)

func TestCountingDefaultStrongOrder(t *testing.T) {
	want := []IdentifierType{TypeCloudIdentifier, TypeGreenboneID, TypeMachineID, TypeBIOSUUID, TypeAgentID, TypeSSHHostKey, TypeTLSPublicKeyHash}
	if got := GreenboneMatchPolicy().StrongOrder; !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestCountingSufficientWeakEvidence(t *testing.T) {
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"ip alone never binds", []IdentifierValue{ip1}, []Candidate{fuzzyRow("A", 1, ip1, mac1)}, ActionCreate, StageFuzzy, "", nil},
		{"fqdn alone never binds", []IdentifierValue{fqdn1}, []Candidate{fuzzyRow("A", 1, fqdn1, ip1)}, ActionCreate, StageFuzzy, "", nil},
		{"hostname alone never binds", []IdentifierValue{host1}, []Candidate{fuzzyRow("A", 1, host1, ip1)}, ActionCreate, StageFuzzy, "", nil},
		{"mac alone binds", []IdentifierValue{mac1}, []Candidate{fuzzyRow("A", 1, mac1, ip1)}, ActionReuse, StageFuzzy, "A", nil},
		{"ip and fqdn bind", []IdentifierValue{ip1, fqdn1}, []Candidate{fuzzyRow("A", 1, ip1, fqdn1)}, ActionReuse, StageFuzzy, "A", nil},
		{"ip and hostname bind", []IdentifierValue{ip1, host1}, []Candidate{fuzzyRow("A", 1, ip1, host1)}, ActionReuse, StageFuzzy, "A", nil},
		{"fqdn and hostname bind", []IdentifierValue{fqdn1, host1}, []Candidate{fuzzyRow("A", 1, fqdn1, host1)}, ActionReuse, StageFuzzy, "A", nil},
		{"two values of one type are one type", []IdentifierValue{ip1, ip2}, []Candidate{fuzzyRow("A", 1, ip1, ip2)}, ActionCreate, StageFuzzy, "", nil},
	})
	anchorIP := MatchPolicy{Fuzzy: []FuzzyMember{{Type: TypeIP, Weight: 1}, {Type: TypeMAC, Weight: .4}}}
	runCountingCases(t, anchorIP, []countingCase{
		{"the anchor follows the policy weights", []IdentifierValue{ip1}, []Candidate{fuzzyRow("A", 1, ip1, mac1)}, ActionReuse, StageFuzzy, "A", nil},
		{"a type below weight one needs a second type", []IdentifierValue{mac1}, []Candidate{fuzzyRow("A", 1, ip1, mac1)}, ActionCreate, StageFuzzy, "", nil},
	})
}

func TestCountingCompatibility(t *testing.T) {
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"same fqdn and mac with a new ip stay one asset", []IdentifierValue{fqdn1, ip2, mac1}, []Candidate{fuzzyRow("A", 1, fqdn1, ip1, mac1)}, ActionReuse, StageFuzzy, "A", nil},
		{"a second nic stays one asset", []IdentifierValue{ip1, mac1, ip2, mac2}, []Candidate{fuzzyRow("A", 1, ip1, mac1)}, ActionReuse, StageFuzzy, "A", nil},
		{"a hostname only the report carries does not block", []IdentifierValue{ip1, mac1, host1}, []Candidate{fuzzyRow("A", 1, ip1, mac1)}, ActionReuse, StageFuzzy, "A", nil},
		{"a renamed host with the same mac stays one asset", []IdentifierValue{fqdn2, ip1, mac1}, []Candidate{fuzzyRow("A", 1, fqdn1, ip1, mac1)}, ActionReuse, StageFuzzy, "A", nil},
		{"same ip with different macs are two assets", []IdentifierValue{ip1, mac2}, []Candidate{fuzzyRow("A", 1, ip1, mac1)}, ActionCreate, StageFuzzy, "", nil},
		{"same ip and fqdn with different macs are two assets", []IdentifierValue{ip1, fqdn1, mac2}, []Candidate{fuzzyRow("A", 1, ip1, fqdn1, mac1)}, ActionCreate, StageFuzzy, "", nil},
		{"a mac on one side only is compatible", []IdentifierValue{ip1, fqdn1}, []Candidate{fuzzyRow("A", 1, ip1, fqdn1, mac1)}, ActionReuse, StageFuzzy, "A", nil},
		{"another scanner's ip is another value", []IdentifierValue{{Type: TypeIP, Value: ip1.Value, Scope: Scope{"scanner": "s2"}}, fqdn1}, []Candidate{fuzzyRow("A", 1, ip1, fqdn1)}, ActionCreate, StageFuzzy, "", nil},
	})
}

func TestCountingStrongContradiction(t *testing.T) {
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"different cloud id with the same machine id is a new asset", []IdentifierValue{cloud, mid1}, []Candidate{fuzzyRow("A", 1, fuzzyValue(TypeCloudIdentifier, "i-2"), mid1)}, ActionCreate, StageStrong, "", nil},
		{"different machine id with the same ssh key is a new asset", []IdentifierValue{mid1, ssh1}, []Candidate{fuzzyRow("A", 1, mid2, ssh1)}, ActionCreate, StageStrong, "", nil},
		{"different machine id with the same bios uuid is a new asset", []IdentifierValue{mid1, bios}, []Candidate{fuzzyRow("A", 1, mid2, bios)}, ActionCreate, StageStrong, "", nil},
		{"reinstalled agent with the same machine id is the same asset", []IdentifierValue{fuzzyValue(TypeAgentID, "agent-new"), mid1}, []Candidate{fuzzyRow("A", 1, agent, mid1)}, ActionReuse, StageStrong, "A", nil},
		{"a higher type on one side only does not block", []IdentifierValue{cloud, mid1}, []Candidate{fuzzyRow("A", 1, mid1)}, ActionReuse, StageStrong, "A", nil},
		{"a contradicted candidate does not get weak evidence", []IdentifierValue{cloud, mid1, ip1, mac1}, []Candidate{fuzzyRow("A", 1, fuzzyValue(TypeCloudIdentifier, "i-2"), mid1, ip1, mac1)}, ActionCreate, StageStrong, "", nil},
		{"differing tls key sets are inconclusive and weak evidence decides", []IdentifierValue{fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("a", 64)), ip1, fqdn1}, []Candidate{fuzzyRow("A", 1, fuzzyValue(TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("b", 64)), ip1, fqdn1)}, ActionReuse, StageFuzzy, "A", nil},
	})
}

func TestCountingStrongComparisonUnavailable(t *testing.T) {
	scan := fuzzyRow("SCAN", 1, ip1, mac1)
	agentAsset := fuzzyRow("AGENT", 2, agent, ip1, mac1)
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"an agent report reuses the scan-only asset", []IdentifierValue{agent, ip1, mac1}, []Candidate{scan}, ActionReuse, StageFuzzy, "SCAN", nil},
		{"a scan report reuses the agent asset", []IdentifierValue{ip1, mac1}, []Candidate{agentAsset}, ActionReuse, StageFuzzy, "AGENT", nil},
		{"the agent asset wins and the scan asset merges into it", []IdentifierValue{agent, ip1, mac1}, []Candidate{agentAsset, scan}, ActionReuse, StageStrong, "AGENT", []int{1}},
		{"no candidates with strong ids create in the strong stage", []IdentifierValue{agent, ip1}, nil, ActionCreate, StageStrong, "", nil},
		{"only contradicted candidates create in the strong stage", []IdentifierValue{agent, ip1, mac1}, []Candidate{fuzzyRow("A", 1, fuzzyValue(TypeAgentID, "agent-2"), ip1, mac1)}, ActionCreate, StageStrong, "", nil},
		{"insufficient weak evidence with strong ids creates in the strong stage", []IdentifierValue{agent, ip1}, []Candidate{fuzzyRow("A", 1, ssh1, ip1)}, ActionCreate, StageStrong, "", nil},
		{"insufficient weak evidence without strong ids creates in the fuzzy stage", []IdentifierValue{ip1}, []Candidate{fuzzyRow("A", 1, ssh1, ip1)}, ActionCreate, StageFuzzy, "", nil},
	})
}

func TestCountingFreshness(t *testing.T) {
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"the newest strong match survives and the others merge", []IdentifierValue{mid1}, []Candidate{fuzzyRow("OLD", 1, mid1), fuzzyRow("NEW", 5, mid1), fuzzyRow("MID", 3, mid1)}, ActionReuse, StageStrong, "NEW", []int{0, 2}},
		{"a higher priority match beats a newer lower one", []IdentifierValue{cloud, agent}, []Candidate{fuzzyRow("CLOUD", 1, cloud), fuzzyRow("AGENT", 5, agent)}, ActionReuse, StageStrong, "CLOUD", nil},
		{"more shared weak evidence beats newer", []IdentifierValue{ip1, fqdn1, mac1}, []Candidate{fuzzyRow("NEWER", 5, ip1, fqdn1), fuzzyRow("CLOSER", 1, ip1, fqdn1, mac1)}, ActionReuse, StageFuzzy, "CLOSER", []int{0}},
		{"equal weak evidence newest survives", []IdentifierValue{ip1, fqdn1}, []Candidate{fuzzyRow("OLD", 1, ip1, fqdn1), fuzzyRow("NEW", 5, ip1, fqdn1)}, ActionReuse, StageFuzzy, "NEW", []int{0}},
	})
}

func TestCountingMergePlan(t *testing.T) {
	agent2 := fuzzyValue(TypeAgentID, "agent-2")
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"a strong-equal source merges", []IdentifierValue{mid1}, []Candidate{fuzzyRow("A", 5, mid1), fuzzyRow("B", 1, mid1, ip2)}, ActionReuse, StageStrong, "A", []int{1}},
		{"a source with sufficient weak evidence merges", []IdentifierValue{mid1}, []Candidate{fuzzyRow("A", 5, mid1, ip1, mac1), fuzzyRow("B", 1, ip1, mac1)}, ActionReuse, StageStrong, "A", []int{1}},
		{"a source sharing one weak type stays", []IdentifierValue{mid1}, []Candidate{fuzzyRow("A", 5, mid1, ip1, mac1), fuzzyRow("B", 1, ip1)}, ActionReuse, StageStrong, "A", nil},
		{"a source contradicting the survivor stays", []IdentifierValue{mid1}, []Candidate{fuzzyRow("A", 5, mid1, ip1, mac1), fuzzyRow("B", 1, mid2, ip1, mac1)}, ActionReuse, StageStrong, "A", nil},
		{"a weak source contradicting a strong-merged source stays", []IdentifierValue{mid1}, []Candidate{fuzzyRow("A", 5, mid1, ip1, mac1), fuzzyRow("B", 1, mid1, agent), fuzzyRow("C", 2, agent2, ip1, mac1)}, ActionReuse, StageStrong, "A", []int{1}},
		{"two weak sources contradicting each other both stay", []IdentifierValue{ip1, mac1}, []Candidate{fuzzyRow("W", 5, ip1, mac1), fuzzyRow("A", 1, agent, ip1, mac1), fuzzyRow("B", 2, agent2, ip1, mac1)}, ActionReuse, StageFuzzy, "W", nil},
		{"two weak sources sharing their strong id both merge", []IdentifierValue{ip1, mac1}, []Candidate{fuzzyRow("W", 5, ip1, mac1), fuzzyRow("A", 1, agent, ip1, mac1), fuzzyRow("B", 2, agent, ip1, mac1)}, ActionReuse, StageFuzzy, "W", []int{1, 2}},
		{"a weak source with a different mac stays", []IdentifierValue{ip1, fqdn1}, []Candidate{fuzzyRow("A", 5, ip1, fqdn1, mac1), fuzzyRow("B", 1, ip1, fqdn1, mac2)}, ActionReuse, StageFuzzy, "A", nil},
		{"merge indices keep input order", []IdentifierValue{mid1}, []Candidate{fuzzyRow("B", 1, ip1, mac1), fuzzyRow("A", 5, mid1, ip1, mac1), fuzzyRow("C", 2, mid1)}, ActionReuse, StageStrong, "A", []int{0, 2}},
	})
}

func TestCountingTLSEligibility(t *testing.T) {
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
	host := fuzzyValue(TypeHostname, "WEB01.example.com")
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
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

func TestCountingDecisionAppliesPageScenarios(t *testing.T) {
	runCountingCases(t, GreenboneMatchPolicy(), []countingCase{
		{"golden image clone keeping the machine id is one asset", []IdentifierValue{mid1, ip2, mac2}, []Candidate{fuzzyRow("A", 1, mid1, ip1, mac1)}, ActionReuse, StageStrong, "A", nil},
		{"os reinstall with a new machine id is a new asset", []IdentifierValue{mid2, bios, ip1, mac1}, []Candidate{fuzzyRow("A", 1, mid1, bios, ip1, mac1)}, ActionCreate, StageStrong, "", nil},
		{"reimaged cloud instance keeps its cloud id", []IdentifierValue{cloud, mid2, agent}, []Candidate{fuzzyRow("A", 1, cloud, mid1, fuzzyValue(TypeAgentID, "agent-old"))}, ActionReuse, StageStrong, "A", nil},
		{"a host without identifiers the customer could provide is counted separately", []IdentifierValue{ip2}, []Candidate{fuzzyRow("A", 1, ip1, mac1)}, ActionCreate, StageFuzzy, "", nil},
	})
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
