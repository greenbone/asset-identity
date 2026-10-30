// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity_test

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/greenbone/asset-identity/identity"
)

func TestNormalizationStructuralErrors(t *testing.T) {
	tests := []struct {
		name     string
		v        identity.IdentifierValue
		category error
	}{
		{"unknown", identity.IdentifierValue{Type: "future_type"}, identity.ErrUnknownIdentifierType},
		{"scope", identity.IdentifierValue{Type: identity.TypeIP, Value: "192.0.2.1", Scope: identity.Scope{"": "bad"}}, identity.ErrInvalidScope},
		{"kind missing", identity.IdentifierValue{Type: identity.TypeMachineID, Value: strings.Repeat("1", 32)}, identity.ErrUnsupportedIdentifierFormat},
		{"kind unknown", identity.IdentifierValue{Type: identity.TypeMachineID, Scope: identity.Scope{"kind": "unknown"}}, identity.ErrUnsupportedIdentifierFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := tt.v.Clone()
			if err := identity.ValidateIdentifier(tt.v); !errors.Is(err, tt.category) {
				t.Fatalf("validation: %v, want %v", err, tt.category)
			}
			got, err := identity.NormalizeIdentifier(tt.v)
			if !errors.Is(err, tt.category) || !reflect.DeepEqual(got, identity.IdentifierValue{}) {
				t.Fatalf("normalize: %+v %v", got, err)
			}
			if !reflect.DeepEqual(before, tt.v) {
				t.Fatal("invalid input mutated")
			}
		})
	}
}

func TestSemanticEquality(t *testing.T) {
	value := func(typ identity.IdentifierType, s string) identity.IdentifierValue {
		return identity.IdentifierValue{Type: typ, Value: s}
	}
	a := value(identity.TypeHostname, "Web.Example.")
	nilScope := value(identity.TypeHostname, "web.example")
	empty := nilScope
	empty.Scope = identity.Scope{}
	scoped := a
	scoped.Scope = identity.Scope{"namespace": "A", "optional": ""}
	reordered := nilScope
	reordered.Scope = identity.Scope{"optional": "", "namespace": "A"}
	changed := reordered.Clone()
	changed.Scope["namespace"] = "a"
	withEmpty := a.Clone()
	withEmpty.Scope = identity.Scope{"optional": ""}
	withoutDimension := a.Clone()
	withoutDimension.Scope = identity.Scope{}
	extra := reordered.Clone()
	extra.Scope["extra"] = "dimension"
	tests := []struct {
		name string
		a, b identity.IdentifierValue
		want bool
	}{
		{"hostname canonical", a, nilScope, true}, {"different type", a, value(identity.TypeFQDN, "web.example"), false},
		{"short versus qualified hostname", value(identity.TypeHostname, "web"), nilScope, false},
		{"absolute versus relative", value(identity.TypeHostname, "web."), value(identity.TypeHostname, "web"), false},
		{"opaque case", value(identity.TypeAgentID, "Id"), value(identity.TypeAgentID, "id"), false},
		{"opaque surrounding whitespace", value(identity.TypeGreenboneID, " Id "), value(identity.TypeGreenboneID, "Id"), true},
		{"opaque inner whitespace", value(identity.TypeGreenboneID, "I d"), value(identity.TypeGreenboneID, "Id"), false},
		{"cloud case", value(identity.TypeCloudIdentifier, "Provider/Resource-A"), value(identity.TypeCloudIdentifier, "provider/resource-a"), false},
		{"scope presence", nilScope, empty, false}, {"scope insertion order", scoped, reordered, true}, {"scope case", scoped, changed, false},
		{"empty versus absent dimension", withEmpty, withoutDimension, false},
		{"extra dimension", scoped, extra, false},
		{"TLS digest distinction", value(identity.TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("a", 64)), value(identity.TypeTLSPublicKeyHash, "spki-sha256:"+strings.Repeat("b", 64)), false},
		{"mapped family", value(identity.TypeIP, "192.0.2.1"), value(identity.TypeIP, "::ffff:192.0.2.1"), true},
		{"zone absent", value(identity.TypeIP, "2001:db8::1"), value(identity.TypeIP, "2001:db8::1%eth0"), true},
		{"zone case", value(identity.TypeIP, "2001:db8::1%eth0"), value(identity.TypeIP, "2001:db8::1%Eth0"), true},
		{"other address", value(identity.TypeIP, "192.0.2.1"), value(identity.TypeIP, "192.0.2.2"), false},
	}
	linux := value(identity.TypeMachineID, "00112233445566778899aabbccddeeff")
	linux.Scope = identity.Scope{"kind": "linux_machine_id"}
	windows := value(identity.TypeMachineID, linux.Value)
	windows.Scope = identity.Scope{"kind": "windows_machine_guid"}
	tests = append(tests, struct {
		name string
		a, b identity.IdentifierValue
		want bool
	}{"machine lineage", linux, windows, false})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, pair := range [][2]identity.IdentifierValue{{tt.a, tt.b}, {tt.b, tt.a}} {
				got, err := identity.EqualIdentifiers(pair[0], pair[1])
				if err != nil || got != tt.want {
					t.Fatalf("equality=%v %v", got, err)
				}
			}
			for _, v := range []identity.IdentifierValue{tt.a, tt.b} {
				same, err := identity.EqualIdentifiers(v, v)
				if err != nil || !same {
					t.Fatal("not reflexive")
				}
			}
		})
	}
	variants := []identity.IdentifierValue{value(identity.TypeMAC, "02ABCDEF0123"), value(identity.TypeMAC, "02:ab:cd:ef:01:23"), value(identity.TypeMAC, "02ab.cdef.0123")}
	for _, x := range variants {
		for _, y := range variants {
			same, err := identity.EqualIdentifiers(x, y)
			if err != nil || !same {
				t.Fatal("equivalence is not transitive")
			}
		}
	}
}

func TestEqualityErrorPrecedence(t *testing.T) {
	good := identity.IdentifierValue{Type: identity.TypeHostname, Value: "web"}
	bad := identity.IdentifierValue{Type: identity.TypeIP, Value: "bad"}
	unknown := identity.IdentifierValue{Type: "unknown"}
	for _, tt := range []struct {
		a, b     identity.IdentifierValue
		category error
		operand  string
	}{{bad, good, identity.ErrInvalidIdentifierValue, "a:"}, {good, bad, identity.ErrInvalidIdentifierValue, "b:"}, {unknown, bad, identity.ErrUnknownIdentifierType, "a:"}, {bad, unknown, identity.ErrInvalidIdentifierValue, "a:"}} {
		same, err := identity.EqualIdentifiers(tt.a, tt.b)
		if same || !errors.Is(err, tt.category) || !strings.Contains(err.Error(), tt.operand) {
			t.Fatalf("%v %v", same, err)
		}
	}
}

func TestNormalizedScopeOwnership(t *testing.T) {
	for _, scope := range []identity.Scope{nil, {}, {"Namespace": " Mixed ", "empty": "", "extra": "x"}} {
		v := identity.IdentifierValue{Type: identity.TypeHostname, Value: "WEB", Scope: scope}
		before := v.Clone()
		for range 3 {
			got, err := identity.NormalizeIdentifier(v)
			if err != nil || !reflect.DeepEqual(got.Scope, scope) {
				t.Fatalf("scope changed: %+v %v", got, err)
			}
			if got.Scope != nil {
				got.Scope["new"] = "changed"
			}
			if !reflect.DeepEqual(v, before) {
				t.Fatal("scope alias")
			}
		}
	}
}

func TestSSHNormalization(t *testing.T) {
	for _, fixture := range sshFixtures() {
		t.Run(fixture.algorithm, func(t *testing.T) {
			canonical := fixture.algorithm + " " + base64.StdEncoding.EncodeToString(fixture.blob)
			for _, input := range []string{canonical, canonical + " comment", canonical + "\tcomment\r\n", canonical + "\n", "22 " + canonical, "65535\t" + canonical + " comment\r\n", "22 " + canonical + "\n\n", canonical + "\n\n", canonical + "\r", " " + canonical} {
				v := identity.IdentifierValue{Type: identity.TypeSSHHostKey, Value: input}
				got, err := identity.NormalizeIdentifier(v)
				if err != nil || got.Value != canonical {
					t.Fatalf("%q: %+v %v", input, got, err)
				}
				if err := identity.ValidateIdentifier(got); err != nil {
					t.Fatal(err)
				}
				again, err := identity.NormalizeIdentifier(got)
				if err != nil || !identity.SameRepresentation(got, again) {
					t.Fatal("SSH not idempotent")
				}
				if same, err := identity.EqualIdentifiers(v, got); err != nil || !same {
					t.Fatal("SSH comments change equality")
				}
			}
			for _, bad := range []string{"0 " + canonical, "65536 " + canonical, "22x " + canonical, canonical + "\n" + canonical, canonical + "\r\n" + canonical, fixture.algorithm + " " + base64.StdEncoding.EncodeToString(append(bytes.Clone(fixture.blob), 0)), fixture.algorithm + " !!!!", "ssh-rsa " + base64.StdEncoding.EncodeToString(sshWire([]byte("ssh-ed25519"), make([]byte, 32)))} {
				// The mismatch fixture is invalid even in the RSA subtest.
				if err := identity.ValidateIdentifier(identity.IdentifierValue{Type: identity.TypeSSHHostKey, Value: bad}); !errors.Is(err, identity.ErrInvalidIdentifierValue) {
					t.Fatalf("bad key accepted: %v", err)
				}
			}
		})
	}
	for _, bad := range []string{"22", "22 ", "-22 ssh-ed25519 AAAA", "SHA256:AAAA", "ssh-ed25519 SHA256:AAAA", "ssh-dss AAAA", "ssh-ed25519-cert-v01@openssh.com AAAA", "-----BEGIN PRIVATE KEY-----", "host ssh-ed25519 AAAA", "no-port-forwarding ssh-ed25519 AAAA"} {
		if err := identity.ValidateIdentifier(identity.IdentifierValue{Type: identity.TypeSSHHostKey, Value: bad}); !errors.Is(err, identity.ErrUnsupportedIdentifierFormat) && !errors.Is(err, identity.ErrInvalidIdentifierValue) {
			t.Fatalf("unsupported key accepted: %v", err)
		}
	}
	for _, blob := range [][]byte{
		sshWire([]byte("ssh-ed25519"), make([]byte, 31)),
		sshWire([]byte("ssh-rsa"), []byte{1, 0, 1}, []byte{0xff}),
		sshWire([]byte("ecdsa-sha2-nistp256"), []byte("nistp384"), []byte{4}),
	} {
		algorithm := string(blob[4 : 4+binary.BigEndian.Uint32(blob[:4])])
		if err := identity.ValidateIdentifier(identity.IdentifierValue{Type: identity.TypeSSHHostKey, Value: algorithm + " " + base64.StdEncoding.EncodeToString(blob)}); !errors.Is(err, identity.ErrInvalidIdentifierValue) {
			t.Fatalf("invalid key structure accepted: %v", err)
		}
	}
	// A redundant RSA mpint leading zero must not silently change key material.
	blob := sshWire([]byte("ssh-rsa"), []byte{0, 1, 0, 1}, []byte{0, 0x80, 1})
	if err := identity.ValidateIdentifier(identity.IdentifierValue{Type: identity.TypeSSHHostKey, Value: "ssh-rsa " + base64.StdEncoding.EncodeToString(blob)}); !errors.Is(err, identity.ErrInvalidIdentifierValue) {
		t.Fatalf("noncanonical RSA accepted: %v", err)
	}
}

type sshFixture struct {
	algorithm string
	blob      []byte
}

func sshFixtures() []sshFixture {
	fixtures := []sshFixture{{"ssh-ed25519", sshWire([]byte("ssh-ed25519"), bytes.Repeat([]byte{1}, 32))}, {"ssh-rsa", sshWire([]byte("ssh-rsa"), []byte{1, 0, 1}, []byte{0, 0x80, 1})}}
	for _, item := range []struct {
		name  string
		curve elliptic.Curve
	}{{"nistp256", elliptic.P256()}, {"nistp384", elliptic.P384()}, {"nistp521", elliptic.P521()}} {
		algorithm := "ecdsa-sha2-" + item.name
		point := elliptic.Marshal(item.curve, item.curve.Params().Gx, item.curve.Params().Gy)
		fixtures = append(fixtures, sshFixture{algorithm, sshWire([]byte(algorithm), []byte(item.name), point)})
	}
	return fixtures
}
func sshWire(fields ...[]byte) []byte {
	var blob []byte
	for _, field := range fields {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(field)))
		blob = append(blob, field...)
	}
	return blob
}

func TestNormalizationDoesNotChangeModelBehavior(t *testing.T) {
	for _, v := range []identity.IdentifierValue{{Type: identity.TypeIP, Value: "not an IP"}, {Type: identity.TypeHostname, Value: "WEB"}, {Type: identity.TypeMachineID, Value: "unknown producer"}} {
		if err := v.Validate(); err != nil {
			t.Fatal("structural validation changed")
		}
		o, err := identity.NewObservation(v, nil)
		if err != nil || !identity.SameRepresentation(v, o.Identifier) || o.ObservedAt != nil {
			t.Fatal("constructor gained semantic behavior")
		}
		if !identity.SameRepresentation(v, o.Normalize().Identifier) {
			t.Fatal("timestamp normalization changed payload")
		}
	}
}

func TestConcurrentNormalization(t *testing.T) {
	v := identity.IdentifierValue{Type: identity.TypeHostname, Value: "WEB.EXAMPLE.", Scope: identity.Scope{"namespace": "A"}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 30 {
				got, err := identity.NormalizeIdentifier(v)
				if err != nil || got.Value != "web.example" {
					t.Error("nondeterministic normalization")
				}
				if same, err := identity.EqualIdentifiers(v, got); err != nil || !same {
					t.Error("nondeterministic equality")
				}
				got.Scope["namespace"] = "independent"
			}
		})
	}
	wg.Wait()
	if v.Scope["namespace"] != "A" {
		t.Fatal("concurrent copies mutate caller")
	}
}
