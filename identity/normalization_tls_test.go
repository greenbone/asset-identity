// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/greenbone/asset-identity/identity"
)

//go:embed testdata/tls_scanner_certificate.txt
var scannerCertificate string

func TestTLSScannerCertificate(t *testing.T) {
	raw := strings.TrimSpace(scannerCertificate)
	const want = "spki-sha256:1667ab37ba6f84c9c7053970c7557507deccefdbb09c454d9d0ca0e4fe1c3319"
	for _, scope := range []identity.Scope{nil, {}, {"realm": "r"}} {
		input := identity.IdentifierValue{Type: identity.TypeTLSPublicKeyHash, Value: raw, Scope: scope}
		before := input.Clone()
		if err := identity.ValidateIdentifier(input); err != nil {
			t.Fatal(err)
		}
		normalized, err := identity.NormalizeIdentifier(input)
		if err != nil || normalized.Value != want || normalized.Type != input.Type || !reflect.DeepEqual(normalized.Scope, scope) {
			t.Fatalf("certificate: %+v %v", normalized, err)
		}
		again, err := identity.NormalizeIdentifier(normalized)
		if err != nil || !identity.SameRepresentation(normalized, again) {
			t.Fatalf("not idempotent: %+v %v", again, err)
		}
		if equal, err := identity.EqualIdentifiers(input, normalized); err != nil || !equal {
			t.Fatalf("certificate differs from its SPKI hash: %v %v", equal, err)
		}
		for _, pair := range [][2]identity.IdentifierValue{{input, normalized}, {normalized, input}} {
			decision, err := identity.Decide(identity.Observation{Identifiers: []identity.IdentifierValue{pair[0]}}, []identity.Candidate{{AssetKey: "existing", Identifiers: []identity.IdentifierValue{pair[1]}}}, identity.GreenboneMatchPolicy())
			if err != nil || decision.Action != identity.ActionReuse || decision.Stage != identity.StageStrong || decision.SelectedKey != "existing" {
				t.Fatalf("raw/canonical matching: %+v %v", decision, err)
			}
		}
		if normalized.Scope != nil {
			normalized.Scope["new"] = "changed"
		}
		if !reflect.DeepEqual(input, before) {
			t.Fatal("normalization mutated input or shared scope storage")
		}
	}
}

func TestTLSCertificateRenewalUsesPublicKey(t *testing.T) {
	normalize := func(seed byte, serial int64) identity.IdentifierValue {
		t.Helper()
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1, 0)}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		value, err := identity.NormalizeIdentifier(identity.IdentifierValue{Type: identity.TypeTLSPublicKeyHash, Value: "x509:" + base64.StdEncoding.EncodeToString(der)})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	first, renewed, differentKey := normalize(1, 1), normalize(1, 2), normalize(2, 1)
	if !identity.SameRepresentation(first, renewed) || identity.SameRepresentation(first, differentKey) {
		t.Fatal("TLS identity must follow the public key, not certificate serial or validity")
	}
}

func TestInvalidTLSScannerCertificate(t *testing.T) {
	raw := strings.TrimSpace(scannerCertificate)
	der, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "x509:"))
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{
		"x509:", "x509:!!!!", "x509:AAAA", "x509: " + strings.TrimPrefix(raw, "x509:"),
		raw + "\n", "x509:\n" + strings.TrimPrefix(raw, "x509:"),
		"x509:" + base64.StdEncoding.EncodeToString(der[:len(der)-1]),
		"x509:" + base64.StdEncoding.EncodeToString(append(der, 0)),
	}
	for _, input := range inputs {
		value := identity.IdentifierValue{Type: identity.TypeTLSPublicKeyHash, Value: input}
		if err := identity.ValidateIdentifier(value); !errors.Is(err, identity.ErrInvalidIdentifierValue) {
			t.Fatalf("invalid certificate validation: %v", err)
		}
		result, err := identity.NormalizeIdentifier(value)
		if !errors.Is(err, identity.ErrInvalidIdentifierValue) || !reflect.DeepEqual(result, identity.IdentifierValue{}) {
			t.Fatalf("invalid certificate normalization: %+v %v", result, err)
		}
	}
}
