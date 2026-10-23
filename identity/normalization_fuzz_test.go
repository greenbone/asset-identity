// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity_test

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/greenbone/asset-identity/identity"
)

// FuzzNormalization checks parser safety, idempotence, and scope ownership.
func FuzzNormalization(f *testing.F) {
	types := []identity.IdentifierType{
		identity.TypeIP, identity.TypeHostname, identity.TypeFQDN, identity.TypeMAC,
		identity.TypeSSHHostKey, identity.TypeTLSPublicKeyHash, identity.TypeBIOSUUID,
		identity.TypeMachineID,
	}
	seeds := []string{
		"2001:0DB8::1", "HOST", "HOST.EXAMPLE.", "02-AB-CD-EF-01-23",
		"22 ssh-ed25519 invalid", strings.TrimSpace(scannerCertificate),
		"{00112233-4455-6677-8899-AABBCCDDEEFF}", "00112233445566778899AABBCCDDEEFF",
	}
	for i, seed := range seeds {
		for mode := uint8(0); mode < 3; mode++ {
			f.Add(uint8(i), seed, "kind", "linux_machine_id", mode)
		}
	}
	for _, key := range sshFixtures() {
		f.Add(uint8(4), "22 "+key.algorithm+" "+base64.StdEncoding.EncodeToString(key.blob), "realm", "r", uint8(2))
	}
	f.Fuzz(func(t *testing.T, selector uint8, payload, dimension, scopeValue string, mode uint8) {
		input := identity.IdentifierValue{Type: types[int(selector)%len(types)], Value: payload}
		switch mode % 3 {
		case 1:
			input.Scope = identity.Scope{}
		case 2:
			input.Scope = identity.Scope{dimension: scopeValue}
		}
		before := input.Clone()
		got, err := identity.NormalizeIdentifier(input)
		if !reflect.DeepEqual(input, before) {
			t.Fatal("normalization mutated input")
		}
		if err != nil {
			return
		}
		if !reflect.DeepEqual(got.Scope, input.Scope) {
			t.Fatal("normalization changed scope")
		}
		again, err := identity.NormalizeIdentifier(got)
		if err != nil || !identity.SameRepresentation(got, again) {
			t.Fatalf("normalization is not idempotent: %+v, %v", got, err)
		}
		if got.Scope != nil {
			got.Scope["test"] = "changed"
			if !reflect.DeepEqual(input, before) {
				t.Fatal("normalized scope aliases input")
			}
		}
	})
}
