// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/greenbone/asset-identity/identity"
)

// FuzzNormalization checks parser safety and idempotence.
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
		f.Add(uint8(i), seed)
	}
	for _, key := range sshFixtures() {
		f.Add(uint8(4), "22 "+key.algorithm+" "+base64.StdEncoding.EncodeToString(key.blob))
	}
	f.Fuzz(func(t *testing.T, selector uint8, payload string) {
		input := identity.IdentifierValue{Type: types[int(selector)%len(types)], Value: payload}
		got, err := identity.NormalizeIdentifier(input)
		if err != nil {
			return
		}
		if got.Type != input.Type {
			t.Fatalf("normalization changed the type: %+v", got)
		}
		again, err := identity.NormalizeIdentifier(got)
		if err != nil || !identity.SameRepresentation(got, again) {
			t.Fatalf("normalization is not idempotent: %+v, %v", got, err)
		}
	})
}
