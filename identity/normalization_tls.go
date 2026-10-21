// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

func canonicalSPKIHash(value string) (string, error) {
	const prefix = "spki-sha256:"
	if encoded, ok := strings.CutPrefix(value, "x509:"); ok {
		if strings.ContainsAny(encoded, "\r\n") {
			return "", ErrInvalidIdentifierValue
		}
		der, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return "", ErrInvalidIdentifierValue
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return "", ErrInvalidIdentifierValue
		}
		return fmt.Sprintf("%s%x", prefix, sha256.Sum256(certificate.RawSubjectPublicKeyInfo)), nil
	}
	if !strings.HasPrefix(value, prefix) {
		return "", ErrUnsupportedIdentifierFormat
	}

	digest, err := canonicalHex(strings.TrimPrefix(value, prefix), 64)
	if err != nil {
		return "", err
	}
	return prefix + digest, nil
}
