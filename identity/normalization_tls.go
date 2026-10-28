// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
)

const spkiPrefix = "spki-sha256:"

func canonicalSPKIHash(value string) (string, error) {
	if strings.HasPrefix(value, "x509:") {
		certificate, err := parseCertificate(value)
		if err != nil {
			return "", err
		}
		return spkiHash(certificate), nil
	}
	if !strings.HasPrefix(value, spkiPrefix) {
		return "", ErrUnsupportedIdentifierFormat
	}
	digest, err := canonicalHex(strings.TrimPrefix(value, spkiPrefix), 64)
	if err != nil {
		return "", err
	}
	return spkiPrefix + digest, nil
}

func parseCertificate(value string) (*x509.Certificate, error) {
	encoded := strings.TrimPrefix(value, "x509:")
	if strings.ContainsAny(encoded, "\r\n") {
		return nil, ErrInvalidIdentifierValue
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidIdentifierValue
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrInvalidIdentifierValue
	}
	return certificate, nil
}

func spkiHash(certificate *x509.Certificate) string {
	return fmt.Sprintf("%s%x", spkiPrefix, sha256.Sum256(certificate.RawSubjectPublicKeyInfo))
}

// certificateNamesHost reports whether the subject CN or a DNS SAN equals one of the canonical host names. Names that
// are not plain ASCII host names, wildcards included, never match.
func certificateNamesHost(certificate *x509.Certificate, names []string) bool {
	for _, name := range append([]string{certificate.Subject.CommonName}, certificate.DNSNames...) {
		labels, err := dnsLabels(name)
		if err == nil && slices.Contains(names, strings.Join(labels, ".")) {
			return true
		}
	}
	return false
}
