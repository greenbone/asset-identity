// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Public-key lines may include the scanner's leading port number.
func canonicalSSHKey(value string) (string, error) {
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
		value = strings.TrimSuffix(value, "\r")
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", ErrInvalidIdentifierValue
	}
	separatorIndex := strings.IndexAny(value, " \t")
	if separatorIndex < 0 {
		return "", ErrUnsupportedIdentifierFormat
	}
	algorithm := value[:separatorIndex]
	keyData := strings.TrimLeft(value[separatorIndex:], " \t")
	if len(algorithm) > 0 && algorithm[0] >= '0' && algorithm[0] <= '9' {
		port, err := strconv.ParseUint(algorithm, 10, 16)
		if err != nil || port == 0 {
			return "", ErrInvalidIdentifierValue
		}
		separatorIndex = strings.IndexAny(keyData, " \t")
		if separatorIndex < 0 {
			return "", ErrUnsupportedIdentifierFormat
		}
		algorithm = keyData[:separatorIndex]
		keyData = strings.TrimLeft(keyData[separatorIndex:], " \t")
	}
	switch algorithm {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	default:
		return "", ErrUnsupportedIdentifierFormat
	}
	encodedKey := keyData
	if i := strings.IndexAny(keyData, " \t"); i >= 0 {
		encodedKey = keyData[:i]
	}
	if strings.HasPrefix(encodedKey, "SHA256:") || strings.HasPrefix(encodedKey, "MD5:") {
		return "", ErrUnsupportedIdentifierFormat
	}
	keyBlob, err := base64.StdEncoding.Strict().DecodeString(encodedKey)
	if err != nil {
		return "", ErrInvalidIdentifierValue
	}
	key, err := ssh.ParsePublicKey(keyBlob)
	if err != nil || key.Type() != algorithm {
		return "", ErrInvalidIdentifierValue
	}
	if public, ok := key.(ssh.CryptoPublicKey); ok {
		if rsaKey, ok := public.CryptoPublicKey().(*rsa.PublicKey); ok && rsaKey.N.Sign() <= 0 {
			return "", ErrInvalidIdentifierValue
		}
	}
	canonical := key.Marshal()
	if !bytes.Equal(keyBlob, canonical) {
		return "", ErrInvalidIdentifierValue
	}
	return algorithm + " " + base64.StdEncoding.EncodeToString(canonical), nil
}
