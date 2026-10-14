package identity

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Only the SPEC-001B public-key-line grammar is supported. Fingerprints,
// certificates, known-hosts records, and private keys need separate producer
// contracts; no guessed conversion to public-key material is possible.
func canonicalSSHKey(value string) (string, error) {
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
		value = strings.TrimSuffix(value, "\r")
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", ErrInvalidIdentifierValue
	}
	split := strings.IndexAny(value, " \t")
	if split < 0 {
		return "", ErrUnsupportedIdentifierFormat
	}
	algorithm := value[:split]
	switch algorithm {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	default:
		return "", ErrUnsupportedIdentifierFormat
	}
	rest := strings.TrimLeft(value[split:], " \t")
	encoded := rest
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		encoded = rest[:i]
	}
	if strings.HasPrefix(encoded, "SHA256:") || strings.HasPrefix(encoded, "MD5:") {
		return "", ErrUnsupportedIdentifierFormat
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return "", ErrInvalidIdentifierValue
	}
	key, err := ssh.ParsePublicKey(blob)
	if err != nil || key.Type() != algorithm {
		return "", ErrInvalidIdentifierValue
	}
	if public, ok := key.(ssh.CryptoPublicKey); ok {
		if rsaKey, ok := public.CryptoPublicKey().(*rsa.PublicKey); ok && rsaKey.N.Sign() <= 0 {
			return "", ErrInvalidIdentifierValue
		}
	}
	canonical := key.Marshal()
	if !bytes.Equal(blob, canonical) {
		return "", ErrInvalidIdentifierValue
	}
	return algorithm + " " + base64.StdEncoding.EncodeToString(canonical), nil
}
