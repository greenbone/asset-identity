// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"unicode"
)

func canonicalHex(value string, length int) (string, error) {
	if len(value) != length {
		return "", ErrInvalidIdentifierValue
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", ErrInvalidIdentifierValue
	}
	return strings.ToLower(value), nil
}

func canonicalUUID(value string) (string, error) {
	if len(value) == 38 && value[0] == '{' && value[37] == '}' {
		value = value[1:37]
	}
	if len(value) == 36 {
		for _, i := range []int{8, 13, 18, 23} {
			if value[i] != '-' {
				return "", ErrInvalidIdentifierValue
			}
		}
		value = value[:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
	}
	h, err := canonicalHex(value, 32)
	if err != nil {
		return "", err
	}
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

func canonicalMAC(value string) (string, error) {
	switch len(value) {
	case 12:
		h, err := canonicalHex(value, 12)
		if err != nil {
			return "", err
		}
		value = h[:2] + ":" + h[2:4] + ":" + h[4:6] + ":" + h[6:8] + ":" + h[8:10] + ":" + h[10:]
	case 17:
		separator := value[2]
		if separator != ':' && separator != '-' {
			return "", ErrInvalidIdentifierValue
		}
		for _, i := range []int{5, 8, 11, 14} {
			if value[i] != separator {
				return "", ErrInvalidIdentifierValue
			}
		}
	case 14:
		if value[4] != '.' || value[9] != '.' {
			return "", ErrInvalidIdentifierValue
		}
	default:
		return "", ErrInvalidIdentifierValue
	}
	address, err := net.ParseMAC(value)
	if err != nil || len(address) != 6 {
		return "", ErrInvalidIdentifierValue
	}
	return address.String(), nil
}

func canonicalIP(value string) (string, error) {
	if strings.ContainsFunc(value, unicode.IsSpace) || strings.Count(value, "%") > 1 {
		return "", ErrInvalidIdentifierValue
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "", ErrInvalidIdentifierValue
	}
	return address.String(), nil
}

func canonicalDNS(value string, fqdn bool) (string, error) {
	absolute := strings.HasSuffix(value, ".")
	name := strings.TrimSuffix(value, ".")
	if name == "" || len(name) > 253 {
		return "", ErrInvalidIdentifierValue
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", ErrInvalidIdentifierValue
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidIdentifierValue
		}
		for i := range len(label) {
			c := label[i]
			letterOrDigit := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
			if !letterOrDigit && c != '-' {
				return "", ErrInvalidIdentifierValue
			}
		}
	}
	if fqdn && len(labels) == 1 && !absolute {
		return "", ErrUnsupportedIdentifierFormat
	}
	canonical := strings.ToLower(name)
	if absolute && len(labels) == 1 {
		canonical += "."
	}
	return canonical, nil
}

func canonicalSPKIHash(value string) (string, error) {
	const prefix = "spki-sha256:"
	if !strings.HasPrefix(value, prefix) {
		return "", ErrUnsupportedIdentifierFormat
	}
	digest, err := canonicalHex(strings.TrimPrefix(value, prefix), 64)
	if err != nil {
		return "", err
	}
	return prefix + digest, nil
}
