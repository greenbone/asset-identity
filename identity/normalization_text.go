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

// canonicalIP unmaps IPv4-mapped IPv6 and drops the zone; one zone without whitespace is accepted on input.
func canonicalIP(value string) (netip.Addr, error) {
	if strings.ContainsFunc(value, unicode.IsSpace) || strings.Count(value, "%") > 1 {
		return netip.Addr{}, ErrInvalidIdentifierValue
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, ErrInvalidIdentifierValue
	}
	return address.Unmap().WithZone(""), nil
}

var sharedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// isSharedAddress reports unspecified, loopback, link-local, multicast and broadcast addresses.
func isSharedAddress(address netip.Addr) bool {
	for _, prefix := range sharedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// dnsLabels returns the lower-case labels of an ASCII host name; a trailing root dot is ignored. Labels use letters,
// digits, hyphen and underscore and neither start nor end with a hyphen. An IP address is not a name.
func dnsLabels(value string) ([]string, error) {
	name := strings.TrimSuffix(value, ".")
	if name == "" || len(name) > 253 {
		return nil, ErrInvalidIdentifierValue
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return nil, ErrInvalidIdentifierValue
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, ErrInvalidIdentifierValue
		}
		for j := range len(label) {
			if !isLabelByte(label[j]) {
				return nil, ErrInvalidIdentifierValue
			}
		}
		labels[i] = strings.ToLower(label)
	}
	return labels, nil
}

func isLabelByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

func isDigits(value string) bool {
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
