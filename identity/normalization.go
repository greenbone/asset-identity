// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidIdentifierValue identifies malformed payload syntax and values that identify no machine.
	ErrInvalidIdentifierValue = errors.New("invalid identifier value")
	// ErrUnsupportedIdentifierFormat identifies formats that have no supported contract.
	ErrUnsupportedIdentifierFormat = errors.New("unsupported identifier format")
)

// errPlaceholder marks well-formed values every machine or no machine carries: zero, broadcast, loopback,
// link-local, multicast and vendor default values. Decide leaves them out; NormalizeIdentifier reports them as
// ErrInvalidIdentifierValue.
var errPlaceholder = errors.New("placeholder value")

const maxOpaqueLength = 2048

// normalizers holds one normalizer per identifier type. Input is trimmed of surrounding whitespace and nonempty.
var normalizers = map[IdentifierType]func(value string) (string, error){
	TypeCloudIdentifier:  normalizeOpaque,
	TypeGreenboneID:      normalizeOpaque,
	TypeAgentID:          normalizeOpaque,
	TypeMachineID:        normalizeMachineID,
	TypeBIOSUUID:         normalizeBIOSUUID,
	TypeSSHHostKey:       normalizeSSHHostKey,
	TypeTLSPublicKeyHash: normalizeTLSPublicKeyHash,
	TypeIP:               normalizeIP,
	TypeFQDN:             normalizeFQDN,
	TypeMAC:              normalizeMAC,
	TypeHostname:         normalizeHostname,
	TypeImageReference:   normalizeOpaque,
}

// ValidateIdentifier checks type-specific payload syntax without mutating input.
func ValidateIdentifier(value IdentifierValue) error {
	_, err := canonicalIdentifierValue(value)
	return err
}

// NormalizeIdentifier returns the identifier with its canonical payload.
func NormalizeIdentifier(value IdentifierValue) (IdentifierValue, error) {
	canonical, err := canonicalIdentifierValue(value)
	if err != nil {
		return IdentifierValue{}, err
	}
	return IdentifierValue{Type: value.Type, Value: canonical}, nil
}

// EqualIdentifiers compares canonical type and payload.
// Both inputs are validated, with errors reported from a before b.
func EqualIdentifiers(a, b IdentifierValue) (bool, error) {
	left, err := NormalizeIdentifier(a)
	if err != nil {
		return false, fmt.Errorf("a: %w", err)
	}
	right, err := NormalizeIdentifier(b)
	if err != nil {
		return false, fmt.Errorf("b: %w", err)
	}
	return SameRepresentation(left, right), nil
}

func canonicalIdentifierValue(value IdentifierValue) (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	payload := strings.TrimSpace(value.Value)
	if payload == "" {
		return "", fmt.Errorf("%s: empty payload: %w", value.Type, ErrInvalidIdentifierValue)
	}
	canonical, err := normalizers[value.Type](payload)
	if errors.Is(err, errPlaceholder) {
		return "", fmt.Errorf("%s: %w: %w", value.Type, ErrInvalidIdentifierValue, err)
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", value.Type, err)
	}
	return canonical, nil
}

func normalizeOpaque(value string) (string, error) {
	if len(value) > maxOpaqueLength {
		return "", ErrInvalidIdentifierValue
	}
	return value, nil
}

// normalizeMachineID takes the 128 bits of a machine id in any of their written forms, the 32 hex digits of a Linux
// machine-id or the UUID of a Windows MachineGuid, with or without braces, and returns them as 32 lowercase hex digits.
func normalizeMachineID(value string) (string, error) {
	if strings.EqualFold(value, "uninitialized") {
		return "", errPlaceholder
	}
	canonical, err := canonicalUUID(value)
	if err != nil {
		return "", err
	}
	canonical = strings.ReplaceAll(canonical, "-", "")
	if strings.Trim(canonical, "0") == "" {
		return "", errPlaceholder
	}
	return canonical, nil
}

var placeholderBIOSUUIDs = []string{
	"00000000-0000-0000-0000-000000000000",
	"ffffffff-ffff-ffff-ffff-ffffffffffff",
	"03000200-0400-0500-0006-000700080009",
}

func normalizeBIOSUUID(value string) (string, error) {
	canonical, err := canonicalUUID(value)
	if err != nil {
		return "", err
	}
	for _, placeholder := range placeholderBIOSUUIDs {
		if canonical == placeholder {
			return "", errPlaceholder
		}
	}
	return canonical, nil
}

func normalizeSSHHostKey(value string) (string, error) {
	return canonicalSSHKey(value)
}

func normalizeTLSPublicKeyHash(value string) (string, error) {
	return canonicalSPKIHash(value)
}

func normalizeIP(value string) (string, error) {
	address, err := canonicalIP(value)
	if err != nil {
		return "", err
	}
	if isSharedAddress(address) {
		return "", errPlaceholder
	}
	return address.String(), nil
}

func normalizeMAC(value string) (string, error) {
	canonical, err := canonicalMAC(value)
	if err != nil {
		return "", err
	}
	if canonical == "00:00:00:00:00:00" || canonical == "ff:ff:ff:ff:ff:ff" {
		return "", errPlaceholder
	}
	return canonical, nil
}

func normalizeFQDN(value string) (string, error) {
	labels, err := dnsLabels(value)
	if err != nil {
		return "", err
	}
	if len(labels) < 2 {
		return "", ErrUnsupportedIdentifierFormat
	}
	if isDigits(labels[len(labels)-1]) {
		return "", ErrInvalidIdentifierValue
	}
	canonical := strings.Join(labels, ".")
	if canonical == "localhost.localdomain" {
		return "", errPlaceholder
	}
	return canonical, nil
}

func normalizeHostname(value string) (string, error) {
	labels, err := dnsLabels(value)
	if err != nil {
		return "", err
	}
	if len(labels) > 1 && isDigits(labels[len(labels)-1]) {
		return "", ErrInvalidIdentifierValue
	}
	canonical := strings.Join(labels, ".")
	if canonical == "localhost" || canonical == "localhost.localdomain" {
		return "", errPlaceholder
	}
	if len(labels) == 1 && strings.HasSuffix(value, ".") {
		canonical += "."
	}
	return canonical, nil
}
