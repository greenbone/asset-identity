package identity

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidIdentifierValue identifies malformed payload syntax.
	ErrInvalidIdentifierValue = errors.New("invalid identifier value")
	// ErrUnsupportedIdentifierFormat identifies formats that have no supported contract.
	ErrUnsupportedIdentifierFormat = errors.New("unsupported identifier format")
)

// ValidateIdentifier checks supported payload syntax without mutating input.
// It does not establish producer authenticity, scope sufficiency, or matching eligibility.
// Unlike IdentifierValue.Validate, it checks type-specific payload formats.
func ValidateIdentifier(value IdentifierValue) error {
	_, err := canonicalIdentifierValue(value)
	return err
}

// NormalizeIdentifier returns a canonical payload and an independent scope copy.
// Opaque Greenbone, agent, and cloud payloads are only checked for nonemptiness;
// no producer-specific generation, namespace, placeholder, or conversion rules
// are inferred. Unsupported collector formats return an error.
func NormalizeIdentifier(value IdentifierValue) (IdentifierValue, error) {
	canonical, err := canonicalIdentifierValue(value)
	if err != nil {
		return IdentifierValue{}, err
	}
	result := value.Clone()
	result.Value = canonical
	return result, nil
}

// EqualIdentifiers compares canonical type, payload, and complete supplied scope.
// Both inputs must be valid, even when their types differ. Error precedence is a
// then b. Equality does not decide asset identity or matching eligibility.
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
	if value.Type == TypeMachineID {
		switch value.Scope["kind"] {
		case "linux_machine_id", "windows_machine_guid":
		default:
			return "", fmt.Errorf("%s: kind: %w", value.Type, ErrUnsupportedIdentifierFormat)
		}
	}
	if value.Value == "" {
		return "", fmt.Errorf("%s: empty payload: %w", value.Type, ErrInvalidIdentifierValue)
	}
	var canonical string
	var err error
	switch value.Type {
	case TypeGreenboneID, TypeAgentID, TypeCloudIdentifier:
		canonical = value.Value
	case TypeMachineID:
		if value.Scope["kind"] == "linux_machine_id" {
			canonical, err = canonicalHex(value.Value, 32)
		} else {
			canonical, err = canonicalUUID(value.Value)
		}
	case TypeBIOSUUID:
		canonical, err = canonicalUUID(value.Value)
	case TypeMAC:
		canonical, err = canonicalMAC(value.Value)
	case TypeIP:
		canonical, err = canonicalIP(value.Value)
	case TypeHostname, TypeFQDN:
		canonical, err = canonicalDNS(value.Value, value.Type == TypeFQDN)
	case TypeTLSPublicKeyHash:
		canonical, err = canonicalSPKIHash(value.Value)
	case TypeSSHHostKey:
		canonical, err = canonicalSSHKey(value.Value)
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", value.Type, err)
	}
	return canonical, nil
}
