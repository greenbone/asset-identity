package identity

import "fmt"

// BoundaryContext holds caller-resolved, qualified identity boundaries.
// Empty BoundaryID means unresolved; ScannerID is optional provenance only.
type BoundaryContext struct {
	BoundaryID string
	ScannerID  string // optional observer provenance, never identity or trust
}

// BoundaryCompatibility is a comparison outcome, not identity or authorization.
type BoundaryCompatibility string

const (
	BoundaryCompatible   BoundaryCompatibility = "COMPATIBLE"
	BoundaryIncompatible BoundaryCompatibility = "INCOMPATIBLE"
	BoundaryUnknown      BoundaryCompatibility = "UNKNOWN"
)

// CompareBoundaries compares caller-resolved keys without validating qualification.
// Equal keys are compatible, distinct keys incompatible, and missing keys unknown.
func CompareBoundaries(a, b BoundaryContext) BoundaryCompatibility {
	if a.BoundaryID == "" || b.BoundaryID == "" {
		return BoundaryUnknown
	}
	if a.BoundaryID == b.BoundaryID {
		return BoundaryCompatible
	}
	return BoundaryIncompatible
}

// FuzzyBoundaryMode governs fuzzy selection and merge evaluation admission.
type FuzzyBoundaryMode string

const (
	FuzzyBoundaryStrict FuzzyBoundaryMode = "strict"
	FuzzyBoundaryLegacy FuzzyBoundaryMode = "legacy"
)

// Validate rejects missing or unsupported modes without selecting a default.
func (m FuzzyBoundaryMode) Validate() error {
	switch m {
	case FuzzyBoundaryStrict, FuzzyBoundaryLegacy:
		return nil
	default:
		return fmt.Errorf("%w: fuzzy boundary mode %q", ErrInvalidMatchPolicy, m)
	}
}

// Admit checks fuzzy boundary admission without granting identity or merge safety.
func (m FuzzyBoundaryMode) Admit(c BoundaryCompatibility) (bool, error) {
	if err := m.Validate(); err != nil {
		return false, err
	}
	switch c {
	case BoundaryCompatible:
		return true, nil
	case BoundaryIncompatible:
		return false, nil
	case BoundaryUnknown:
		return m == FuzzyBoundaryLegacy, nil
	default:
		return false, fmt.Errorf("invalid boundary compatibility %q", c)
	}
}
