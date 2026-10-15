package identity

import "fmt"

// BoundaryContext describes one logical identity namespace for a matching view.
// Nonempty BoundaryIDs MUST be caller-resolved qualified compatibility-class keys:
// equivalent contexts have identical keys and distinct keys identify known
// incompatible namespaces. The library does not validate a qualification grammar,
// trust arbitrary raw strings, resolve aliases, or infer a key from ScannerID.
// Missing/unresolved context MUST be supplied with an empty BoundaryID. Callers
// partition historical evidence by boundary before using matching foundations.
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

// CompareBoundaries compares only caller-resolved keys under BoundaryContext's
// input assumption. It cannot establish that nonempty raw strings are qualified.
// Missing either key produces UNKNOWN, including both-missing and same scanner.
// Strong cross-boundary eligibility is intentionally not provided by this helper.
func CompareBoundaries(a, b BoundaryContext) BoundaryCompatibility {
	if a.BoundaryID == "" || b.BoundaryID == "" {
		return BoundaryUnknown
	}
	if a.BoundaryID == b.BoundaryID {
		return BoundaryCompatible
	}
	return BoundaryIncompatible
}

// FuzzyBoundaryMode governs boundary admission into fuzzy selection and merge
// evaluation only. It does not grant independent merge safety or strong trust.
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

// Admit applies the same boundary gate to fuzzy selection and merge evaluation.
// Legacy admits UNKNOWN without changing compatibility or establishing identity.
// Callers must still apply containment and independently approved merge safety.
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
