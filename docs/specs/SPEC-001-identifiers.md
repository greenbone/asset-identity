# SPEC-001: Asset Identifiers

The library normalizes identifiers and returns CREATE or REUSE.
It also returns a merge plan when a strong match permits merges.
The Go and GLib C APIs use the same algorithm.

## Requirements

- Accept several identifier types and several values per type.
- Compare the type and normalized value. Repeated values add no evidence.
- Reuse a key through the highest-priority shared strong match.
- Keep assets separate when a relevant strong identifier conflicts.
- Try continuity matching, then fuzzy matching, if no strong match selects a key.
- Exclude an asset with a strong conflict from later stages.
- Permit merges only at the strong stage.
- Return an error for invalid input.
- Keep caller data unchanged and return independently owned results.
- Exclude timestamps and history from identifier equality.
- Keep the Go core independent of C, databases, and network services.
- Support `CGO_ENABLED=0`.

## Application responsibilities

The application supplies eligible identifiers and stored scan snapshots.
It enforces access, scope, freshness, and retention rules.
It creates keys, stores evidence, and applies merges.

The library does not discover assets, verify trust in identifier sources, or store results.
Matching identifiers do not establish global uniqueness.

## Specifications

| Specification                              | Content                                                 |
| ------------------------------------------ | ------------------------------------------------------- |
| [SPEC-001A](SPEC-001A-identifier-model.md) | Types, timestamps, history, and ownership               |
| [SPEC-001B](SPEC-001B-normalization.md)    | Accepted formats, normalization, and equality           |
| [SPEC-002](SPEC-002-reconciliation.md)     | Policy, snapshots, matching, merge plans, and the C API |

Tests are in [identity](../../identity) and [tests/c](../../tests/c).
