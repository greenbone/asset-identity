# SPEC-001: Asset Identifiers

The library normalizes identifiers, chooses `CREATE` or `REUSE`, and returns candidates to merge. Go and GLib C callers
use the same algorithm.

## Requirements

- Accept multiple identifier types and multiple values per type.
- Compare type, canonical value, and complete scope. Duplicates add no evidence.
- Reuse a key through the highest-priority shared strong match, and let the application store new evidence on that key.
- Keep conflicting stronger identities separate and merge compatible existing records.
- Use weak containment only when the observation has no configured strong IDs.
- Return an error for invalid input. Preserve caller data and return independently owned results.
- Keep timestamps and history separate from identifier equality.
- Keep the Go core independent of C, databases, and network services; it must work with `CGO_ENABLED=0`.

Applications supply eligible active identifiers and candidates, enforce scope and access boundaries, create keys, retain
evidence, and apply merges. The library does not discover assets, verify producer trust, or store results.

## Contracts

| Specification                              | Defines                                           |
|--------------------------------------------|---------------------------------------------------|
| [SPEC-001A](SPEC-001A-identifier-model.md) | Types, scopes, timestamps, history, and ownership |
| [SPEC-001B](SPEC-001B-normalization.md)    | Accepted formats, normalization, and equality     |
| [SPEC-002](SPEC-002-reconciliation.md)     | Policy, matching, merge plans, and the C API      |

Supported formats are explicit; the library does not guess conversions or global uniqueness. Tests live in [
`identity`](../../identity) and [`tests/c`](../../tests/c).
