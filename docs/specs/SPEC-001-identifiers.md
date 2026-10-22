# SPEC-001: Asset Identifiers

The `identity` package provides a native Go identifier model, normalization, and asset-key selection. The GLib C API
calls the same reconciliation implementation.

## Requirements

- Support multiple types and multiple values per type.
- Identify values by type, canonical payload, and complete scope. Repeated values do not add evidence.
- Keep observation timestamps and history separate from identifier equality.
- Use configurable strong-ID priority, followed by fuzzy containment when no strong evidence is supplied.
- Return `CREATE` or `REUSE`; invalid input returns an error.
- Preserve caller data and return independent copies where data is retained or returned.
- Keep the Go core independent of C, GLib, databases, and network services.

The library does not generate keys, discover candidates, verify producer trust, manage persistence, retain history, or
apply database merges. Applications supply eligible active identifiers and candidates and apply the result.

## Contracts

| Specification                              | Defines                                                                  |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| [SPEC-001A](SPEC-001A-identifier-model.md) | Types, scopes, timestamps, history, ownership, and structural validation |
| [SPEC-001B](SPEC-001B-normalization.md)    | Supported payload formats, normalization, and semantic equality          |
| [SPEC-002](SPEC-002-reconciliation.md)     | Policy, strong/fuzzy matching, decisions, and the C API                  |

Type names and normalization do not establish global uniqueness or matching eligibility. New formats or matching rules
require an explicit contract; unsupported inputs are not guessed.

## Verification

Model, normalization, and reconciliation tests live in [`identity`](../../identity). The core must build and test with
`CGO_ENABLED=0`.
