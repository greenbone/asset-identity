# SPEC-001: Asset Identifiers

**Status:** Draft  
**Component:** asset-identity  
**Scope:** Identifier representation, equality, observation history, and classification policy

## 1. Purpose

Define a reusable, extensible asset identifier model for the Greenbone asset identity library.

The core must be a native Go package usable by gvmd-lite and suitable for use by gvmd through a future, separate C adapter.

This specification does not define asset matching or merging. Identifier-value equality alone does not establish asset identity.

## 2. Requirements

### REQ-001: Multiple identifiers

An asset observation or candidate may contain multiple identifier types.

Each identifier type may have multiple values.

Equivalent values of the same type and scope must not be treated as distinct identifier values or create additional identity evidence solely through duplication. Repeated observations are handled separately under REQ-005 and REQ-008; this requirement does not define matching scores or evidence weighting.

### REQ-002: Strong identifiers

The authoritative Greenbone default strong identifier priority, highest first, is:

1. Greenbone ID
2. Agent ID
3. Machine ID
4. BIOS UUID
5. SSH host key
6. TLS certificate public-key hash
7. Cloud identifier

The priority order must be configurable and absolute within the selected policy. It must not depend on input order or the order in which identifier types are defined.

Priority must be represented by policy rather than hardcoded into future reconciliation logic. Priority configurations must reject duplicate type entries and unknown identifier types. A known type is one supported by the library version in use.

The treatment of omitted types and classification overrides remains an open decision. The meaning of priority when matching or conflicting evidence is encountered belongs to a subsequent specification.

### REQ-003: Other identifiers

Support these additional identifiers:

- IP
- FQDN
- MAC
- Hostname

These identifiers are designated for weak/fuzzy matching under a separate policy. That policy's behavior is outside this specification.

### REQ-004: Extensibility

Identifier types must use stable string identifiers rather than require callers to rely on numeric enum positions. The exact string identifiers remain an open decision.

Adding a supported identifier type in a future library version must not require changing the generic identifier model or rewriting future matching algorithms.

Each supported type must have an explicit value, scope, validation, normalization, and equality contract. Identifier classification and priority must be defined by policy rather than by hardcoded matching logic.

Runtime identifier registration is not part of this specification and must not be implemented for now. Handling unknown types in identifier input, separately from priority configuration, remains an open decision.

### REQ-005: Identifier observations and history

An identifier value must support:

- Identifier type
- Identifier value
- Identifier scope or namespace, where applicable

Each observation of an identifier value must support an observation timestamp or an explicitly missing timestamp. Present timestamps must represent UTC instants and denote when the identifier was observed, rather than when it was ingested. Missing timestamps must not be inferred from a sentinel instant or replaced with the current time.

Observation history must be kept separate from identifier-value equality. Repeated observations of the same identifier value may carry different timestamps without becoming distinct identifier values. The history representation and handling of repeated observations remain open decisions.

Identifier values must not be discarded solely because newer observations contain different values.

### REQ-006: Normalization

Identifier-value comparison must use semantically correct equality as defined under REQ-008.

Exact type-specific normalization rules remain open for separate approval. No implementation may silently choose those rules. Before a type's normalization is implemented, its contract must explicitly define accepted inputs, validation, canonical representation, scope handling, and equality behavior.

Normalization must be deterministic, idempotent, and independently testable, and must preserve meaningful distinctions between values.

Do not assume that identifiers are globally unique.

Do not automatically normalize opaque identifiers using generic lowercase or whitespace transformations.

### REQ-007: Independence

The identifier model must not depend on:

- PostgreSQL or other databases
- GLib
- gvmd
- gvmd-ng (gvmd-lite)
- HTTP or gRPC
- C
- cgo

The core must remain a native Go package.

### REQ-008: Identifier-value equality

Identifier-value equality must account for the stable type identifier, the value under that type's approved normalization rules, and the scope under that type's approved scope rules.

Observation timestamps and observation history must not participate in identifier-value equality.

The representation and comparison of scopes, including absent versus empty scope, remain open decisions. An absent scope must not silently assert global uniqueness.

### REQ-009: Future C adapter compatibility

The model must allow a future, separate C adapter to preserve stable type identifiers, all required identifier values and scopes, observation history, and UTC timestamps including explicitly missing timestamps without loss of meaning or required precision.

The core must not expose a C dependency to achieve this compatibility. C bindings, ABI layout, memory ownership, and lifetime rules belong to a separate specification; native Go memory layouts are not a C ABI contract.

## 3. Acceptance Criteria

- [ ] All defined identifier types can be represented using stable string type identifiers.
- [ ] Multiple values of the same identifier type are supported.
- [ ] Identifier scopes can be represented, including values in different scopes.
- [ ] UTC observation timestamps and explicitly missing timestamps can be represented distinctly.
- [ ] Identifier-value equality is independent of observation timestamps and history.
- [ ] Equivalent values of the same type and scope do not become distinct identifier values solely through duplication.
- [ ] Observation history is represented separately without silently discarding timestamp information under an unapproved aggregation rule.
- [ ] Different values are not discarded solely because newer observations contain different values.
- [ ] Strong identifier priorities are configurable, absolute, and independent of input order.
- [ ] The default priority exactly matches the authoritative order in REQ-002.
- [ ] Duplicate and unknown type entries in priority configurations are rejected.
- [ ] A new supported type can be added without changing the generic identifier model or future matching algorithms.
- [ ] Runtime identifier registration is not implemented.
- [ ] Once approved, type-specific validation rejects invalid inputs and normalization can be tested independently for determinism, idempotence, equality, and preserved distinctions.
- [ ] All required data has a lossless mapping suitable for a future C adapter without defining bindings here.
- [ ] The core builds and its tests run with `CGO_ENABLED=0`, without C, GLib, or database dependencies.

## 4. Out of Scope

- Candidate selection
- Strong identifier matching
- Weak/fuzzy matching
- Matching scores or evidence weighting
- Conflict-resolution rules
- Freshness-based selection
- Asset merging
- Asset counting
- Database operations and persistence implementation
- Runtime identifier registration
- C bindings

Any future work in these areas requires separate specifications or approval.

## 5. Open Decisions

- Exact stable string identifiers for the supported types.
- Exact type-specific validation, normalization, and canonical representations, including accepted input encodings.
- Scope structure and comparison, absent versus empty scope, and namespace requirements for each type, including Agent ID and cloud identifiers.
- Observation-history representation and handling of repeated observations, including explicitly missing timestamps.
- Timestamp precision, supported range, and external encoding.
- Treatment of omitted types in priority configurations, disabling types, and classification overrides.
- Handling unknown identifier types in identifier input; priority configurations must reject them.
- Validation and handling of invalid BIOS UUIDs or placeholder values.
- SSH host key representation, including key material versus fingerprints and algorithm information.
- TLS certificate public-key hash definition, including hashed material, digest algorithm, and encoding.
- IP address forms, IPv4-mapped IPv6 treatment, and zone handling; DNS case, trailing-dot, and internationalized-name rules; MAC forms; hostname semantics.
- Error reporting and batch rejection versus partial acceptance for invalid input.

Do not silently resolve these decisions during implementation.
