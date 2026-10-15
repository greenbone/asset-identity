# SPEC-001A: Native Go Identifier Model

**Status:** Approved — native Go model contract  
**Component:** asset-identity  
**Parent:** [SPEC-001: Asset Identifiers](SPEC-001-identifiers.md)  
**Scope:** Native Go data representation, structural validation, and equality boundaries

## 1. Authority and approved scope

SPEC-001 is authoritative. This document finalizes its native Go data model following explicit approval of the choices
below. It resolves only the parent's model-specific open decisions and does not amend the parent document.

The following are inherited requirements: stable string type identifiers; multiple values; scopes; UTC observation
timestamps with explicit missingness; separation of identifier values from observation history; no runtime registration;
a native Go core; and lossless suitability for a future C adapter.

The names, representations, structural comparison, timestamp range and precision, and error contracts below are approved
for implementation. Type-specific normalization and semantic equality remain open. Go snippets describe the public data
model and examples.

## 2. Approved identifier type names

Use a defined string type and constants for the types supported by this library version:

```go
type IdentifierType string

const (
TypeGreenboneID       IdentifierType = "greenbone_id"
TypeAgentID           IdentifierType = "agent_id"
TypeMachineID         IdentifierType = "machine_id"
TypeBIOSUUID          IdentifierType = "bios_uuid"
TypeSSHHostKey        IdentifierType = "ssh_host_key"
TypeTLSPublicKeyHash  IdentifierType = "tls_certificate_public_key_hash"
TypeCloudIdentifier   IdentifierType = "cloud_identifier"
TypeIP                IdentifierType = "ip"
TypeFQDN              IdentifierType = "fqdn"
TypeMAC               IdentifierType = "mac"
TypeHostname          IdentifierType = "hostname"
)
```

Approved names are exact and case-sensitive. Validation does not trim, lowercase, or accept aliases for type names. The
empty string is an unknown type.

**Rationale:** String constants are readable, work across language boundaries, and avoid dependence on enum numbering.
Existing names remain stable; future library versions can add constants and their type contracts. There is no runtime
registry.

The declaration order follows the parent's default strong priority for readability only. It must not be used as a
priority mechanism. Classification and configurable priority remain separate from these data types.

## 3. Approved data types

```go
// Scope is a set of named namespace dimensions.
// nil means absent; a non-nil empty map means explicitly present and empty.
type Scope map[string]string

type IdentifierValue struct {
Type  IdentifierType
Value string
Scope Scope
}

type IdentifierObservation struct {
Identifier IdentifierValue
ObservedAt *time.Time // nil means explicitly missing
}

type ObservationHistory []IdentifierObservation
```

The snippets use the standard library's `time` package. No interfaces, generic metadata containers, registry objects, C
types, or database types are required.

Use `[]IdentifierValue` when a collection of identifier values is needed. It supports any number of values per type and
values in different scopes. Do not use `map[IdentifierType]IdentifierValue`, which would overwrite additional values of
a type.

`Value` preserves its supplied bytes without normalization or parsing. A Go string can carry text or bytes; choosing
accepted encodings for particular types remains subject to separate approval. This model does not choose SSH key, TLS
hash, UUID, or address encodings.

**Rationale:** Separate structs keep observation metadata out of value equality. Ordinary slices support multiple values
without an additional collection framework. Copying an identifier into each observation avoids index references and
their integrity rules.

### 3.1 Structured scopes

Use named string dimensions rather than a single concatenated namespace string. For example, a cloud scope could be:

```go
Scope{
"provider": "example-cloud",
"account":  "account-17",
"region":   "region-a",
}
```

These dimension names are illustrative, not an approved cloud namespace contract. Which dimensions are required,
permitted, or meaningful for each identifier type remains open.

Approved generic scope rules:

- A scope has at most one value per dimension, as represented by the map.
- Dimension names must be nonempty. Dimension names and values are otherwise compared exactly; there is no generic
  trimming or case folding.
- Empty dimension values are representable and differ from absent dimensions. Whether a type permits them remains open.
- Map insertion and iteration order do not affect scope equality.
- Absent scope (`nil`) and explicitly present empty scope (`Scope{}`) remain distinct. Neither denotes a wildcard or
  asserts global uniqueness.

**Rationale:** Named dimensions accommodate different namespace structures without fixing provider, tenant, network, or
agent-specific fields into the core struct. Keeping absence distinct from explicit emptiness preserves information until
type-specific scope semantics are approved.

### 3.2 Observation timestamps

Use an optional `*time.Time`:

- `nil` means the observation timestamp is explicitly missing.
- A non-nil pointer means present, including a pointer to Go's zero time. `IsZero()` must not be used to infer
  missingness.
- Present times retained by validated input constructors are stored in UTC with nanosecond precision, without a
  monotonic-clock component. Directly constructed input may contain other timezone offsets.
- Use a supported UTC year range of 1 through 9999 inclusive; out-of-range times produce a validation error. Unix epoch
  and pre-epoch times are valid.
- Offset-bearing input is converted to the same UTC instant; it is not reinterpreted as UTC wall time. UTC conversion
  must not change precision or supply a missing timestamp.
- Observation order and validity do not depend on whether timestamps are missing, equal, or chronological. No freshness
  rule is implied.

**Rationale:** A pointer provides idiomatic explicit optionality without reserving an instant as a sentinel. Nanosecond
precision avoids premature truncation. The approved bounded year range permits conventional timestamp representations
while still preserving a present zero time. This document approves the range and precision; external timestamp encoding
remains open.

UTC conversion removes Go's process-local monotonic reading; that reading is not observation-history data. See
the [Go time documentation](https://pkg.go.dev/time#hdr-Monotonic_Clocks). External timestamp encoding remains open.

### 3.3 Ownership and mutation

These approved structs are mutable Go data. Copying a struct does not deep-copy its scope map or timestamp pointer.
Every library API retaining caller-provided data, including constructors returning owned observations or histories, must
defensively copy the scope map and timestamp value so later caller mutation cannot alter retained identifiers or
history. Copying an absent scope must preserve absence.

No automatic concurrency protection or global mutable state is approved. Callers synchronize concurrent mutation of
their own data.

## 4. Identifier-value equality

The parent requires semantic equality under approved type-specific value and scope rules. Those rules remain open. This
document must not substitute byte equality for that semantic contract.

Provide a separate, clearly named structural operation, `SameRepresentation(a, b IdentifierValue) bool`, for model tests
and callers that deliberately need exact representation comparison. For structurally valid inputs it returns true
exactly when:

1. Type strings are equal.
2. Value strings contain identical bytes.
3. Scope presence is equal and all scope dimension names and values are equal, independent of map order.

The operation neither normalizes nor validates its operands. Validation is a separate boundary. Even if identical
invalid inputs compare structurally equal, that result does not make them valid identifiers.

Timestamps, history length, history order, and repeated observations are excluded from identifier-value equality. Do not
compare `IdentifierValue` with Go's `==`; its scope map requires explicit comparison.

When representations differ, `SameRepresentation` returning false does not establish semantic inequality. For example,
differently formatted IP strings might later normalize to the same value under an approved contract. Semantic equality
and semantic deduplication remain deferred until the applicable type contracts are approved. No generic `Equal`
operation claiming semantic equality is approved at this stage.

**Rationale:** Exact representation comparison is testable without silently resolving normalization. A separate name
makes its limited guarantee explicit.

## 5. Observation history and multiple values

Represent supplied history as an ordered slice of observations. Preserve supplied sequence order without interpreting it
as timestamp order or priority.

Each history entry contains an identifier value and its own present or missing timestamp. Reobserving the same value
adds observation metadata, not a new distinct identifier value. Construction and copying preserve supplied entries,
including identical entries, because no event identifier or history aggregation rule exists. This does not require
callers to retain all observations indefinitely.

No implicit sorting, replacement by the newest value, timestamp aggregation, or history deduplication is approved.
Different values remain representable together. `ObservationHistory` is only an in-memory representation. The library
does not require unlimited observation retention. Callers own persistence, retention limits, pruning, and lifecycle
decisions; the model itself does not apply those policies.

An ordinary `[]IdentifierValue` does not enforce uniqueness by itself. Consumers must not count duplicate
representations or repeated observations as additional identity evidence. It is possible to identify exact duplicate
representations now; semantic duplicates require the later approved normalization contracts. No matching or
evidence-counting algorithm is defined here.

**Rationale:** Retaining observations avoids losing timestamps while keeping distinct-value semantics separate. It also
avoids imposing first-seen/last-seen summaries or an event store on the core model.

## 6. Approved validation and error behavior

Direct struct construction can represent invalid input; it does not imply validation. Validated input constructors check
structural validity at the input boundary. Plain struct construction, cloning, timestamp normalization, and structural
comparison remain separate operations and do not imply validation. Approved model validation covers only:

- A type name from the supported constant set.
- Nonempty scope dimension names, when a scope is present.
- Present observation times whose UTC instant lies within the approved range, regardless of the input timezone offset.

Validation accepts valid `time.Time` values with any timezone offset and checks the UTC instant without modifying the
input. Timestamp normalization is a separate operation: it copies a present time and converts it to UTC without
validating it. Validated constructors normalize a defensive copy at the input boundary and then validate that copy.
Missing timestamps remain `nil` throughout. Type-specific validity, including empty values and placeholders, remains
open; passing model validation does not certify type-specific validity.

Provide errors identifiable with `errors.Is`:

| Error category              | Approved behavior                                                                                                                                             |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ErrUnknownIdentifierType`  | Reject unknown, empty, or misspelled type names; include the rejected type in diagnostic context. Do not silently ignore, register, coerce, or classify them. |
| `ErrInvalidScope`           | Reject an empty dimension name; identify the affected field. Per-type scope validation remains deferred.                                                      |
| `ErrInvalidObservationTime` | Reject an instant outside the approved UTC year range. Different timezone offsets are accepted. A missing timestamp is valid.                                 |

Batch validation must return the first error in slice order with its entry index, without returning a partially accepted
batch or mutating caller data. Where multiple scope keys are invalid, diagnostics must not depend on map iteration
order. Invalid input returns an error rather than causing a panic.

**Rationale:** Strict unknown-type handling catches integration mistakes without introducing runtime registration.
Recognizable errors avoid string matching. Rejecting a batch at the validation boundary avoids accidental silent data
loss; callers can explicitly validate individual entries if needed. These resolve the parent's unknown-input and model
error-behavior decisions for this package.

### 6.1 Minimal public operations

The `identity` package provides these operations in addition to the data types:

```go
func (v IdentifierValue) Validate() error
func (v IdentifierValue) Clone() IdentifierValue
func (o IdentifierObservation) Validate() error
func (o IdentifierObservation) Clone() IdentifierObservation
func (o IdentifierObservation) Normalize() IdentifierObservation
func (h ObservationHistory) Validate() error
func (h ObservationHistory) Clone() ObservationHistory
func SameRepresentation(a, b IdentifierValue) bool
func NewObservation(v IdentifierValue, observedAt *time.Time) (IdentifierObservation, error)
func NewObservationHistory(input ObservationHistory) (ObservationHistory, error)
```

`Clone` defensively copies maps, timestamp values, and history slices, preserving nil versus non-nil empty collections.
It does not validate or normalize. `Normalize` returns a defensive copy with UTC timestamps and no monotonic reading; it
does not change type names, payloads, or scopes, and does not validate. `Validate` never mutates input and checks types
before scopes, then timestamps for observations. All validation errors wrap the documented categories.

`NewObservation` normalizes a defensive copy and validates it. `NewObservationHistory` does the same for every supplied
entry, returning the first error with its zero-based entry index and no partial history. Neither constructor stores
global state or enforces a retention policy.

## 7. Representative examples

The following is an illustrative function-body fragment, not an implementation. Scope names and payloads demonstrate
representation only, not approved type-specific validity.

```go
agent := IdentifierValue{
Type:  TypeAgentID,
Value: "agent-42",
Scope: Scope{"namespace": "deployment-a"},
}

values := []IdentifierValue{
{Type: TypeIP, Value: "192.0.2.10", Scope: Scope{"network": "network-a"}},
{Type: TypeIP, Value: "192.0.2.11", Scope: Scope{"network": "network-a"}},
{Type: TypeIP, Value: "192.0.2.10", Scope: Scope{"network": "network-b"}},
agent,
}

first := time.Date(2026, 10, 14, 8, 0, 0, 123456789, time.UTC)
later := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
history := ObservationHistory{
{Identifier: agent, ObservedAt: &first},
{Identifier: agent, ObservedAt: &later},
{Identifier: agent, ObservedAt: nil},
}

absentScope := IdentifierValue{Type: TypeMachineID, Value: "machine-7"}
emptyScope := IdentifierValue{Type: TypeMachineID, Value: "machine-7", Scope: Scope{}}

zero := time.Time{}.UTC()
presentZero := IdentifierObservation{Identifier: agent, ObservedAt: &zero}
missingTime := IdentifierObservation{Identifier: agent, ObservedAt: nil}

unknown := IdentifierValue{Type: IdentifierType("future_type"), Value: "x"}
```

Expected outcomes under this contract:

- `values` holds three IP representations, including the same address in two different scopes; none overwrites another.
- `history` contains three observations of one identifier-value representation. Their timestamp differences do not
  change identifier-value equality.
- `absentScope` and `emptyScope` have different representations; no wildcard or global-uniqueness interpretation
  follows.
- `presentZero` and `missingTime` have equal identifier representations but different timestamp-presence states.
- Validation of `unknown` returns an error recognizable as `ErrUnknownIdentifierType`.

## 8. Future C API suitability

No C bindings or ABI layout are approved. A future adapter must preserve the logical data described here:

- Exact type and value bytes, including embedded zero bytes where permitted by the eventual type contract.
- Scope absence versus an explicitly empty scope and every dimension name/value pair. Map order carries no meaning.
- Every history entry, supplied sequence order, and the identifier representation associated with each entry.
- Timestamp presence, UTC instant, and nanosecond precision throughout the approved range, including present zero and
  pre-epoch instants.

The adapter must not flatten structured scopes ambiguously, collapse history into a latest timestamp, or turn missing
timestamps into zero instants. String lengths and timestamp presence must remain recoverable; Go memory layouts are not
the external contract.

A lossless timestamp mapping need not use one signed nanosecond count since the Unix epoch, which would not cover the
approved range. A later adapter specification will choose a suitable encoding, ownership, and lifetime rules. No
C-specific fields belong in these Go types.

## 9. Testable acceptance criteria

These criteria are requirements for the approved native Go model. Logical export/import here means exercising
field-preserving model copies, not implementing an external encoding or C adapter.

- [ ] Each of the eleven type constants has exactly the approved stable string value; unknown, empty, mixed-case, and
  whitespace-altered names fail model validation.
- [ ] Two values of the same type and two equal payloads in different scopes coexist in a collection without
  replacement.
- [ ] Scope dimensions compare independently of insertion order; changed, missing, or extra dimensions change
  representation equality.
- [ ] Absent scope differs from explicitly empty scope; an empty dimension value differs from an absent dimension; empty
  dimension names fail validation.
- [ ] `SameRepresentation` tests type, value bytes, and scope only; case and whitespace in payloads are preserved rather
  than normalized.
- [ ] Structural comparison is reflexive, symmetric, and transitive; it makes no semantic claim about differently
  formatted values.
- [ ] Repeated observations with different, equal, or missing timestamps leave identifier-value comparison unchanged and
  preserve every supplied history entry during construction and copying without imposing unlimited caller retention.
- [ ] Newer observations of different values do not remove older values or history entries.
- [ ] A nil timestamp differs from a present zero time; UTC epoch and pre-epoch times are accepted.
- [ ] Offset conversion preserves the instant and nanoseconds; different timezone offsets pass validation without
  mutation, and out-of-range UTC instants fail validation without supplying missing timestamps.
- [ ] Retaining data copies maps and timestamp values; mutating caller-owned inputs cannot alter retained data, and
  scope missingness survives copying.
- [ ] Validation errors support `errors.Is`; batch failures identify the first invalid entry and produce no partial
  result or input mutation.
- [ ] Adding a supported type in a later version requires no changes to the generic structs or structural comparison
  rules and exposes no runtime registration API.
- [ ] A logical export/import test preserves every value, scope dimension and presence state, history entry, and
  timestamp presence/precision at range boundaries, without requiring C bindings.
- [ ] The model package builds and its tests pass with `CGO_ENABLED=0`, using no C, GLib, database, or
  application-specific dependency.

## 10. Remaining open decisions

Stable names, map-based scope and presence semantics, optional `time.Time`, timestamp range and precision, exact
representation comparison, defensive copying, caller-controlled retention, and model validation/error contracts are
resolved by this approved specification.

Type-specific normalization, payload encodings and validity, placeholder handling, required scope dimensions, and
semantic equality remain unresolved. External serialization and C adapter contracts remain separate work. Classification
overrides, omitted priority types, and disabling types are not resolved here.

Matching scores, strong or weak matching, candidate selection, asset merging, database operations, runtime registration,
and C adapter implementation are outside this document's scope.
