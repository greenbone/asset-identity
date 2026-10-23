# SPEC-001A: Identifier Model

This document defines the data model in [`identity/model.go`](../../identity/model.go). Payload normalization is defined
in [SPEC-001B](SPEC-001B-normalization.md).

## Data types

```go
type IdentifierType string
type Scope map[string]string

type IdentifierValue struct {
Type  IdentifierType
Value string
Scope Scope
}

type IdentifierObservation struct {
Identifier IdentifierValue
ObservedAt *time.Time
}

type ObservationHistory []IdentifierObservation
```

Use `[]IdentifierValue` for collections so multiple values of one type remain representable. Type names are exact,
case-sensitive strings; declaration order does not define matching priority.

| Go constant            | Type name                         |
|------------------------|-----------------------------------|
| `TypeGreenboneID`      | `greenbone_id`                    |
| `TypeAgentID`          | `agent_id`                        |
| `TypeMachineID`        | `machine_id`                      |
| `TypeBIOSUUID`         | `bios_uuid`                       |
| `TypeSSHHostKey`       | `ssh_host_key`                    |
| `TypeTLSPublicKeyHash` | `tls_certificate_public_key_hash` |
| `TypeCloudIdentifier`  | `cloud_identifier`                |
| `TypeIP`               | `ip`                              |
| `TypeFQDN`             | `fqdn`                            |
| `TypeMAC`              | `mac`                             |
| `TypeHostname`         | `hostname`                        |

## Scope and equality

Scope dimensions use exact names and values. Names must be nonempty; values may be empty. Map order does not matter.
Missing dimensions differ from empty values, and `nil` scope differs from `Scope{}`. Neither absent nor empty scope is a
wildcard or a claim of global uniqueness.

`SameRepresentation(a, b)` compares type, payload bytes, and complete scope without validation or normalization. Use
`EqualIdentifiers` from SPEC-001B for semantic equality. Timestamps and history never participate in either comparison.

## Timestamps and history

- `nil` means missing. A non-nil Go zero time is present.
- Present timestamps must fall within UTC years 1–9999. Epoch and pre-epoch times are valid.
- Timestamp normalization preserves the instant and nanoseconds, converts to UTC, and removes monotonic-clock data.
- History preserves supplied entry order and duplicates. It does not sort, aggregate, replace, or expire observations.
  Applications own retention and choose the active values used for matching.

## Operations and errors

| Operation                         | Behavior                                                                                        |
|-----------------------------------|-------------------------------------------------------------------------------------------------|
| `IdentifierValue.Validate`        | Check supported type and nonempty scope dimension names; do not inspect payload syntax          |
| `IdentifierObservation.Validate`  | Check the identifier structure and present timestamp range                                      |
| `ObservationHistory.Validate`     | Return the first invalid entry with its zero-based index                                        |
| `Clone` methods                   | Copy maps, timestamp storage, and history entries; preserve nil/empty distinctions and timezone |
| `IdentifierObservation.Normalize` | Clone and normalize only the timestamp; do not validate or normalize the payload                |
| `NewObservation`                  | Copy, normalize the timestamp, and validate; return a zero observation on error                 |
| `NewObservationHistory`           | Apply the constructor to each entry; return nil and the first indexed error on failure          |

Direct struct construction does not validate input. Structural errors support `errors.Is`:
`ErrUnknownIdentifierType`, `ErrInvalidScope`, and `ErrInvalidObservationTime`. Validation is deterministic and does not
mutate input or return partially accepted histories.

Callers must synchronize their own mutations. Library copies must not share mutable scope maps or timestamp storage with
inputs. The C reconciliation API and its ownership rules are defined in [SPEC-002](SPEC-002-reconciliation.md#c-api).
