# SPEC-001A: Identifier Model

The Go types are defined in [`model.go`](../../identity/model.go). Payload formats are defined
in [SPEC-001B](SPEC-001B-normalization.md).

## Data types

| Type                    | Contents                                                      |
|-------------------------|---------------------------------------------------------------|
| `IdentifierValue`       | `Type`, raw string `Value`, and `Scope` (`map[string]string`) |
| `IdentifierObservation` | An identifier and optional `ObservedAt` timestamp             |
| `ObservationHistory`    | An ordered slice of identifier observations                   |

Use `[]IdentifierValue` to allow multiple values of the same type. Type names are case-sensitive; their declaration
order does not define matching priority.

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

Scope names and values are exact; names must be nonempty. Map order does not matter. A missing dimension differs from an
empty value; `nil` scope differs from `Scope{}`. Neither is a wildcard.

`SameRepresentation` compares type, raw value, and complete scope without validation.
`EqualIdentifiers` compares normalized values. Neither comparison includes timestamps or history.

## Timestamps and history

`nil` means a missing timestamp; a non-nil Go zero time is present. Present instants must fall within UTC years 1–9999;
epoch and pre-epoch times are valid. Timestamp normalization preserves nanoseconds, converts to UTC, and removes
monotonic-clock data. History keeps input order and duplicates; applications decide retention and active values.

## Operations and errors

| Operation                         | Behavior                                                                                              |
|-----------------------------------|-------------------------------------------------------------------------------------------------------|
| `Validate` methods                | Check supported type, scope names, and any present timestamp; history returns the first indexed error |
| `Clone` methods                   | Copy scopes, timestamp storage, and history; preserve nil/empty distinctions and timezone             |
| `IdentifierObservation.Normalize` | Clone and normalize only the timestamp; do not validate or normalize the payload                      |
| `NewObservation`                  | Copy, normalize the timestamp, and validate; return a zero observation on error                       |
| `NewObservationHistory`           | Apply the constructor to each entry; return nil and the first indexed error on failure                |

Direct struct construction does not validate. Structural validation does not check payload syntax. Errors support
`errors.Is`: `ErrUnknownIdentifierType`, `ErrInvalidScope`, and `ErrInvalidObservationTime`. Operations do not mutate
inputs or return partial histories; callers must synchronize their own mutations.
See [SPEC-002](SPEC-002-reconciliation.md#c-api) for C ownership.
