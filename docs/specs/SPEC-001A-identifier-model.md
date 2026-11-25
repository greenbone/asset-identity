# SPEC-001A: Identifier Model

[model.go](../../identity/model.go) defines the Go identifier types.
[SPEC-001B](SPEC-001B-normalization.md) defines accepted values.

## Data types

| Type                    | Content                                                  |
| ----------------------- | -------------------------------------------------------- |
| `IdentifierValue`       | `Type` and raw string `Value`                            |
| `IdentifierObservation` | An `IdentifierValue` and optional `ObservedAt` timestamp |
| `ObservationHistory`    | An ordered slice of `IdentifierObservation` values       |

Use `[]IdentifierValue` to supply several values of the same type.
Type names are case-sensitive.
Their declaration order does not set matching priority.

| Go constant            | Type name                         |
| ---------------------- | --------------------------------- |
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
| `TypeImageReference`   | `image_reference`                 |

## Equality

`SameRepresentation` compares the type and raw value without validation.
`EqualIdentifiers` compares normalized types and values.
Neither function compares timestamps or history.

## Timestamps and history

`nil` means that a timestamp is missing.
A non-nil Go zero time is present.
Present times must be within UTC years 1–9999.
Unix epoch and pre-epoch times are valid.

Timestamp normalization converts to UTC and removes monotonic-clock data.
It preserves nanoseconds.
History preserves input order and repeated entries.
The application controls retention and decides which values remain active.

## Snapshot candidates

`Decide` takes candidates that each represent one stored scan snapshot.
All identifiers in a candidate share its `LastSeen` observation time.
Several snapshots can have the same asset key.
`Decide` does not take an `ObservationHistory` argument.
See [SPEC-002](SPEC-002-reconciliation.md) for snapshot selection and conflict checks.

## Operations

| Operation                         | Behavior                                                                                                     |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `Validate` methods                | Check the supported type and any present timestamp. History returns the first error with its entry index.    |
| `Clone` methods                   | Copy timestamp storage and history. Preserve the time zone and the difference between nil and empty history. |
| `IdentifierObservation.Normalize` | Copy and normalize only the timestamp. Do not validate or normalize the identifier value.                    |
| `NewObservation`                  | Copy, normalize the timestamp, and validate. Return a zero `IdentifierObservation` on error.                 |
| `NewObservationHistory`           | Apply `NewObservation` to each entry. Return nil and the first indexed error on failure.                     |

Direct struct construction does not validate input.
Structural validation does not check identifier value syntax.

Errors support `errors.Is` with `ErrUnknownIdentifierType` and `ErrInvalidObservationTime`.
Operations do not change inputs or return partial histories.
Callers must prevent concurrent changes to shared inputs.
See [SPEC-002](SPEC-002-reconciliation.md#c-api) for C ownership rules.
