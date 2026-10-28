# SPEC-001B: Normalization and Equality

Normalization validates supported payload syntax and returns a canonical identifier. It does not establish producer
trust, global uniqueness, or eligibility for matching. The data model and structural validation are defined
in [SPEC-001A](SPEC-001A-identifier-model.md).

## API

```go
func ValidateIdentifier(value IdentifierValue) error
func NormalizeIdentifier(value IdentifierValue) (IdentifierValue, error)
func EqualIdentifiers(a, b IdentifierValue) (bool, error)
```

- `ValidateIdentifier` checks structure, format, and payload syntax without changing input.
- `NormalizeIdentifier` returns a canonical payload with an independently copied scope, or a zero value on error.
- `EqualIdentifiers` normalizes `a`, then `b`, and compares their type, canonical payload, and complete scope. Invalid
  input returns an error even when the types or scopes differ; errors from `a` take precedence.

Each identifier type has its own normalizer; it runs before any matching. Callers pass raw producer values and receive
the canonical value or an error. Normalization is deterministic and idempotent. It trims surrounding whitespace and
preserves type, scope bytes, and absent/empty scope distinctions. It performs no namespace inference, lookups, or history
processing. Existing structural `Validate` methods and observation constructors do not normalize payloads.

Placeholders are well-formed values that identify no single machine: values every machine or no machine carries, and
vendor defaults. `NormalizeIdentifier` and `ValidateIdentifier` report them as `ErrInvalidIdentifierValue`. `Decide`,
`EvaluateStrongPriority`, and `MatchingIdentifiers` leave them out instead of failing, so one such value in a report
neither fails nor influences a decision. Malformed values still fail.

## Supported formats

| Type                                     | Accepted input                                                    | Canonical payload                         | Placeholders                                                  |
|------------------------------------------|-------------------------------------------------------------------|-------------------------------------------|---------------------------------------------------------------|
| Greenbone ID, Agent ID, cloud identifier | Nonempty opaque string up to 2048 bytes                           | Exact bytes after trimming, case kept     | —                                                             |
| Machine ID, `kind=linux_machine_id`      | Exactly 32 hex digits                                             | Lowercase compact hex                     | All zero; `uninitialized` in any case                         |
| Machine ID, `kind=windows_machine_guid`  | UUID text as defined below                                        | Lowercase hyphenated UUID                 | All zero                                                      |
| BIOS UUID                                | UUID text as defined below                                        | Lowercase hyphenated UUID                 | All zero, all F, `03000200-0400-0500-0006-000700080009`       |
| SSH host key                             | Public-key line, optionally prefixed by a scanner port            | Algorithm and canonical padded base64 blob | —                                                             |
| TLS public-key hash                      | `x509:<base64-DER>` or `spki-sha256:<64 hex digits>`              | `spki-sha256:` and lowercase digest       | —                                                             |
| MAC                                      | 48-bit colon, hyphen, dotted, or compact hex                      | Six lowercase colon-separated octets      | All zero, broadcast                                           |
| IP                                       | IPv4 or IPv6 address, IPv4-mapped IPv6, optional IPv6 zone        | Canonical address text, unmapped, no zone | Unspecified, loopback, link-local, multicast, broadcast       |
| Hostname                                 | ASCII DNS name, single or qualified, non-numeric last label       | Lowercase; final dot removed only for multi-label names | `localhost`, `localhost.localdomain`                |
| FQDN                                     | ASCII DNS name with at least two labels and a non-numeric last label | Lowercase, no final dot                | `localhost.localdomain`                                       |

### Machine IDs and UUIDs

Machine IDs require the exact `Scope["kind"]` value shown in the table. Missing or unsupported kinds are errors; the
library does not infer the operating system. The kind remains part of scope and equality.

UUID input accepts compact 32-digit hex, `8-4-4-4-12` hyphenated hex, or the hyphenated form in braces. Inner
whitespace, URNs, and raw firmware bytes are unsupported. No version/variant allowlist or byte swapping is applied.

### SSH keys

Accept one `[port] <algorithm> <base64-blob> [comment]` line with space/tab separators; surrounding whitespace, line
ends included, is trimmed.
The optional scanner port is decimal, in 1–65535, and is removed during normalization; it is not part of key identity.
Supported algorithms are `ssh-ed25519`, `ssh-rsa`, and `ecdsa-sha2-nistp256/384/521`.

Require strict padded standard base64, agreement between the outer and embedded algorithm, complete parsing, and
canonical wire encoding. RSA moduli must be positive. Comments are removed. Fingerprints,
certificates, private keys, known-hosts records, unsupported algorithms, and additional lines are unsupported. Key
strength, ownership, and trust are outside normalization.

### TLS hashes

The digest represents SHA-256 over the certificate's exact DER SubjectPublicKeyInfo (`RawSubjectPublicKeyInfo` in Go).
Callers may pass either the tagged digest or `x509:` followed by one certificate encoded as strict padded standard
base64 DER on a single line. For a certificate, the library parses DER and calculates the SPKI hash internally. Output
is always `spki-sha256:<lowercase hex>`, so raw certificates and their canonical hashes compare equally. Certificate
renewal with the same public key preserves the identifier.

Normalization does not verify certificate names, signatures, trust, or validity. During matching, a certificate counts
only when its subject CN or a DNS SAN equals an FQDN or hostname of the same view ([SPEC-002](SPEC-002-reconciliation.md#strong-matching)). A supplied tagged digest cannot prove what the
producer hashed. Bare/base64 digests, certificate fingerprints, PEM, other tags, malformed DER, and trailing DER data
are unsupported. An all-zero tagged digest is syntactically valid.

### MAC and IP addresses

MAC input accepts six hex pairs with consistent colon/hyphen separators, three dotted groups of four hex digits, or
twelve compact hex digits. Other widths, mixed separators, and inner whitespace are rejected. Multicast MACs are kept.

IPv4 requires four decimal octets without leading zeroes except `0`. IPv6 supports compressed, expanded, and
embedded-IPv4 forms. IPv4-mapped IPv6 is unmapped to IPv4. An IPv6 zone must be nonempty and contain no whitespace or
additional `%`; it is dropped. Zones on IPv4, ports, brackets, CIDR, URLs, DNS names, and inner whitespace are rejected.
Private addresses are kept.

### Hostnames and FQDNs

Each label contains 1–63 ASCII letters, digits, hyphens, or underscores and neither starts nor ends with a hyphen. The
name excluding a final dot is at most 253 bytes. Empty labels, root-only names, IP literals, wildcards, raw Unicode
(Unicode case folding included), and DNS escapes are rejected. No IDNA conversion or alias expansion is performed.

`HOST.Example.` becomes `host.example` as hostname and as FQDN. A single-label absolute hostname keeps its dot: `HOST.`
becomes `host.`, distinct from `host`. A single-label name is unsupported as FQDN. A numeric last label in a
multi-label name is invalid for both types, so a malformed IP such as `192.168.1.010` is never read as a name.
Identically spelled hostname and FQDN values remain distinct because their types differ.

## Errors and verification

Check structural validity first, machine-format discrimination second, and payload syntax next. Errors support
`errors.Is`: `ErrUnknownIdentifierType`, `ErrInvalidScope`, `ErrInvalidIdentifierValue`, and
`ErrUnsupportedIdentifierFormat`. Empty payloads and placeholders are invalid. Unsupported producer formats require an
explicit contract rather than guessed conversions.

[`normalization_types_test.go`](../../identity/normalization_types_test.go) has one table per identifier type with
accepted, placeholder, and rejected values, and shows that placeholders take no part in a decision.
[`normalization_test.go`](../../identity/normalization_test.go) covers semantic equality, error precedence,
idempotency, scope copying, SSH key structure, and unchanged structural APIs. Tests use fixed inputs and run without cgo.
