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

Normalization is deterministic and idempotent. It preserves type, scope bytes, and absent/empty scope distinctions. It
performs no generic trimming, namespace inference, lookups, or history processing. Existing structural `Validate`
methods and observation constructors do not normalize payloads.

## Supported formats

| Type                                     | Accepted input                                                                | Canonical payload                                        |
|------------------------------------------|-------------------------------------------------------------------------------|----------------------------------------------------------|
| Greenbone ID, Agent ID, cloud identifier | Nonempty opaque string                                                        | Exact bytes, including case and whitespace               |
| Machine ID, `kind=linux_machine_id`      | Exactly 32 hex digits                                                         | Lowercase compact hex                                    |
| Machine ID, `kind=windows_machine_guid`  | UUID text as defined below                                                    | Lowercase hyphenated UUID                                |
| BIOS UUID                                | UUID text as defined below                                                    | Lowercase hyphenated UUID                                |
| SSH host key                             | Public-key line, optionally prefixed by a scanner port                        | Algorithm and canonical padded base64 blob               |
| TLS public-key hash                      | `x509:<base64-DER>` or `spki-sha256:<64 hex digits>`                          | Same exact tag and lowercase digest                      |
| MAC                                      | 48-bit colon, hyphen, dotted, or compact hex                                  | Six lowercase colon-separated octets                     |
| IP                                       | IPv4 or IPv6 address, with optional IPv6 zone                                 | Canonical address text; preserve address family and zone |
| Hostname                                 | Short or qualified ASCII DNS hostname                                         | Lowercase; remove final dot only for multi-label names   |
| FQDN                                     | Multi-label DNS hostname, or an absolute single-label name such as `example.` | Same DNS spelling rules; retain the FQDN type            |

### Machine IDs and UUIDs

Machine IDs require the exact `Scope["kind"]` value shown in the table. Missing or unsupported kinds are errors; the
library does not infer the operating system. The kind remains part of scope and equality.

UUID input accepts compact 32-digit hex, `8-4-4-4-12` hyphenated hex, or the hyphenated form in braces. Whitespace,
URNs, and raw firmware bytes are unsupported. No version/variant allowlist or byte swapping is applied. Zero and all-FF
UUIDs and zero machine IDs remain syntactically valid.

### SSH keys

Accept one `[port] <algorithm> <base64-blob> [comment]` line with space/tab separators and an optional final LF or CRLF.
The optional scanner port is decimal, in 1–65535, and is removed during normalization; it is not part of key identity.
Supported algorithms are `ssh-ed25519`, `ssh-rsa`, and `ecdsa-sha2-nistp256/384/521`.

Require strict padded standard base64, agreement between the outer and embedded algorithm, complete parsing, and
canonical wire encoding. RSA moduli must be positive. Comments and the final line ending are removed. Fingerprints,
certificates, private keys, known-hosts records, unsupported algorithms, and additional lines are unsupported. Key
strength, ownership, and trust are outside normalization.

### TLS hashes

The digest represents SHA-256 over the certificate's exact DER SubjectPublicKeyInfo (`RawSubjectPublicKeyInfo` in Go).
Callers may pass either the tagged digest or `x509:` followed by one certificate encoded as strict padded standard
base64 DER on a single line. For a certificate, the library parses DER and calculates the SPKI hash internally. Output
is always `spki-sha256:<lowercase hex>`, so raw certificates and their canonical hashes compare equally. Certificate
renewal with the same public key preserves the identifier.

Certificate names, signatures, trust, and validity are not verified. A supplied tagged digest cannot prove what the
producer hashed. Bare/base64 digests, certificate fingerprints, PEM, other tags, malformed DER, and trailing DER data
are unsupported. An all-zero tagged digest is syntactically valid.

### MAC and IP addresses

MAC input accepts six hex pairs with consistent colon/hyphen separators, three dotted groups of four hex digits, or
twelve compact hex digits. Other widths, mixed separators, and whitespace are rejected.

IPv4 requires four decimal octets without leading zeroes except `0`. IPv6 supports compressed, expanded, and
embedded-IPv4 forms. Mapped IPv6 remains distinct from IPv4; addresses are not unmapped. An IPv6 zone must be nonempty
and contain no whitespace or additional `%`; preserve it exactly. Zones on IPv4, ports, brackets, CIDR, URLs, DNS names,
and surrounding whitespace are rejected.

Syntactically valid zero, broadcast, multicast, loopback, private, or link-local addresses are accepted. Their
usefulness for identifying an asset is decided by the caller.

### Hostnames and FQDNs

Each label contains 1–63 ASCII letters, digits, or hyphens and starts/ends with a letter or digit. The name excluding a
final dot is at most 253 bytes. Empty labels, root-only names, IP literals, wildcards, underscores, raw Unicode, and DNS
escapes are rejected. No IDNA conversion or alias expansion is performed.

`HOST.Example.` becomes `host.example`. A single-label absolute name keeps its dot: `HOST.` becomes `host.`. Bare `host`
is valid as hostname but unsupported as FQDN. `hostname:host` and `hostname:host.` remain distinct; identically spelled
hostname and FQDN values also remain distinct because their types differ.

## Errors and verification

Check structural validity first, machine-format discrimination second, and payload syntax next. Errors support
`errors.Is`: `ErrUnknownIdentifierType`, `ErrInvalidScope`, `ErrInvalidIdentifierValue`, and
`ErrUnsupportedIdentifierFormat`. Empty payloads are invalid; no placeholder blacklist is applied. Unsupported producer
formats require an explicit contract rather than guessed conversions.

[`normalization_test.go`](../../identity/normalization_test.go) covers accepted/rejected formats, semantic equality,
error precedence, idempotency, scope copying, and unchanged structural APIs. Tests use fixed inputs and run without cgo.
