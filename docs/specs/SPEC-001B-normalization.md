# SPEC-001B: Normalization and Equality

Normalization checks identifier value syntax and returns a canonical value.
A canonical value is the standard form used for comparison.
Normalization does not establish trust or uniqueness.
See [SPEC-001A](SPEC-001A-identifier-model.md) for the model.

## API

| Function              | Result                                                           |
| --------------------- | ---------------------------------------------------------------- |
| `ValidateIdentifier`  | Validate structure, format, and payload without changing input   |
| `NormalizeIdentifier` | Return the identifier with its canonical value, or zero on error |
| `EqualIdentifiers`    | Normalize both values and compare type and value                 |

Normalization removes surrounding whitespace and preserves the type.
The same input always gives the same result.
Normalizing an already normalized value does not change it.

Equality validates `a` before `b`, even if their types differ.
Structural `Validate` methods and observation constructors do not normalize identifier values.
Normalization does not perform lookups, infer namespaces, or process history.

## Supported formats

| Type                                     | Accepted input → canonical value                                                               |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Greenbone ID, Agent ID, cloud identifier | Nonempty opaque string, at most 2048 bytes → trimmed bytes, preserving case                    |
| Image reference                          | Same as above; the producer passes `registry/repository@sha256:<digest>`                       |
| Machine ID                               | 32 hex digits or hyphenated or braced UUID → 32 lowercase hex digits                           |
| BIOS UUID                                | Compact, hyphenated, or braced hyphenated UUID → lowercase hyphenated UUID                     |
| SSH host key                             | `[port] <algorithm> <base64-blob> [comment]` → algorithm and canonical padded base64 blob      |
| TLS public-key hash                      | `x509:<base64-DER>` or `spki-sha256:<64 hex digits>` → `spki-sha256:<lowercase digest>`        |
| MAC                                      | 48-bit colon, hyphen, dotted, or compact hex → six lowercase colon-separated octets            |
| IP                                       | IPv4 or IPv6, including mapped IPv4 and IPv6 zones → canonical address, unmapped, without zone |
| Hostname                                 | Single or qualified ASCII DNS name → lowercase; remove a final dot only for qualified names    |
| FQDN                                     | ASCII DNS name with at least two labels → lowercase, without final dot                         |

### Placeholders

`ValidateIdentifier` and `NormalizeIdentifier` reject these as `ErrInvalidIdentifierValue`:

- Machine IDs: all zero, and `uninitialized` in any case.
- BIOS UUIDs: all zero, all F, or `03000200-0400-0500-0006-000700080009`.
- MACs: all zero or broadcast.
- IPs: unspecified, loopback, link-local, multicast, or broadcast.
- Names: `localhost` (hostname) and `localhost.localdomain` (hostname or FQDN).

`Decide`, `EvaluateStrongPriority`, and `MatchingIdentifiers` omit placeholders. Malformed identifiers still fail.

### Machine IDs and UUIDs

A machine ID contains 128 bits.
Accept the 32 hex digits of a Linux machine-id or the UUID form of a Windows MachineGuid.
Both forms normalize to the same 32 lowercase hex digits.
The caller does not need to specify the operating system.

UUIDs accept these forms:

- 32 hex digits.
- Hyphenated `8-4-4-4-12` hex digits.
- The hyphenated form in braces.

Do not accept inner whitespace, URNs, or raw firmware bytes.
Do not swap bytes or filter UUID versions or variants.

### SSH keys

Accept one line with spaces or tabs between fields.
An optional decimal port must be 1–65535.
Remove the port and any comment from the normalized value.

Supported algorithms are `ssh-ed25519`, `ssh-rsa`, and `ecdsa-sha2-nistp256/384/521`.
Require these conditions:

- Strict padded standard base64.
- Matching outer and embedded algorithm names.
- Complete parsing and canonical wire encoding.
- Positive RSA moduli.

Do not accept additional lines, fingerprints, certificates, private keys, or known-hosts records.
Normalization does not assess key strength, ownership, or trust.

### TLS hashes

Hash the certificate's exact DER SubjectPublicKeyInfo with SHA-256.
An `x509:` input contains one DER certificate.
Encode it as strict padded standard base64 on one line.

Renewal with the same public key preserves the hash.
A raw certificate and its tagged hash normalize to the same value.
An all-zero tagged digest is syntactically valid.

Normalization does not check certificate names, signatures, trust, or validity dates.
During matching, accept a raw certificate only if its CN or a DNS SAN matches a hostname or FQDN in the same input record.
See the [certificate matching rules](SPEC-002-reconciliation.md#normalization).
Supplied tagged hashes remain eligible.
The library cannot verify what the caller hashed.

Do not accept bare or base64 digests, certificate fingerprints, PEM, other tags, malformed DER, or trailing DER data.

### MAC and IP addresses

MAC separators must be consistent.
Reject other widths, mixed separators, and inner whitespace.
Accept multicast MACs.

IPv4 requires four decimal octets.
Do not accept leading zeroes, except for the octet `0`.
IPv6 accepts compressed, expanded, and embedded-IPv4 forms.
An IPv6 zone must be nonempty and contain no whitespace or extra `%`.
Remove the zone from the normalized value.

Reject IPv4 zones, ports, brackets, CIDR, URLs, DNS names, and inner whitespace.
Accept private addresses.

### Hostnames and FQDNs

Labels contain 1–63 ASCII letters, digits, hyphens, or underscores.
A label cannot start or end with a hyphen.
The name without a final dot must be at most 253 bytes.
Qualified names cannot have a numeric final label.

Reject empty labels, root-only names, IP literals, wildcards, Unicode, and DNS escapes.
Do not convert IDNA names or expand aliases.

`HOST.Example.` becomes `host.example` for either type.
`HOST.` remains `host.` as a hostname and is invalid as an FQDN.
Hostname and FQDN remain separate types.

## Errors and verification

Validation checks structure before identifier value syntax.
Empty values and placeholders are invalid.
Errors support `errors.Is` with these categories:

- `ErrUnknownIdentifierType`.
- `ErrInvalidIdentifierValue`.
- `ErrUnsupportedIdentifierFormat`.

The `normalization*_test.go` tests in [identity](../../identity) cover accepted formats, placeholders, and malformed input.
They also cover equality, error order, copying, and repeated normalization.
These tests include fuzz tests and run without cgo.
