# SPEC-001B: Normalization and Equality

Normalization checks payload syntax and produces a canonical value. It does not establish trust or uniqueness.
See [SPEC-001A](SPEC-001A-identifier-model.md) for the model.

## API

| Function              | Result                                                                 |
|-----------------------|------------------------------------------------------------------------|
| `ValidateIdentifier`  | Validate structure, format, and payload without changing input         |
| `NormalizeIdentifier` | Return a canonical value with a copied scope, or a zero value on error |
| `EqualIdentifiers`    | Normalize both values and compare type, value, and complete scope      |

Normalization trims surrounding whitespace, preserves type and scope, and is deterministic and idempotent. Equality
validates `a` before `b`, even when their types or scopes differ. Structural `Validate` methods and observation
constructors do not normalize payloads. No lookups, namespace inference, or history processing occur.

## Supported formats

| Type                                     | Accepted input → canonical value                                                               |
|------------------------------------------|------------------------------------------------------------------------------------------------|
| Greenbone ID, Agent ID, cloud identifier | Nonempty opaque string, at most 2048 bytes → trimmed bytes, preserving case                    |
| Linux machine ID                         | Exactly 32 hex digits → lowercase compact hex                                                  |
| Windows machine GUID, BIOS UUID          | Compact, hyphenated, or braced hyphenated UUID → lowercase hyphenated UUID                     |
| SSH host key                             | `[port] <algorithm> <base64-blob> [comment]` → algorithm and canonical padded base64 blob      |
| TLS public-key hash                      | `x509:<base64-DER>` or `spki-sha256:<64 hex digits>` → `spki-sha256:<lowercase digest>`        |
| MAC                                      | 48-bit colon, hyphen, dotted, or compact hex → six lowercase colon-separated octets            |
| IP                                       | IPv4 or IPv6, including mapped IPv4 and IPv6 zones → canonical address, unmapped, without zone |
| Hostname                                 | Single or qualified ASCII DNS name → lowercase; remove a final dot only for qualified names    |
| FQDN                                     | ASCII DNS name with at least two labels → lowercase, without final dot                         |

### Placeholders

`ValidateIdentifier` and `NormalizeIdentifier` reject these as `ErrInvalidIdentifierValue`:

- Machine IDs: all zero; Linux also accepts `uninitialized` in any case as a placeholder.
- BIOS UUIDs: all zero, all F, or `03000200-0400-0500-0006-000700080009`.
- MACs: all zero or broadcast.
- IPs: unspecified, loopback, link-local, multicast, or broadcast.
- Names: `localhost` (hostname) and `localhost.localdomain` (hostname or FQDN).

`Decide`, `EvaluateStrongPriority`, and `MatchingIdentifiers` omit placeholders. Malformed identifiers still fail.

### Machine IDs and UUIDs

Machine IDs require `Scope["kind"]` to be exactly `linux_machine_id` or `windows_machine_guid`. The library does not
infer the OS; the kind remains part of equality. UUIDs accept 32 hex digits, `8-4-4-4-12` hex, or that hyphenated form
in braces. Inner whitespace, URNs, and raw firmware bytes are unsupported; no byte swapping or version/variant filtering
occurs.

### SSH keys

Accept one line with spaces or tabs between fields. An optional decimal port must be 1–65535; it and any comment are
removed. Supported algorithms are `ssh-ed25519`, `ssh-rsa`, and `ecdsa-sha2-nistp256/384/521`. Require strict padded
standard base64, matching outer/embedded algorithms, complete parsing, canonical wire encoding, and positive RSA moduli.
Additional lines, fingerprints, certificates, private keys, and known-hosts records are unsupported. Normalization does
not assess key strength, ownership, or trust.

### TLS hashes

Hash the certificate's exact DER SubjectPublicKeyInfo with SHA-256. An `x509:` input contains one DER certificate
encoded as strict padded standard base64 on one line. Renewal with the same public key preserves the hash. A raw
certificate and its tagged hash normalize equally; an all-zero tagged digest is syntactically valid.

Normalization does not check certificate names, signatures, trust, or validity dates. Matching admits a raw certificate
only when its CN or a DNS SAN names a supplied hostname or FQDN;
see [strong matching](SPEC-002-reconciliation.md#strong-matching). Supplied tagged hashes remain eligible, but the
library cannot verify what the producer hashed. Bare/base64 digests, certificate fingerprints, PEM, other tags,
malformed DER, and trailing DER data are unsupported.

### MAC and IP addresses

MAC separators must be consistent; reject other widths, mixed separators, and inner whitespace. Keep multicast MACs.
IPv4 requires four decimal octets without leading zeroes except `0`. IPv6 accepts compressed, expanded, and
embedded-IPv4 forms. An IPv6 zone must be nonempty, contain no whitespace or extra `%`, and is removed. Reject IPv4
zones, ports, brackets, CIDR, URLs, DNS names, and inner whitespace. Keep private addresses.

### Hostnames and FQDNs

Labels contain 1–63 ASCII letters, digits, hyphens, or underscores; they cannot start or end with a hyphen. The name
without a final dot is at most 253 bytes. Reject empty labels, root-only names, IP literals, wildcards, Unicode, and DNS
escapes. No IDNA conversion or alias expansion occurs. Qualified names cannot have a numeric final label.
`HOST.Example.` becomes `host.example` for either type;
`HOST.` remains `host.` as a hostname and is invalid as an FQDN. Hostname and FQDN remain distinct types.

## Errors and verification

Validation checks structure, then machine-ID kind, then payload syntax. Errors support `errors.Is`:
`ErrUnknownIdentifierType`, `ErrInvalidScope`, `ErrInvalidIdentifierValue`, and `ErrUnsupportedIdentifierFormat`. Empty
payloads and placeholders are invalid.

The `normalization*_test.go` tests in [`identity`](../../identity) cover formats, placeholders, malformed input,
equality, error order, copying, and idempotency, including fuzz tests. They run without cgo.
