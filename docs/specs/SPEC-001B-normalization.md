# SPEC-001B: Identifier Normalization and Semantic Equality

**Status:** API and equality contract approved; type-specific proposals pending approval  
**Component:** asset-identity  
**Parents:** [SPEC-001](SPEC-001-identifiers.md), [SPEC-001A](SPEC-001A-identifier-model.md)  
**Scope:** Syntactic validation, canonical representation, and semantic identifier equality

## 1. Authority, approval, and compatibility

The parents and approved SPEC-001A public contracts remain authoritative. The standalone API design and semantic equality contract in sections 5–6 are approved, together with the architectural separation below. Detailed producer formats and canonicalization proposals require approval before implementation. This document does not authorize Go implementation or resolve unclear Greenbone-specific semantics.

Three responsibilities must remain distinct:

1. **Syntactic validation:** Is the input structurally well formed and interpretable under a supported format?
2. **Normalization and semantic equality:** Which representations denote the same typed identifier value in the explicitly supplied scope?
3. **Matching eligibility:** Is that value sufficiently reliable and sufficiently scoped for a reconciliation policy to use as identity evidence?

The first two are this specification's scope. The third belongs to a future policy specification. Syntactic validity or equality must never imply matching eligibility, global uniqueness, authenticity, or asset identity. Known placeholders may be syntactically valid; recognizing an unreliable value is not grounds for a syntax error.

The existing eleven string type names, structs, observations/history, and public operations remain unchanged:

- Existing `Validate` methods remain structural-only; existing payload acceptance is unchanged.
- `SameRepresentation` remains exact type/value/scope comparison without normalization or validation.
- `IdentifierObservation.Normalize`, `NewObservation`, and `NewObservationHistory` retain timestamp-only normalization and structural validation. They do not implicitly call new semantic operations.
- Nil versus empty scopes, defensive copies, explicit timestamp missingness, and caller-controlled history retention are preserved.

Strong types remain `greenbone_id`, `agent_id`, `machine_id`, `bios_uuid`, `ssh_host_key`, `tls_certificate_public_key_hash`, and `cloud_identifier`. Other types remain `mac`, `ip`, `hostname`, and `fqdn`. The parent's configurable, absolute default strong order is unchanged and is not implemented here.

### 1.1 FQDN compatibility

Keep `TypeFQDN = "fqdn"` and `TypeHostname = "hostname"` as separate supported types. Removing FQDN would turn approved inputs into unknown types; silently retagging it would change type-preserving normalization and equality.

Both may contain qualified names. Propose that hostname also accepts short names, while FQDN uses the qualification convention in section 4.7. Shared DNS canonicalization does not imply cross-type equality: identical spelling under different types returns `(false, nil)` when both inputs are valid.

gvmd ingestion may deliberately represent qualified names as `hostname`. Normalization does not migrate existing `fqdn` observations or infer aliases. Cross-type matching belongs to a future policy; any removal or automatic unification would require an explicitly approved compatibility amendment.

## 2. Common normalization and scope contract

Normalization must be deterministic and idempotent, independent of locale, clock, network, database, observation history, and map iteration order. No DNS lookup, cloud lookup, certificate fetch, OS interface lookup, or identifier generation is permitted.

Type names remain exact SPEC-001A strings. Unknown types produce `ErrUnknownIdentifierType`; no aliases, automatic type-name correction, or runtime registration are introduced.

Return a defensive copy of scope. Preserve all dimensions, exact dimension names and values, and nil versus non-nil empty maps. Do not trim/case-fold scope, add inferred fields, drop extra fields, or substitute a default namespace. SPEC-001A's rejection of an empty dimension name remains structural validation; empty dimension values remain representable.

Network, scanner, tenant, deployment, or issuing namespaces are not general syntax requirements. Greenbone ID, Agent ID, short hostname, MAC, IP, SSH, and TLS values may arrive without scope. A missing IPv6 zone or missing network namespace does not invalidate an otherwise well-formed address. Scope sufficiency for matching belongs to reconciliation policy.

Map order does not affect equality. Changed, extra, or missing dimensions do affect equality. Nil and explicitly empty scopes remain distinct. Equal unscoped values remain equal typed values; equality does not assert that their observations identify the same asset.

A format discriminator needed to interpret payload syntax is separate from an identity namespace. The proposed machine-ID `kind` selects Linux versus Windows parsing; it is not a scanner/network requirement. Its representation and missing-input handling still need producer approval. No analogous mandatory cloud namespace schema is imposed by the provisional opaque cloud format.

There is no generic whitespace normalization. Propose nonempty opaque Greenbone, agent, and cloud payloads that preserve exact bytes, including case and whitespace. Strings such as `unknown`, `none`, `0`, or `null` must not become invalid through an invented placeholder blacklist. Structured formats reject whitespace only where their specific grammar excludes it.

## 3. Normalization decision table

Detailed formats below are proposals. Successful equality additionally requires the same type and exact supplied scope. The eligibility column identifies responsibilities deferred to policy; it does not prescribe exclusions.

| Type | Syntax / accepted input proposal | Canonical representation / equality basis | Scope and format information | Matching eligibility, outside syntax |
| --- | --- | --- | --- | --- |
| `greenbone_id` | Nonempty opaque Greenbone identity; no invented UUID/generation pattern | Exact supplied bytes | Scope optional; preserve supplied realm information | Issuance authenticity, placeholders, realm sufficiency remain domain questions |
| `agent_id` | Nonempty opaque producer identifier | Exact supplied bytes | Scope optional; never infer issuing namespace | Issuer/reuse semantics and namespace sufficiency remain open |
| `machine_id` | Linux 32 hex digits or Windows GUID text, selected by proposed `kind` | Linux lowercase compact hex; Windows lowercase hyphenated GUID | Proposed `kind=linux_machine_id` or `kind=windows_machine_guid`; namespace optional | Zero/sentinel values, cloned installations, producer authenticity, and realm sufficiency belong to policy |
| `bios_uuid` | Well-formed 128-bit UUID text, section 4.2 | Lowercase hyphenated UUID | Scope optional; raw firmware decoding requires collector provenance | Nil/max UUIDs and OEM placeholders may be unreliable; no syntax rejection solely for that reason |
| `ssh_host_key` | One algorithm-tagged public-key line, section 4.3 | `<key-format> <padded-standard-base64-canonical-wire-blob>` | Key format explicit in payload; supplied scope optional | Key strength, trust, reuse, and namespace sufficiency are separate |
| `tls_certificate_public_key_hash` | `spki-sha256:<64 hex digits>` only in the minimal proposal | Same tag plus lowercase digest of exact DER SPKI | Scope optional; hashing provenance supplied by collector | CN/SAN/reference-name agreement, trust, time, and evidence admission are separate |
| `cloud_identifier` | Nonempty opaque cloud resource payload | Exact supplied bytes; no provider-specific rewrite | Preserve optional provider/resource-type/namespace dimensions; concrete producer formats open | Provider and namespace completeness/uniqueness belong to policy |
| `mac` | 48-bit colon, hyphen, dotted, or compact hex | Lowercase six colon-separated octets | Scope optional | Zero, broadcast, multicast, or randomized values remain syntactically valid; policy decides usefulness |
| `ip` | IPv4/IPv6 text, with optional IPv6 zone | Canonical address text; proposed mapped-family preservation; exact zone | Scope optional; zone optional and never inferred | Unspecified, multicast, broadcast, loopback, or insufficient context do not cause syntax errors |
| `hostname` | Proposed ASCII DNS host-name subset, short or qualified | ASCII lowercase; multi-label root-dot removal | Scope optional, including short names | Short-name ambiguity, namespace sufficiency, and aliases belong to policy |
| `fqdn` | Same DNS subset with proposed qualification convention | Same DNS normalization; retain `fqdn` type | Scope optional; single-label absolute root dot retained | Cross-type matching and namespace sufficiency are separate |

Missing producer-format context must not be repaired through guesses. Syntax checks cannot certify that an opaque value came from Greenbone, an agent issuer, or a cloud provider.

## 4. Detailed format proposals

### 4.1 Opaque identities and machine formats

Greenbone ID is a Greenbone-generated identity, but the supplied parents do not specify its generation format. Propose nonempty, byte-exact payload handling; do not assume UUID syntax, strip prefixes, generate replacements, require a namespace, or equate it with agent/machine IDs. Producer examples are needed for stronger format validation.

Agent ID follows the same conservative payload handling under its own type. Scope may be absent, explicitly empty, or populated. Supplied issuing/deployment dimensions participate in equality without being mandatory. Issuer format, reuse/reset behavior, and matching namespace requirements remain open.

Cloud input is provisionally opaque rather than a guessed ARN/URI/resource-ID parser. Preserve supplied `provider`, `resource_type`, `namespace`, account, region, project, or other dimensions exactly, without requiring or inventing them. ARN spelling and a short resource ID remain different payloads unless an approved producer contract declares equivalence. A policy may need more context to admit either as identity evidence.

For machine ID, propose a `Scope["kind"]` format discriminator with exact tokens `linux_machine_id` and `windows_machine_guid`. Missing, empty, or unsupported `kind` yields `ErrUnsupportedIdentifierFormat` in the new semantic APIs; existing structural validation still accepts the model. This proposal addresses an ambiguous payload format, not identity-scope sufficiency, and requires confirmation that collectors provide or can explicitly translate lineage information.

Linux accepts exactly 32 ASCII hex digits, case-insensitively, and emits lowercase compact hex. A file terminator is handled by a collector's file-format contract, not generic trimming. All-zero hex is syntactically representable even though systemd requires a nonzero issued machine-id; the normalizer must not certify producer issuance. [systemd machine-id contract](https://github.com/systemd/systemd/blob/main/man/machine-id.xml)

Windows MachineGuid uses the GUID text forms below and lowercase hyphenated output. The Microsoft GUID definition supports text structure, not Greenbone collection provenance or uniqueness. [Microsoft GUID structure](https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid)

Linux and Windows identifiers remain distinguishable even when their 128 bits agree: the explicit `kind` remains significant scope data. Do not infer OS from a compact hex payload, normalize away lineage, or use a network namespace to guess a format.

### 4.2 BIOS UUID and Windows GUID text

Propose accepting exactly 32 hex digits, `8-4-4-4-12` hyphenated hex, or that hyphenated form enclosed by one brace pair. Hex case is insignificant; emit lowercase hyphenated text. Reject malformed lengths/separators, whitespace, partial values, URNs, and raw binary in this initial text grammar.

Nil/all-zero and Max/all-FF UUIDs have well-defined representations and normalize successfully. Their use as placeholders is a matching/producer eligibility concern, not malformed UUID syntax. The previous proposal to reject these solely as identity placeholders is withdrawn. Do not invent OEM blacklists or uniqueness tests. [RFC 9562 Nil and Max UUIDs](https://www.rfc-editor.org/rfc/rfc9562.html#section-5.9)

Propose no UUID version/variant allowlist until producer contracts are confirmed. Text normalization does not certify firmware-generated or Windows-issued identities. Raw SMBIOS UUID byte order must be decoded by collectors with known provenance; never guess by byte-swapping an existing text value. [DMTF SMBIOS UUID encoding](https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0a.pdf)

### 4.3 SSH host-key material

**Minimal representation proposal:** Accept one standard public-key line, `<key-format> <standard-base64-key-blob> [comment]`. Canonical output is `<key-format> <padded-standard-base64-canonical-wire-blob>`, without a comment or line terminator. This proposes public-key material equality rather than the previous multiple fingerprint input grammars; producer confirmation is still required.

Allow space/tab field separators and one optional final LF/CRLF. Require complete blob parsing, agreement between outer and embedded key-format tokens, valid algorithm-specific structure, and no trailing wire data. Reject noncanonical wire encodings rather than silently changing key meaning. Canonical serialization includes the key-format tag; comparison uses exact public-key material and supplied scope, not negotiated signature names or comments.

Propose initial formats `ssh-ed25519`, `ssh-rsa`, and `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`. Supporting a key format does not approve it for matching or cryptographic negotiation. Native Go parsing may use an approved parser dependency. [Go SSH public-key parsing](https://pkg.go.dev/golang.org/x/crypto/ssh#ParsePublicKey)

`rsa-sha2-256` and `rsa-sha2-512` are signature algorithms, not replacement names for the RSA public-key format. [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332.html#section-2)

Do not add speculative custom hex/base64 fingerprint grammars, fingerprint-to-material equivalence, PEM conversions, known-hosts records, option-bearing authorized-key lines, or SSH certificates. They are unsupported in the minimal proposal; if collectors actually supply them, document that producer format and approve a conversion contract first. A fingerprint cannot be expanded into key material, and an untagged fingerprint cannot identify its key algorithm. Private keys are not identifier input.

Key strength, ownership, trust, reused keys, certificate handling, and scope sufficiency do not belong in syntax validation. Public-key equality is not evidence that two observations belong to one asset.

### 4.4 TLS public-key hashing and eligibility

**Minimal representation proposal:** Accept only `spki-sha256:<64 hex digits>`, emitting the same tag with lowercase hex. Require exactly a 32-byte digest. Do not add base64 alternatives, bare hashes, PEM/certificate inputs, or other hash algorithms without producer evidence and separate approval. Valid digest bytes, including an all-zero digest, are not rejected by an invented placeholder test.

Define the hash precisely as SHA-256 over the leaf certificate's exact DER SubjectPublicKeyInfo, including algorithm identifier and parameters. For a parsed Go certificate this is `RawSubjectPublicKeyInfo`; it is not the whole certificate, PEM text, modulus, or re-marshaled approximation. Identical SPKI bytes across renewals yield equal hashes; mathematically equivalent keys with different SPKI encodings are not automatically equated. [RFC 5280 SubjectPublicKeyInfo](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7)

Certificate extraction and conversion from actual collector output require an explicit provenance contract. The tag names the material and algorithm; digest bytes cannot prove that a producer hashed the claimed material. Wrong scheme tags are unsupported, but a misleading SPKI tag on a whole-certificate digest cannot be detected by normalization alone.

CN/SAN/hostname/IP eligibility is entirely outside validation, normalization, and semantic equality. A hash carries no certificate names. A future policy needs the original leaf certificate, reference identity, and producer context to establish name agreement, trust, time validity, or admissibility. Do not infer eligibility from scope, add an `eligible=true` field, or alter SPEC-001A structs.

RFC 9525 SAN-based verification and Go's CN-ignoring `VerifyHostname` are references for that future decision, not a verification contract approved here. Legacy CN fallback, wildcard rules, short-name/IP treatment, self-signed/expired certificates, trusted chains, and hash-only evidence remain open policy/producer questions. No certificate verification helper is specified in this document. [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html#section-4), [Go certificate name verification](https://pkg.go.dev/crypto/x509#Certificate.VerifyHostname)

### 4.5 MAC syntax

Propose six octets as colon-separated or hyphen-separated hex pairs, three dotted groups of four hex digits, or twelve compact hex digits. Hex case is insignificant; emit lowercase colon-separated pairs. Reject malformed groups, mixed separators, whitespace, or widths unsupported by this initial 48-bit format. Wider collector formats require separate approval. [Go MAC parser](https://pkg.go.dev/net#ParseMAC)

All-zero, all-FF/broadcast, multicast, locally administered, and randomized addresses remain valid when syntactically well formed. Normalization and equality do not test identity reliability, assignment, permanence, or uniqueness. A future matching policy may exclude some categories; this specification does not choose exclusions.

### 4.6 IP syntax

IPv4 accepts four decimal octets from 0 to 255 without leading zeroes except the single digit `0`. IPv6 accepts compressed, expanded, and embedded-IPv4 forms. Reject malformed addresses, historical integer/octal/hex/abbreviated IPv4 forms, whitespace, ports, brackets, CIDR, URLs, and DNS names under this proposed address-only grammar.

Emit dotted-decimal IPv4 and RFC 5952 IPv6 spelling with lowercase hex and canonical compression. Propose preserving IPv4-mapped IPv6 as IPv6 (`::ffff:192.0.2.1`), distinct from IPv4 `192.0.2.1`; do not automatically unmap. This representation choice still needs approval. [RFC 5952](https://www.rfc-editor.org/rfc/rfc5952.html)

An IPv6 zone is optional. If supplied, require a nonempty `%zone` with no extra percent signs or whitespace, and preserve it exactly. Reject zones on IPv4. Unzoned `fe80::1` is syntactically valid. Never require a network/scanner namespace, map interface names to indices, or infer a zone. Zone differences participate in equality; zoned and unzoned values remain distinct.

Unspecified, multicast, broadcast, loopback, private, and link-local addresses normalize successfully when syntactically valid. Their matching usefulness and necessary network context are policy questions. No subnet-directed-broadcast inference, freshness selection, or address-based asset rule is introduced.

### 4.7 Hostname and FQDN syntax

Propose an ASCII DNS host-name subset: each label is 1–63 bytes, contains letters/digits/hyphens, and starts/ends with a letter or digit; the name without a terminal dot is at most 253 bytes. Reject malformed labels, empty interior labels, root-only names, wildcards, underscore service labels, IP literals, raw Unicode U-labels, and DNS escape syntax in the initial proposal. IDNA, non-DNS inventory names, and collector-specific alternatives remain open rather than being silently converted.

Fold ASCII A–Z to lowercase. Remove a final root dot on multi-label names; retain it on absolute single-label names. Accepted syntax and this root-dot convention remain proposals based on DNS case semantics. [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343.html)

`hostname` accepts relative short names such as `web` without namespace and qualified names such as `web.example.org`. `web` is not equal to `web.example.org`; no suffix expansion, DNS resolution, first-label stripping, or alias matching is performed. Scope sufficiency for a short name is deferred to policy.

Propose `fqdn` accepting multi-label names with/without a terminal dot and absolute single-label names such as `example.`. Bare single-label `fqdn:example` is unsupported under this initial qualification convention, regardless of namespace. Dot counting does not prove qualification; this convention requires producer confirmation.

Retaining the root dot in canonical `example.` preserves absolute meaning and idempotency; it remains distinct from relative `hostname:example`. Qualified hostname and FQDN values share spelling normalization but retain different types.

## 5. Approved native Go API

Add standalone operations alongside unchanged SPEC-001A APIs:

```go
func ValidateIdentifier(value IdentifierValue) error

func NormalizeIdentifier(value IdentifierValue) (IdentifierValue, error)

func EqualIdentifiers(a, b IdentifierValue) (bool, error)
```

`ValidateIdentifier` checks structural validity and supported input syntax/format information. It does not mutate or canonicalize data or decide matching eligibility. It remains distinct from structural-only `IdentifierValue.Validate`; private parsing to verify syntax does not rewrite input.

`NormalizeIdentifier` validates input and returns its canonical representation with a defensively copied scope. Validation and conversion are separate responsibilities even though this convenience function invokes both. Preserve type, scope bytes/presence, and original caller data; return a zero `IdentifierValue` on error. Successful output must itself pass `ValidateIdentifier` and normalize idempotently. No timestamps or history are processed.

There is no registration system, normalization framework, matching-policy argument, or eligibility result. Type-specific rules and producer-format support require explicit approval before implementation.

## 6. Approved semantic equality contract

For valid supported inputs:

```text
EqualIdentifiers(a, b) = SameRepresentation(NormalizeIdentifier(a), NormalizeIdentifier(b))
```

Process `a` first, returning `(false, error)` on failure; otherwise process `b`. Validate/normalize before comparing type or scope, so malformed input is not hidden by an early false. Error context identifies the operand; if both fail, `a` is reported first. Valid differences in type, complete supplied scope, or canonical payload return `(false, nil)`.

Equality is reflexive, symmetric, and transitive over valid inputs under one approved rule version. Error precedence may depend on operand order; successful equality does not. Structural equality of invalid inputs does not certify syntax validity.

Equal valid values may be ineligible under a future policy. Different scopes remain unequal even when a future policy could relate them. Equality never applies matching priority, fuzzy scores, freshness, evidence weighting, conflict resolution, candidate selection, or merging. Missing timestamps and history do not participate.

## 7. Proposed error categories

Preserve existing errors and `errors.Is` behavior. Existing structural methods do not acquire new restrictions.

| Category | Responsibility |
| --- | --- |
| `ErrUnknownIdentifierType` | Existing error for unknown stable type names |
| `ErrInvalidScope` | Existing structural error for an empty dimension name; not for absent network/scanner/issuer scope |
| `ErrInvalidIdentifierValue` | Proposed error for malformed or empty payloads under the approved input grammar |
| `ErrUnsupportedIdentifierFormat` | Proposed error for formats/algorithms outside the approved grammar, including unresolved machine format discrimination |

Withdraw `ErrPlaceholderIdentifierValue` from the syntax/normalization API: a syntactically valid placeholder is not a validation failure solely because of potential ineligibility. No matching-eligibility error or decision is returned here.

Check structural validity first, explicit format discrimination second, then payload syntax. Diagnostics and field order must be deterministic. No panic, partial canonical output, silent omission, inferred context, or fallback equality for unsupported formats. Avoid complete key blobs or opaque identity payloads in diagnostics.

## 8. Tests separating syntax, equality, and eligibility

Format-dependent outcomes below require approval of the detailed proposals. Eligibility is deliberately not returned by these APIs; policy exclusions are neither assumed nor implemented. Use fixed fixtures and supplied contexts rather than live services.

| Inputs / case | Syntax and normalization | Semantic equality | Eligibility responsibility |
| --- | --- | --- | --- |
| MAC `02:AB:CD:EF:01:23`, `02ab.cdef.0123`, compact/hyphen variants | Valid; canonical `02:ab:cd:ef:01:23` | Equal with identical scope | Policy determines usefulness |
| Zero MAC in compact/colon forms; all-FF/broadcast; multicast `01:00:5e:00:00:01` | Valid; normalize successfully | Equivalent spellings equal, different addresses unequal | May be excluded later; no syntax error |
| MAC malformed group, mixed separators, unsupported width | Syntax/format error | `(false, error)` even against different type | No eligibility evaluation |
| Expanded/compressed/case-varied `2001:db8::1` | Valid; canonical IPv6 | Equal with identical scope | No identity assertion |
| `0.0.0.0`, `::`/expanded zero, multicast, limited broadcast, loopback | Valid; successful normalization | Equivalent spellings equal within type/family; distinct values unequal | Future policy owns any exclusions |
| `010.0.0.1`, invalid octet, CIDR, host:port | Error under address-only grammar | Error, not opaque comparison | Unrelated to evidence reliability |
| Unzoned `fe80::1`, same expanded spelling without namespace | Valid with absent/empty scope | Equal for the same scope presence/state | Policy decides whether more context is necessary |
| `%eth0` versus `%eth1`, zoned versus unzoned IPv6 | Valid; zones preserved | Unequal; no interface lookup | Zone sufficiency is a policy concern |
| `192.0.2.1` versus `::ffff:192.0.2.1` | Valid | Unequal under proposed family preservation | Any cross-family relation belongs elsewhere |
| Short `WEB`, `web` without namespace | Valid; canonical `web` | Equal with same scope; not equal to `web.example.org` | Short-name context belongs to policy |
| Qualified `Web.Example.Org.` versus `web.example.org` | Valid; proposed root-dot normalization | Equal within each type | No cross-type matching |
| Same qualified name under `hostname` and `fqdn` | Both valid | Unequal types | Future policy may define cross-type matching separately |
| `fqdn:Example.` normalized twice; bare `fqdn:example` | Absolute form valid/idempotent; bare form unsupported in proposal | Canonical `example.` remains stable | Qualification convention requires producer approval |
| DNS malformed/oversized label, root-only name, unsupported Unicode/underscore | Syntax/format error under proposed subset | Error | Collector alternatives remain open |
| Greenbone/agent `Id-A`, `id-a`, ` Id-A ` without namespace | Valid nonempty opaque input | Distinct byte values; repeated same bytes equal | No issuance or namespace-sufficiency assertion |
| Same Greenbone/agent value with nil versus empty or differing scopes | All structurally valid | Unequal scope states/dimensions | Neither absence nor equality grants uniqueness |
| Cloud value with absent provider/namespace, same value with supplied dimensions | Valid opaque inputs | Scope differences significant; map order insignificant | Provider/context sufficiency belongs to policy |
| Linux uppercase/lowercase 32-hex with `kind`; Windows GUID text variants with `kind` | Valid; format-specific canonicalization | Equal within a lineage; different kinds unequal | Producer validity and cloned IDs remain separate |
| All-zero Linux ID; nil/max BIOS or Windows GUID | Well-formed text normalizes successfully | Equivalent forms equal | Producer placeholders/ineligibility belong elsewhere |
| Missing/unknown machine `kind`; malformed UUID | Format-discrimination/syntax error | Error; no guessed OS or byte order | Not a network namespace requirement |
| SSH key line with same material/different comment or base64 representation accepted by grammar | Valid parsed blob; canonical material | Equal, including key-format tag and scope | Key strength/trust/reuse separate |
| SSH outer/inner algorithm mismatch, trailing wire bytes, private key, fingerprint-only input | Syntax/unsupported-format error | Error; no fingerprint-to-material inference | Actual collector formats require approval |
| TLS tagged hex uppercase/lowercase; all-zero 32-byte digest | Valid; canonical lowercase `spki-sha256:` | Equal digest bytes and same scope | Digest validity never proves provenance/eligibility |
| TLS base64/bare digest, bad hex/length, whole-cert scheme tag | Unsupported format or syntax error | Error | Existing collector conversion contract remains open |
| Renewed certificates with identical SPKI; certificates with same key hash but different SAN/CN | Collector extraction yields the same digest when exact SPKI agrees | Hash equality unaffected by SAN/CN | Name/trust/time eligibility belongs to future policy |
| Identical invalid values; invalid operand and different-type valid operand | Invalid input remains invalid | Error rather than early false; `a` error first if both fail | No eligibility evaluation |

A syntactically valid digest falsely labeled as SPKI cannot be identified from its bytes. Test extraction provenance separately without claiming that normalization detects incorrect hashing material. No CN/SAN verification helper is implemented or required by SPEC-001B tests.

## 9. Testable acceptance criteria

- [ ] Eleven SPEC-001A type names and all existing public contracts remain unchanged; existing tests continue to pass unchanged.
- [ ] Syntactic validity, semantic equality, and matching eligibility have distinct documented expectations; only the first two are exposed here.
- [ ] Well-formed zero/broadcast/multicast MACs and unspecified/multicast/broadcast/loopback IPs normalize successfully.
- [ ] Missing Greenbone/agent/hostname namespaces, missing network/scanner scopes, and unzoned link-local IPv6 do not cause syntax errors.
- [ ] Supplied scopes are copied defensively and preserved exactly, including extra dimensions, empty values, nil versus empty presence, and case; map insertion order does not affect equality.
- [ ] Normalization preserves type, emits valid canonical output, is deterministic/idempotent, and does not mutate inputs, timestamps, or history.
- [ ] Equality is reflexive/symmetric/transitive over valid fixtures and agrees with structural comparison after normalization.
- [ ] Unknown types and malformed/unsupported inputs produce recognizable deterministic errors, even when operands have different types or scopes.
- [ ] Opaque case/whitespace distinctions are preserved; DNS/hex changes occur only under the approved type grammar.
- [ ] Linux/Windows lineage stays distinct; no payload-shape guessing or implicit scope population is introduced.
- [ ] Qualified names are supported under hostname and FQDN without retagging or cross-type equality; short hostname inputs require no namespace.
- [ ] SSH fixtures verify exact key-format/material parsing, canonical wire serialization, comment removal, and unsupported producer forms without a speculative fingerprint grammar.
- [ ] TLS fixtures verify the explicit SPKI/SHA-256 scheme and strict hex representation; extraction provenance and matching eligibility remain separate responsibilities.
- [ ] No policy exclusions, priority/scoring/freshness rules, candidate selection, matching, merging, runtime registration, database operations, or C adapter are implemented.
- [ ] Any future implementation and parser dependencies are native Go and work with `CGO_ENABLED=0`.

## 10. Unresolved producer-specific questions

1. **Greenbone/agent:** Obtain real payload samples, documented generation/issuance formats, case/whitespace semantics, and provenance. Scope requirements for matching are explicitly deferred; no mandatory namespace is proposed here.
2. **Machine IDs:** Confirm collection sources, exact Linux/Windows formats, availability of lineage information, and the proposed `kind` representation. Approve handling of unsupported or missing lineage without guessing. Nonzero issuance constraints and placeholders do not become reliability-based syntax exclusions.
3. **BIOS UUID:** Confirm textual forms, firmware decoding provenance/byte order, and whether genuine format constraints require version/variant checks. OEM placeholder treatment belongs to policy.
4. **SSH:** Do collectors supply public-key material, fingerprints, known-hosts records, or certificates? Confirm key algorithms, exact encodings, canonical serialization, and a native Go parser. Public-key material is the minimal proposal, not a claim about currently observed collector output. Fingerprint schemes/algorithm provenance and any conversion require separate approval.
5. **TLS:** Confirm collectors hash exact SPKI DER rather than whole certificates or another key representation, the digest algorithm, and their actual encoding. Tagged hex is the minimal internal proposal; bare/base64/hash-only producer input needs an explicit adapter contract before support. CN/SAN/reference-name, chain, time, trust, and hash-only eligibility rules belong to a future policy.
6. **Cloud:** Obtain provider/resource-kind payload examples and existing scope/provenance metadata. Decide any producer-specific syntax/equivalence rules; network/account/region namespace sufficiency belongs to reconciliation policy.
7. **MAC/IP:** Confirm required widths/notations, mapped-IPv6 canonicalization, zone syntax, and actual collector forms. Identity reliability and context sufficiency do not affect syntax acceptance.
8. **Hostname/FQDN:** Confirm DNS versus inventory-name input, Unicode/IDNA/underscore needs, short-name handling, and root-dot/qualification conventions. Namespace sufficiency and cross-type matching belong to policy, not normalization.
9. **Rollout:** Approve input-size limits, parser dependencies, canonical-format stability/versioning, and explicit caller adoption of semantic APIs. Do not change structural constructors to normalize payloads implicitly.

Architectural separation and API/equality approval do not approve unspecified producer formats. Implementation requires explicit decisions for each supported format; unresolved inputs must not be interpreted through best-effort guesses.

## 11. Out of scope

Matching eligibility/exclusions, scope sufficiency for identity matching, candidate selection, fuzzy scores, strong priority implementation, freshness, reconciliation, asset matching/merging/counting, persistence/retention operations, runtime registration, C adapters, certificate verification, and identifier generation.
