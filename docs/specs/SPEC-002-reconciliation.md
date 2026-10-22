# SPEC-002: Asset Reconciliation

`Decide` selects an existing asset key or requests a new one. It returns a merge plan for the application to apply;
it does not create keys or change stored assets. The Go and GLib C APIs use the same implementation.

## Inputs and results

```go
type Observation struct {
Identifiers []IdentifierValue
}

type Candidate struct {
AssetKey    string
Identifiers []IdentifierValue
LastSeen    *time.Time
}

type Decision struct {
Action        DecisionAction // CREATE or REUSE
Stage         MatchingStage  // STRONG or FUZZY
NeedsNewKey   bool
SelectedKey   string
SelectedIndex *int
MergeIndices  []int
MergeKeys     []string
}

func Decide(observation Observation, candidates []Candidate, policy MatchPolicy) (Decision, error)
```

| Action | NeedsNewKey | Selected key/index |
|--------|-------------|--------------------|
| CREATE | true        | Absent             |
| REUSE  | false       | Present            |

Indices refer to the original candidate array. Invalid input returns an error and a zero decision. Inputs are not
mutated or retained; returned pointers are independent. Concurrent calls may share immutable inputs.

Applications supply complete eligible active identifier views and one candidate per existing key. They own discovery, scanner/network boundaries,
authorization, producer trust, history retention, persistence, and applying results. Reconciliation does not read
history or the wall clock. Complete identifier scope remains significant, including nil versus empty scope.

## Policy

```go
type MatchPolicy struct {
StrongOrder []IdentifierType
Fuzzy       []FuzzyMember
}

type FuzzyMember struct {
Type   IdentifierType
Weight float64
}
```

`GreenboneMatchPolicy()` uses this strong priority, highest first:

1. Greenbone ID
2. Agent ID
3. Machine ID
4. BIOS UUID
5. SSH host key
6. TLS public-key hash
7. Cloud identifier

Default fuzzy members, in accumulation order, are MAC (1.0), hostname (0.4), and IP (0.4). FQDN has no default matching
role.

Callers may reorder, reclassify, or omit supported types. Omission disables a type for that stage; empty lists do not
restore defaults. A type cannot participate in both stages. An empty policy is valid. Reject unknown types, duplicate
members, overlapping stages, and fuzzy FQDN membership. Weights must be positive, finite, and representable as positive
finite float32. Omit a type to disable it. Default policies and clones own their slices.

## Strong matching

1. Normalize identifiers using [SPEC-001B](SPEC-001B-normalization.md).
2. Check configured strong types in priority order. At the first type with matches, collect every candidate matching any
   incoming value of that type, with equal scope. For TLS, require equality of the complete normalized public-key sets.
3. Choose the candidate with the newest present `LastSeen`. Missing times rank last. Compare UTC instants at nanosecond
   precision; equal or all-missing times use the smallest asset key by byte order.
4. Return REUSE for that candidate.
5. If incoming configured strong evidence exists but no type matches, return CREATE without fuzzy fallback. Only absence
   of incoming configured strong evidence permits fuzzy matching.

TLS equality ignores order and duplicate normalized keys. `{A,B}` matches `{B,A}` but not `{A}` or `{A,B,C}`; scope
differences remain significant. If TLS sets differ, continue to later configured strong types. TLS mismatch alone does
not veto a higher-priority match. If no strong type matches, return CREATE without fuzzy fallback.

Other strong types still match any incoming value. All qualifying candidates use the same ranking. Lower-priority
matches and fuzzy differences do not veto the winning priority.

## Fuzzy matching

Normalize and deduplicate identifiers, then keep only configured fuzzy types. Each set entry includes type, canonical
value, and complete scope.

A candidate qualifies only if it contains every observed fuzzy identifier. Select a qualifying candidate and return
REUSE; if none qualifies, return CREATE. Empty projected observations and empty candidate lists return CREATE. A
candidate contained by the observation, or partial overlap alone, is insufficient for reuse.

The score is the sum of shared distinct-value counts multiplied by their configured weights. Count conversion,
multiplication, and each accumulation step round to float32 in policy order. Nonfinite scores return an error. All
qualifying candidates contain the full observation and therefore have equal scores. They are ranked by newest `LastSeen`
at whole-second precision, then first input position.

For fuzzy ranking, missing `LastSeen` compares as Unix epoch. It ties epoch, outranks pre-epoch times, and differs from
a present Go zero time. Fractional seconds do not break fuzzy ties. No score threshold or overlap-only matching is performed.

## Merge plan

After selecting a key, compare other candidates with the destination view: the selected candidate for REUSE,
or the incoming observation for CREATE. `MergeIndices` lists source candidates in input order; `MergeKeys`
contains their corresponding asset keys. The selected candidate is excluded. Empty lists mean no key moves.

- If both views contain configured strong IDs, require a match at the winning strong type. For a STRONG REUSE,
  use the type that selected the destination; otherwise use the highest-priority strong type present in the
  destination. TLS requires exact complete key-set equality. Lower-priority differences do not veto that match.
- If either view lacks configured strong IDs, require every source fuzzy identifier to occur in the destination
  fuzzy set. The destination fuzzy set must be nonempty. An empty source fuzzy set is a subset, as in the C reference.
- Partial fuzzy overlap alone does not produce a merge target. Strong mismatches cannot be bypassed through fuzzy
  containment when both views contain strong IDs.

If the destination lacks strong IDs, also compare the proposed strong-ID sources with each other. Use the
highest-priority strong type present in either source, with exact full-set equality for TLS. Exclude both sources
of every incompatible pair; input order does not choose a winner. Compatible strong sources and contained weak
sources remain eligible. Thus a weak observation cannot bridge different Agent IDs into one new key.

Key selection is unchanged: unmatched incoming strong IDs still produce CREATE, even if weak sources can be moved
under the new key. On CREATE, `SelectedIndex` is nil and `SelectedKey` is empty, including when merge targets exist.
The caller generates any new key and atomically stores the observation and moves each merge source to that key.
The library performs no database writes and does not manufacture a union of supplied views.

## Validation

Validate policy before matching. Reject empty candidate keys (`ErrEmptyCandidateKey`) and duplicate keys
(`ErrDuplicateCandidateKey`) across the entire supplied array. Do not skip rows, combine snapshots, or renumber indices.
Validate every candidate timestamp, including unmatched candidates: present UTC years must be 1–9999. Identifiers must
satisfy the structural and normalization contracts, even for types outside the selected stage. Policy errors support
`errors.Is(err, ErrInvalidMatchPolicy)`; identifier/time errors retain their existing categories.

## Examples

Here G/A mean Greenbone/Agent ID and P means IP; scopes are equal unless stated.

| Observation     | Candidates                     | Result                                 |
|-----------------|--------------------------------|----------------------------------------|
| G(g), A(a)      | K1:G(g), K2:A(a) newer         | STRONG REUSE K1: default priority wins |
| G(g1), G(g2)    | K1:G(g1) older, K2:G(g2) newer | STRONG REUSE K2                        |
| G(g), P(p)      | K1:P(p)                        | STRONG CREATE: no fuzzy fallback       |
| P(p1)           | K1:P(p1),P(p2)                 | FUZZY REUSE K1                         |
| P(p1),P(p2)     | K1:P(p1)                       | FUZZY CREATE                           |
| P(p1),P(p3)     | K1:P(p1),P(p2)                 | FUZZY CREATE                           |
| P(p1)           | Z:P(p1), A:P(p1), equal times  | FUZZY REUSE Z: input order wins        |
| G(g), nil scope | K1:G(g), empty scope           | STRONG CREATE                          |

## C API

C callers may pass raw scanner values directly to `gvm_asset_identity_identifier_new`: SSH accepts a leading port, and
TLS accepts `x509:<base64-DER-certificate>`. `gvm_asset_identity_decide` normalizes observation and candidate values
internally. Constructors copy values without parsing; invalid values return INVALID_INPUT from `decide`.

The public header is [`gvm_asset_identity.h`](../../include/gvm_asset_identity.h). ABI 1 installs
`libgvm_asset_identity.so -> .so.1 -> .so.<version>-<arch>`, the header, and pkg-config metadata. Consumers need GLib
development files; Go and Cgreen are build/test dependencies, not consumer dependencies.

- Constructors return owned objects; parents own their nested data. Matching free functions accept NULL.
- `decide` borrows immutable inputs and returns an independent decision. Output slots must not alias inputs or each
  other. On failure the decision is NULL. Pass a NULL-initialized `GError *` and release it with `g_clear_error`.
- Identifier/candidate/policy collections must be real GLib arrays. Scopes are owned string-to-string hash tables; NULL
  differs from an explicitly empty table. Strings are NUL-terminated and cannot contain embedded NUL bytes.
- Timestamps carry presence, signed Unix seconds, and nanoseconds (0–999999999), within UTC years 1–9999. Absent
  timestamps have zero seconds/nanoseconds. No Go pointer crosses the ABI.
- Limits per call: 1,048,576 entries per collection, 16 MiB per string, and 64 MiB of private wire arrays/string bytes.
  Oversized inputs are rejected. Pointers must reference live, aligned objects of the declared types.
- Error codes are INVALID_INPUT, INVALID_POLICY, and INTERNAL. Recoverable Go panics become INTERNAL errors; fatal
  runtime or allocation failures retain normal process behavior.

Build/install commands and path overrides are in the [README](../../README.md#c-build-test-and-install).
`DESTDIR` only stages installation; it is not embedded in metadata. Uninstall removes project files only. CTest sets
`CGREEN_NO_FORK=1` for the Go runtime and clears loader overrides. Native arm64 and other libc combinations have not
been verified; cross-builds require matching GLib, compiler, and sysroot.

## Verification

Run `make test`, `make test-install`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, and `go vet ./...`. Tests
cover priority, multiple strong values, ranking, scopes, containment, merge safeguards, validation, ownership, and concurrent calls.

The 78 [C reference fixtures](../../identity/testdata/fuzzy_c_compat.jsonl) preserve fuzzy key selection and exact score
bits for canonical supported values with equal scopes, distinct keys, and whole-second timestamps. Their fuzzy merge
indices are also verified. The reference C code's row-skipping behavior is not part of this library's contract; this library rejects empty and duplicate candidate keys.
