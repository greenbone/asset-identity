# SPEC-002: Asset Reconciliation

`Decide` selects an existing asset key or requests a new one. It returns a merge plan for the application to apply; it
does not create keys or change stored assets. The Go and GLib C APIs use the same implementation.

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
}

func Decide(observation Observation, candidates []Candidate, policy MatchPolicy) (Decision, error)
```

| Action | NeedsNewKey | Selected key/index |
|--------|-------------|--------------------|
| CREATE | true        | Absent             |
| REUSE  | false       | Present            |

Indices refer to the original candidate array. Invalid input returns an error and a zero decision. Inputs are not
mutated or retained; returned pointers are independent. Concurrent calls may share immutable inputs.

Applications supply complete eligible active identifier views and one candidate per existing key. They own discovery,
scanner/network boundaries, authorization, producer trust, history retention, persistence, and applying results.
Reconciliation does not read history or the wall clock. Complete identifier scope remains significant, including nil
versus empty scope.

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

1. Cloud identifier
2. Greenbone ID
3. Machine ID
4. BIOS UUID
5. Agent ID
6. SSH host key
7. TLS public-key hash

Default fuzzy members, in accumulation order, are MAC (1.0), hostname (0.4), IP (0.4), and FQDN (0.4). FQDN is weak
evidence and remains distinct from hostname; full normalized names are compared.

Callers may reorder, reclassify, or omit supported types. Omission disables a type for that stage; empty lists do not
restore defaults. A type cannot participate in both stages. An empty policy is valid. Reject unknown types, duplicate
members and overlapping stages. Weights must be positive, finite, and representable as positive finite float32. Omit a
type to disable it. Default policies and clones own their slices.

## Strong matching

1. Normalize identifiers using [SPEC-001B](SPEC-001B-normalization.md) and leave placeholders out. An `x509:` TLS
   certificate stays in a view, as its public-key hash, only when its subject CN or a DNS SAN equals a normalized FQDN
   or hostname of the same view (ASCII names only, case-insensitive, trailing dot ignored, no wildcard matching);
   `spki-sha256:` values stay. The exported `EvaluateStrongPriority` and `MatchingIdentifiers` apply the same view.
2. For each candidate, find the first configured strong type both views carry. An equal value (equal scope) is a match
   at that priority. A different value excludes the candidate from strong and fuzzy matching. For TLS, require equality
   of the complete normalized public-key sets; TLS sets that differ are inconclusive and the next configured type
   decides. A type only one view carries is skipped.
3. Among matching candidates, the highest priority wins. Within it choose the newest present `LastSeen`. Missing times
   rank last. Compare UTC instants at nanosecond precision; equal or all-missing times use the smallest asset key by
   byte order.
4. Return REUSE for that candidate.
5. Without a strong match, candidates that share no configured strong type with the observation enter fuzzy matching.
   Excluded candidates do not.

TLS equality ignores order and duplicate normalized keys. `{A,B}` matches `{B,A}` but not `{A}` or `{A,B,C}`; scope
differences remain significant.

Other strong types match any incoming value. Lower-priority matches and fuzzy differences do not veto the winning
priority.

## Fuzzy matching

Normalize and deduplicate identifiers, then keep only configured fuzzy types. Each set entry includes type, canonical
value, and complete scope. A fuzzy member with weight >= 1 is an anchor.

A candidate qualifies when it is compatible and the shared evidence is sufficient. Compatible: no anchor type carried by
both views without a shared value. Sufficient: a shared anchor value, or shared values of at least two fuzzy types.
Values only one view carries do not block. Empty projected observations and empty candidate lists return CREATE.

The score is the sum of shared distinct-value counts multiplied by their configured weights. Count conversion,
multiplication, and each accumulation step round to float32 in policy order. Nonfinite scores return an error. The
highest score wins; equal scores are ranked by newest `LastSeen` at whole-second precision, then first input position.

For fuzzy ranking, missing `LastSeen` compares as Unix epoch. It ties epoch, outranks pre-epoch times, and differs from
a present Go zero time. Fractional seconds do not break fuzzy ties.

`Stage` is FUZZY when weak evidence selected the key or the observation carries no configured strong identifier;
otherwise STRONG.

## Merge plan

After selecting an existing key, compare other candidates with the selected candidate's view. `MergeIndices` lists source candidates in input order. Retrieve source records and
their asset keys from the original candidate array using these indices. The selected candidate is excluded. An empty
list means no key moves.

- A source sharing a strong type with the destination moves when the value at the first shared type is equal; TLS
  requires exact complete key-set equality. A different value keeps it apart.
- A source sharing no strong type with the destination moves when it is compatible with sufficient shared weak
  evidence, and contradicts neither a source moving through a strong match nor another such weak source. Both sources of a contradicting pair stay; input order does not choose a winner.

A CREATE decision moves no records: a candidate with sufficient evidence would have been reused.

## Validation

Validate policy before matching. Reject empty candidate keys (`ErrEmptyCandidateKey`) and duplicate keys
(`ErrDuplicateCandidateKey`) across the entire supplied array. Do not skip rows, combine snapshots, or renumber indices.
Validate every candidate timestamp, including unmatched candidates: present UTC years must be 1–9999. Identifiers must
satisfy the structural and normalization contracts, even for types outside the selected stage. Policy errors support
`errors.Is(err, ErrInvalidMatchPolicy)`; identifier/time errors retain their existing categories.

## Examples

Here G/A mean Greenbone/Agent ID, P means IP and M means MAC; scopes are equal unless stated.

| Observation     | Candidates                     | Result                                 |
|-----------------|--------------------------------|----------------------------------------|
| G(g), A(a)      | K1:G(g), K2:A(a) newer         | STRONG REUSE K1: default priority wins |
| G(g1), G(g2)    | K1:G(g1) older, K2:G(g2) newer | STRONG REUSE K2                        |
| G(g), P(p)      | K1:P(p)                        | STRONG CREATE: one weak type           |
| G(g), A(a)      | K1:G(g2), A(a)                 | STRONG CREATE: G differs on both sides |
| A(a), M(m), P(p)| K1:M(m), P(p)                  | FUZZY REUSE K1: no shared strong type  |
| P(p1), M(m)     | K1:P(p2), M(m)                 | FUZZY REUSE K1: anchor shared          |
| P(p1)           | K1:P(p1),P(p2)                 | FUZZY CREATE: one type                 |
| P(p1), M(m)     | K1:P(p1), M(m2)                | FUZZY CREATE: anchors differ           |
| M(m)            | Z:M(m), A:M(m), equal times    | FUZZY REUSE Z: input order wins        |
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
cover priority, multiple strong values, ranking, scopes, weak evidence, merge safeguards, validation, ownership, and
concurrent calls.

The 78 [reference fixtures](../../identity/testdata/fuzzy_reference.jsonl) pin fuzzy key selection, exact score bits
and merge indices for canonical supported values with equal scopes, distinct keys, and whole-second timestamps. They
were generated from this implementation; the rules themselves are proven by the decision and counting tests.
