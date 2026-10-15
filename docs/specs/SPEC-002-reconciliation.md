# SPEC-002: Asset Reconciliation and Merge Decisions

**Status:** Draft — caller-owned eligibility, configurable strong priority/ranking, strong-first fallback, and C fuzzy containment, incoming strong multiplicity, and input validation approved\
**Component:** asset-identity  
**Parents:** [SPEC-001](SPEC-001-identifiers.md), [SPEC-001A](SPEC-001A-identifier-model.md), [SPEC-001B](SPEC-001B-normalization.md)  
**Scope:** One native Go reconciliation function extending the gvmd C containment algorithm

## 1. Purpose, authority, and responsibility boundary

Provide one public `Decide(observation, candidates, policy)` reconciliation API in the existing `identity` package.
It is a small Go extension of the established C fuzzy containment algorithm, with strong matching first.
The future C adapter calls the same Go implementation. No separate policy engine or additional packages are required.

**APPROVED application responsibilities:** gvmd/gvmd-lite own scanner and network boundaries, boundary equivalence,
candidate discovery and filtering, permissions/authorization, producer admission, active identifier views, historical
evidence eligibility, persistence, key generation, and applying decisions or merges. They must supply eligible current
observation and candidate views. Supplying those views is the caller contract; the library does not certify producer trust.

**APPROVED library responsibilities:** identifier normalization and semantic equality, configurable strong priorities,
strong candidate selection/ranking, the C fuzzy containment kernel, original supplied candidate indices, and key-reuse,
new-key, conflict, or non-actionable review results. The library performs no scanner/network lookup, equivalence
resolution, boundary filtering, authorization, database access, external-service calls, or history aggregation.

This ownership decision supersedes the earlier library boundary-admission design. `BoundaryContext`, `ScannerID`,
`FuzzyBoundaryMode`, strict/legacy migration modes, boundary-key qualification, and public C compatibility options are
not library inputs or policy. Applications handle any migration of scanner/network metadata themselves.

Identifier `Scope` remains part of identifier identity under SPEC-001A/B. It is not a scanner-boundary filter.
Removing boundary admission must not remove, rewrite, coalesce, or relax scope comparison; nil and empty scopes remain
different. Equal scoped identifiers establish correspondence only under the supplied eligible-view contract.

Approved behavior includes absolute configurable strong priority, same-priority freshness/key ranking, fuzzy entry only
without eligible incoming configured strong evidence, C containment Cases A/B/C, and separation of potential merge
targets from merge authorization. Incoming strong multiplicity is defined in section 4.3. Independent merge safety
remains application-owned; no other contradiction or producer-trust rules are inferred.

## 2. Review of the authoritative C implementation

Reviewed the sibling gvmd checkout at commit `636349bdce036bc72c9119a116c2a7f42f182293`:

- [manage_asset_keys.c](../../../gvmd/src/manage_asset_keys.c), especially `asset_keys_target_merge_decide` (line 504),
  scoring (line 376), and subset helpers (lines 303 and 339).
- [manage_asset_keys.h](../../../gvmd/src/manage_asset_keys.h), for observations, candidate rows, enum types, and
  decision fields.
- [manage_asset_keys_tests.c](../../../gvmd/src/manage_asset_keys_tests.c), including empty candidate maps, multiple
  subsets, equivalent candidates, and partial overlap.

The first two source files were clean in that checkout. Their SHA-256 values are respectively
`353ccca3d4fade09add6d7bcf4312099a57c19e650d4afe2f7f12f24e215638d` and
`54d42f2fb741df93a3880f002061df34899ffb36b8a42cf2ee660043a4a05eb6`. The links identify the reviewed local source; the
fingerprints pin this review even if the sibling checkout changes. Source and tests were inspected, not executed for
this specification.

### 2.1 Sets, comparison, and scoring

Identifiers are maps from integer type to sets of strings. `asset_identifier_map_add` ignores null/empty strings and
eliminates exact duplicates within a type. Comparisons are byte-sensitive `g_str_equal`; there is no normalization,
scope, timestamp, producer, or eligibility check inside the decider.

A map is a subset if every value occurs under the same type in the other map. Null/empty maps and empty per-type sets
are subsets. Multiple values matter individually; a partial overlap is not containment.

Containment iterates **all stored types**, not just the three scored types. The header also lists Agent ID and container
digest; arbitrary integer types can enter the map. They participate in containment but contribute no score. They are not
treated as priority-based strong identities by this function.

The C candidate score is:

```text
float score = 0
score += float(shared MAC value count)      * 1.0f
score += float(shared hostname value count) * 0.4f
score += float(shared IP value count)       * 0.4f
```

Each distinct matching value contributes its type's weight, not one weight per type. Order is MAC, hostname, IP. There
is no minimum score, probability, denominator, penalty for additional candidate identifiers, or score from last-seen
time. The C comment calls MAC “strong”; that means its fuzzy weight, not SPEC-001's strong identifier stage.

**Consequence from the source:** all candidates containing the entire observation share every observed scored value.
Their scores are therefore equal for that observation, regardless of additional identifiers. Score then cannot
distinguish those containing candidates; `last_seen` and input order do. The test comparing MAC-only with
IP-plus-hostname scores tests the helper, not a choice between partially matching candidates in the decider.

### 2.2 Exact decision kernel

Initialize `needs_new_key=1`, `selected_key=NULL`, `selected_index=0`, and no merge indices. Null/empty observation or
absent/zero candidates returns those defaults.

For a nonempty observation `O` and candidate rows `C[i]`:

1. Ignore rows with null/empty asset keys.
2. Search rows satisfying `O ⊆ C[i]`. Choose greater score; on exact score equality choose greater `last_seen`; on equal
   score and time keep the first containing row. The first qualifying row is accepted even with a negative timestamp.
3. If a containing row `S` was selected, reuse its key. In ascending input-index order, add every other keyed row
   satisfying `C[i] ⊆ S`, except rows with the same key string as `S`.
4. Otherwise, add every keyed row satisfying `C[i] ⊆ O`, in input order. If any are found, require a **new** key and
   merge those rows into it; do not reuse even a single contained candidate's key.
5. Otherwise require a new key without merges. Partial intersection alone never causes selection or a merge.

The merge sweep in step 3 compares candidates to the selected candidate, not to the observation. A candidate can share
no identifier with `O` and still merge if it is a subset of `S`. Empty candidate maps also merge in steps 3 or 4. There
is no freshness or score filtering of merge targets.

### 2.3 Edge cases that must not be silently corrected

| Edge                       | Established C behavior                                                                  | Possible change requiring explicit approval                                    |
|----------------------------|-----------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| Empty observation          | New key, no merges, despite empty-set subset mathematics                                | Reject/ignore empty observations at a higher layer                             |
| Empty candidate set        | Cannot contain nonempty observation; is a subset and can merge                          | Exclude candidates with no eligible fuzzy evidence                             |
| Equal score and time       | First containing array row survives                                                     | Key-based tie-break or ambiguity conflict                                      |
| Array permutations         | May change survivor on ties; merge index order follows array order                      | Permutation-invariant survivor requires a new policy                           |
| Multiple values/duplicates | Every distinct value participates; exact duplicates add no count                        | Semantic rather than raw-string duplicate elimination is an intentional change |
| Partial overlap            | No reuse/merge unless some full subset relation also holds                              | Intersection-based matching would change the algorithm                         |
| Unscored/unknown types     | Still constrain containment; score zero for those types                                 | Stage projection and typed validation change treatment                         |
| Duplicate selected key     | All rows sharing survivor key are excluded from merge list                              | No automatic union of their differing snapshots                                |
| Other duplicate keys       | Can appear repeatedly through distinct merge indices; Case B has no key deduplication   | Reject duplicate candidate keys or deduplicate application plan explicitly     |
| Empty/null key             | Row skipped in selection and merge sweeps                                               | Reject malformed candidate input instead                                       |
| Freshness                  | `time_t last_seen` only ranks containing candidates; constructor initializes it to zero | Missing-time representation, expiry, evidence freshness need new rules         |

The C function does not detect contradictory strong evidence, test scanner boundaries, filter authorization, derive
history, or generate asset keys.

## 3. Native inputs, policy, and decision contract

Reuse `IdentifierValue` and the existing package. The reconciliation API takes current active views only:

```go
type Observation struct {
    Identifiers []IdentifierValue
}

type Candidate struct {
    AssetKey    string
    Identifiers []IdentifierValue
    LastSeen    *time.Time
}

type MatchPolicy struct {
    StrongOrder []IdentifierType
    Fuzzy       []FuzzyMember
}

type FuzzyMember struct {
    Type   IdentifierType
    Weight float64
}

func Decide(observation Observation, candidates []Candidate, policy MatchPolicy) (Decision, error)

type Decision struct {
    Action                DecisionAction
    Stage                 MatchingStage
    NeedsNewKey           bool
    SelectedKey           string
    SelectedIndex         *int
    PotentialMergeIndices []int
    PotentialMergeKeys    []string
    Conflict              *ConflictDetails
}
```

`DecisionAction` has CREATE, REUSE, CONFLICT, and REVIEW constants. `MatchingStage` has NONE, STRONG, and FUZZY constants.
`ConflictDetails` contains a reason, implicated candidate indices, and identifier values. Its presence requires a defined
contradiction rule; it is not permission to manufacture a survivor. There are no authorized-merge fields.

No input contains boundary context or history. Applications select eligible active evidence before calling. The library
never unions retained history into Identifiers, discards historical values, derives LastSeen from history, expires evidence,
or reads the wall clock. LastSeen is caller supplied. Identifier normalization and comparison remain SPEC-001B operations.
Unknown, malformed, or unsupported values return the existing validation/normalization errors rather than guessed formats.

Reject duplicate candidate asset keys in the complete supplied list before matching, even if those rows would not match.
Reject empty asset keys with `ErrEmptyCandidateKey` and duplicate nonempty keys with `ErrDuplicateCandidateKey`,
including identical rows. Do not union snapshots, skip unkeyed rows, select a representative, or renumber indices.
Keys are otherwise opaque exact strings; both checks precede identifier matching, even for an empty observation.

### 3.1 Output invariants

| Action | NeedsNewKey | Selected key/index | Potential targets | Meaning |
| --- | --- | --- | --- | --- |
| CREATE | true | Absent | Empty | New key required; no existing identity selected |
| REUSE | false | Present | Empty | Reuse an existing key |
| REVIEW, existing survivor | false | Present | Nonempty | Preserve the fuzzy proposal; application review required |
| REVIEW, new survivor | true | Absent | Nonempty | Preserve the C new-key/subset proposal; application review required |
| CONFLICT | false | Absent | Empty | Defined contradiction; no actionable key plan |

REVIEW is non-actionable, including its proposed key reuse or creation. Applications must apply independently approved
merge safety before acting on a proposal. Do not silently drop potential targets or turn Case B into ordinary CREATE
or REUSE. No decision generates a key, authorizes a merge, or mutates asset state.

SelectedIndex refers to the original supplied array and is nil without a survivor. Potential indices are ascending
input order, exclude the survivor, and have parallel keys. All returned collections and pointers are independently owned.
Inputs are not mutated or retained; concurrent calls are safe while callers do not mutate shared inputs.
Invalid input/policy or an applicable unresolved rule returns an error and a zero, non-actionable Decision. A contradiction
established by the approved incoming-multiplicity rule returns CONFLICT with nil error. Conflict evidence contains
canonical distinct incoming values of the implicated type and original matching candidate indices, if any.
Neither candidate-only differences nor cross-priority disagreements establish additional contradictions.

## 4. Stage 1: Strong matching — APPROVED selection and ranking

### 4.1 Configurable classification and absolute priority

Supported types and their normalization are independent of matching classification. StrongOrder defines both membership
and absolute priority; omission disables a type, and an empty list disables strong participation without restoring defaults.
Applications supply eligible active identifiers; syntactic validity itself is not producer admission. The library does not
re-evaluate scanner boundaries or provenance, or infer global uniqueness from type, scope, or payload.

Determine whether incoming configured strong evidence exists before candidate correspondence. Examine configured types in
order. If one level has no matches, continue to the next: unmatched Greenbone ID does not prevent an Agent ID match.
Stop selection at the first level with a match. Additional identifiers on either side do not require set containment,
and fuzzy value differences or scores cannot veto a strong correspondence.

A unique candidate at that priority reuses its existing key. Lower-priority matches cannot override selection or become
automatic merge targets. Under the default policy, Machine ID matching A takes precedence over BIOS UUID matching B,
even if B is newer. Reordered policy changes that precedence. Cross-priority matches alone are not a defined conflict.

With eligible incoming configured strong evidence and no candidate match, return STRONG CREATE unless incoming multiplicity establishes
CONFLICT under section 4.3. Never run fuzzy on eligible strong no-match, ambiguity, or contradiction. Only absence of incoming configured
strong evidence permits fuzzy entry. Ineligible evidence must already have been excluded from the caller's active view.

### 4.2 Same-priority ranking

For eligible candidates matching one incoming strong value at the winning priority, after applicable conflict checks:

1. Present LastSeen ranks before missing LastSeen.
2. Present UTC instants rank newest first at full nanosecond precision.
3. Equal instants use lexicographically smallest exact unsigned asset-key bytes.
4. If all times are missing, use the same key ordering.

Ignore process-local monotonic readings; equivalent offsets denote equal instants. Do not round strong timestamps.
Nil is missing; present zero and pre-epoch instants rank ahead of missing. Validate present times against the existing
UTC year 1..9999 model contract. Invalid times are errors, not missing times or current time.

Rank the complete matching set, not the first encountered row. Input order must not determine a distinct-key strong tie.
For example asset-10 sorts before asset-2. Newer lower-priority matches, fuzzy scores, or weak values cannot affect this
ranking. Return REUSE with no potential merge targets; strong selection never automatically merges any other key.

### 4.3 Incoming strong multiplicity — APPROVED

Normalize and semantically deduplicate incoming identifiers, preserving complete scope equality. At the highest configured
strong priority with an eligible candidate match, more than one distinct incoming value of that type produces STRONG
CONFLICT. Count all incoming values at that priority, including values that match no candidate. A single incoming value
matching multiple distinct candidate keys uses section 4.2 ranking; it is not a conflict.

A selected higher priority is unaffected by lower-priority multiplicity or disagreement. Multiplicity at an unmatched
higher priority likewise does not veto a match at a lower priority. If no configured strong priority matches any candidate,
multiple distinct incoming values of any configured strong type produce STRONG CONFLICT. Report the first such type in
configured priority order; otherwise return STRONG CREATE. Neither path permits fuzzy fallback.

Candidate-only differing values are not contradictions. CONFLICT has no selected key/index, new-key request, or potential
merge targets. Its evidence identifies the distinct canonical incoming values and matching candidate indices at the
winning priority; the no-match path has no implicated matching indices. No producer trust engine, conflict callbacks,
provenance abstractions, transitive candidate graph, or automatic strong merge operation is introduced.

## 5. Stage 2: Fixed internal C fuzzy containment

### 5.1 Matching views and configuration

Enter only when there is no incoming configured strong evidence in the caller-prepared eligible view. Normalize using
SPEC-001B and project to the configured fuzzy types. Tokens retain canonical type, canonical value, and complete scope.
Deduplicate semantically equal tokens without changing observation history. Multiple distinct values participate separately.
Known out-of-stage identifiers do not affect fuzzy subsets or scores; supported FQDN is unassigned by default.
Fuzzy FQDN membership is rejected with `ErrInvalidMatchPolicy` initially. Explicit strong FQDN membership remains
supported. Do not coalesce hostname/FQDN, expand short names, invent DNS aliases, or change normalization.

Use a fixed internal kernel rather than public compatibility modes or another policy layer. Fuzzy entry order defines
deterministic score accumulation. The Greenbone default supplies MAC, hostname, IP in C order, weighted 1.0, .4, .4.
The kernel reads membership and weights from policy; it does not hardcode classification or scoring constants.
Custom fuzzy entries use their supplied order; map iteration cannot determine sums.

### 5.2 Fixed numeric and freshness behavior

Use the established C float32 weighted intersection-count calculation: round counts, count-times-weight terms, and each
cumulative sum as float32, comparing exact scores without epsilon. FuzzyMember.Weight is configuration storage, converted
to float32 for scoring. Zero (including negative zero), negative, NaN, and infinite weights are rejected with
`ErrInvalidMatchPolicy`; omission disables a type. Positive weights not representable as positive finite float32 cannot
be evaluated. Computed nonfinite scores return errors and no actionable result. No threshold, confidence model, or
overlap-only match is added.

All containing candidates have the same observation intersection score. Compare containing candidates by score descending,
then UTC LastSeen at whole-second precision, then first original input row. Fractional timestamps in the same UTC second
tie; conversion preserves their instant before whole-second comparison, including pre-epoch values. Strong ranking keeps
its separate nanosecond behavior. For fuzzy ranking only, nil LastSeen compares as Unix epoch zero without mutating
the input. Nil ties a present epoch timestamp, outranks pre-epoch timestamps, and retains input-order ties.
A present Go zero time is a valid pre-epoch time, not missing and not Unix epoch zero.

### 5.3 Cases A/B/C and potential merges

For nonempty projected observation O and caller-supplied projected candidates C:

- **A — candidate contains observation:** select a containing candidate using C scoring/time/input-order ranking and
  propose reuse of its key. Collect every other candidate whose set is a subset of the selected candidate's set.
  Compare with the survivor, not O; targets may have no direct overlap with O. Return REVIEW when targets exist,
  otherwise REUSE.
- **B — observation contains candidate:** if no candidate contains O, collect every C[i] subset of O. With any target,
  return REVIEW requiring a new key, even for a single target. Never reuse a contained candidate's key in this case.
- **C — no containment:** return CREATE without potential targets. Partial overlap alone is insufficient.

An empty projected observation returns CREATE without targets before subset sweeps. Preserve C's empty-candidate subset
behavior: supplied eligible candidates made empty by projection also participate as empty subsets. This produces potential
targets only, never merge authorization. Applications must omit candidates they do not admit for this analysis.
Potential targets retain the original supplied input indices and key order. Duplicate-key input is rejected beforehand.

The internal kernel identifies all potential targets. Independent merge safety remains caller-owned and unresolved by
containment. Do not silently discard potential targets or claim that a C subset establishes safe consolidation.

## 6. Caller-owned eligibility, boundaries, and history

Applications must perform scanner/network filtering and equivalence resolution, candidate discovery, permissions,
producer admission, and active/history evidence selection before the call. The library sees only supplied eligible views;
it has no missing-boundary mode, boundary key, scanner field, topology model, or admission callback.
Two scanners may contribute to the same caller-prepared candidate set. Reused private IPs from unrelated networks must be
filtered or otherwise prepared appropriately by applications; raw identical payloads in supplied equally scoped views
will match. This is an explicit application responsibility, not a library inference of global uniqueness.

Scope is different: the library always compares supplied identifier scope exactly under SPEC-001B, including absent versus
empty scope. Caller boundary ownership cannot justify dropping scopes or substituting scanner IDs into them.

The API reads no history and performs no automatic union, latest-value replacement, last-seen derivation, age cutoff,
expiry, or wall-clock lookup. Applications retain prior values and choose active evidence. Historical values must not be
automatically reassigned to the latest scanner/network context by this library. History persistence, pruning, retention,
and merge application remain application concerns.

## 7. Policy defaults and validation

`MatchPolicy` contains only StrongOrder and ordered Fuzzy members. No boundary settings, migration modes, compatibility
switches, configuration loading, YAML, or policy callbacks are implemented. Each default policy and clone owns its slices.

| Stage | Supported type | Priority or weight |
| --- | --- | --- |
| Strong | greenbone_id | 1, highest |
| Strong | agent_id | 2 |
| Strong | machine_id | 3 |
| Strong | bios_uuid | 4 |
| Strong | ssh_host_key | 5 |
| Strong | tls_certificate_public_key_hash | 6 |
| Strong | cloud_identifier | 7 |
| Fuzzy, accumulation order 1 | mac | 1.0 |
| Fuzzy, accumulation order 2 | hostname | .4 |
| Fuzzy, accumulation order 3 | ip | .4 |
| Unassigned | fqdn | No default matching contribution |

Callers may select/reorder/omit supported strong types and configure fuzzy types/weights independently of normalization.
A type cannot participate in both stages. Reclassification requires removal from its former stage; it is not automatic.
An empty policy is valid and yields no matching evidence. It does not silently restore defaults or suppress fuzzy entry.
An empty fuzzy observation then follows C's CREATE guard.

Validate before matching: reject duplicate strong or fuzzy entries, unknown types, overlap, zero/negative/NaN/infinite
weights, and explicit fuzzy FQDN membership with `ErrInvalidMatchPolicy`. Do not silently overwrite, deduplicate, infer
membership, normalize type names, guess a DNS projection, or interpret zero as disabling a member.
Input normalization remains independent of policy. Existing supported producer formats are unchanged.

## 8. Decision scenarios

G/A/MI/B denote eligible Greenbone/Agent/Machine/BIOS values; P/H denote IP/hostname. Equal tokens have equal identifier
Scope unless stated. All rows use caller-prepared eligible views and present whole-second fuzzy timestamps unless noted.
Potential targets are informational; REVIEW never authorizes mutation.

| Scenario | Observation | Candidates | Result |
| --- | --- | --- | --- |
| Unique strong | G(g) | K1:G(g) | STRONG REUSE K1 |
| Strong plus changed IP | G(g),P(p2) | K1:G(g),P(p1) | STRONG REUSE K1 |
| Highest matching priority | G(g),A(a) | K1:G(g)@10; K2:A(a)@20 | STRONG REUSE K1 by default order |
| Custom Agent-first priority | G(g),A(a) | K1:G(g); K2:A(a) | STRONG REUSE K2 |
| Unmatched higher priority | G(g),A(a) | K1:A(a) | STRONG REUSE K1 |
| Machine versus BIOS | MI(x),B(u) | KA:MI(x); KB:B(u) | STRONG REUSE KA by default |
| Same-value strong freshness | G(g) | K1:G(g)@10; K2:G(g)@20 | STRONG REUSE K2; no potential merges |
| Strong equal-time key tie | G(g) | asset-2:G(g)@20; asset-10:G(g)@20 | STRONG REUSE asset-10 |
| Strong nanosecond distinction | G(g) | K1:G(g)@200s+1ns; K2:G(g)@200s+2ns | STRONG REUSE K2 |
| Missing strong timestamp | G(g) | K1:G(g)@missing; K2:G(g)@-1 | STRONG REUSE K2 |
| Eligible strong no-match | G(g),P(p1) | K1:P(p1) | STRONG CREATE; never fuzzy |
| Multiple values at winning priority | G(g1),G(g2) | K1:G(g1); K2:G(g2) | STRONG CONFLICT; no key plan |
| Only one winning value matches | G(g1),G(g2) | K1:G(g1) | STRONG CONFLICT |
| Lower-priority multiplicity | G(g),A(a1),A(a2) | K1:G(g); K2:A(a1) | STRONG REUSE K1 |
| Unmatched higher-priority multiplicity | G(g1),G(g2),A(a) | K1:A(a) | STRONG REUSE K1 |
| No-match multiplicity | G(g1),G(g2),P(p1) | K1:P(p1) | STRONG CONFLICT; never fuzzy |
| Candidate-only differences | G(g1) | K1:G(g1),G(g2) | STRONG REUSE K1 |
| Fuzzy containing candidate | P(p1) | K1:P(p1),P(p2) | FUZZY REUSE K1 |
| Fuzzy contained candidate | P(p1),P(p2) | K1:P(p1) | FUZZY REVIEW; new key proposed; target [K1] |
| Partial overlap | P(p1),P(p3) | K1:P(p1),P(p2) | FUZZY CREATE |
| Fuzzy input-order tie | P(p1) | Z:P(p1)@20; A:P(p1)@20 | REVIEW; Z survivor; target [A] |
| No direct observation overlap | P(p1) | K1:P(p1),H(h)@20; K2:H(h)@10 | REVIEW; K1 survivor; target [K2] |
| Empty observation | Empty | Any keyed distinct rows | FUZZY CREATE; no targets |
| Empty candidate view | P(p1) | K1:empty | REVIEW; new key proposed; target [K1] |
| Scope differs | P(p1) in scope s1 | K1:P(p1) in scope s2 | FUZZY CREATE; no scope coalescing |
| Absent versus empty scope | G(g) with nil scope | K1:G(g) with empty scope | STRONG CREATE |
| Caller filters candidate | P(p1) | Empty supplied list | FUZZY CREATE |
| Caller supplies equal eligible values | P(p1) | K1:P(p1) | FUZZY REUSE, with no scanner check |
| Disabled strong membership | G(g),P(p1) | K1:P(p1); G omitted from policy | FUZZY REUSE K1 |
| Duplicate candidate keys | Any | Two rows with key K | Duplicate-key input error before matching |
| Empty candidate key | Any | One row with empty key | Empty-key input error before matching |
| Missing fuzzy timestamp | P(p1) | K1:P(p1)@missing | FUZZY REUSE K1; nil ranks as epoch |
| Nil versus epoch fuzzy tie | P(p1) | Z:P(p1)@missing; A:P(p1)@0 | REVIEW; Z survivor; target [A] |
| Nil versus pre-epoch fuzzy time | P(p1) | Z:P(p1)@-1; A:P(p1)@missing | REVIEW; A survivor; target [Z] |
| Zero fuzzy weight | Any | Any | Invalid-policy error; omit type to disable |
| Explicit fuzzy FQDN | Any | Any | Invalid-policy error; strong FQDN remains supported |
| Fuzzy subsecond tie | P(p1) | Z:P(p1)@200s; A:P(p1)@200s+999ns | REVIEW; Z survivor; target [A] |

Pinned C regression fixtures additionally characterize multiple values, duplicates within sets, negative timestamps,
empty subsets, equivalent candidates, and exact selected score bits. Typed normalization, scopes, stage projection,
and duplicate-key input rejection are explicit limits on raw-C compatibility.

## 9. Acceptance criteria and verification

- One public Decide API coordinates existing strong helpers and the internal fuzzy kernel in the same package.
- Observation/Candidate contain no BoundaryContext, BoundaryID, ScannerID, or history field.
- MatchPolicy contains only configurable StrongOrder and ordered Fuzzy members; no boundary or compatibility modes remain.
- Applications own candidate filtering, source admission, active views, permissions, equivalence, and all persistence.
- SPEC-001A/B semantics remain unchanged: complete scope equality, nil versus empty, canonicalization, and supported formats.
- Strong configured membership determines stage entry before candidate correspondence; no-match never enables fuzzy.
- Strong priority remains absolute; same-value ranking uses UTC nanoseconds, missing last, then exact key bytes.
- Strong reuse returns no potential merge list. Incoming multiplicity produces CONFLICT only under section 4.3.
- Semantic duplicates count once; candidate-only differences and lower-priority disagreements cannot veto selection.
- No-match multiplicity conflicts without fuzzy fallback; no-match single values require a new key.
- Duplicate nonempty and empty keys are rejected before matching, including identical rows and empty observations.
- Output indices reference the original supplied list without renumbering.
- Zero/negative/NaN/infinite fuzzy weights and fuzzy FQDN membership are invalid policies.
- Fuzzy nil LastSeen compares as Unix epoch zero; whole-second/input-order ties and input immutability are preserved.
- Fuzzy numeric/time/input-order behavior and Cases A/B/C preserve the pinned C kernel after policy projection.
- C empty-observation guard, empty subsets, one-row Case B, and merges without observation overlap are covered by tests.
- Potential merge targets produce REVIEW with proposed key information intact; no merge authorization is encoded.
- Default construction and cloning return independent slices; inputs and returned data do not alias mutable caller state.
- No database, external service, GLib, cgo, authorization, scanner lookup, callback policy engine, or new package is added.
- Table-driven tests cover strong/fuzzy integration, custom classification, scope differences, errors, and concurrent calls.
- Existing C regression fixtures retain exact selected keys, score bits, and potential index order for compatible data.
- Run go test ./..., go test -race ./..., CGO_ENABLED=0 go test ./..., and go vet ./....

## 10. Compatibility with C

The reference C source in section 2 remains authoritative for fuzzy subset relations, float scoring, whole-second
freshness, input-order ties, and survivor/new-key proposals. Native Go adds the strong-first stage, SPEC-001B semantic
normalization, complete scopes, configurable fuzzy membership, incoming strong-multiplicity conflicts, key validation,
and explicit REVIEW. C skips unkeyed rows and permits duplicate-key row semantics; Go rejects both before matching.
Nil fuzzy LastSeen maps to the zero initialized by the C candidate constructor, while a present Go zero time remains
pre-epoch. Zero weights and fuzzy FQDN are rejected configuration, not alternate containment behavior.
C merge outputs become non-actionable potential targets in Go; survivor/new-key proposals retain their meanings.
No scanner boundary filtering is introduced in either kernel. Candidate/evidence preparation belongs to applications.

Compatibility is demonstrated only for canonical supported fuzzy values with equal scopes, equivalent supplied views,
distinct keyed candidates, and present whole-second timestamps. Canonicalization can change duplicates or containment.
The captured C fixtures and native Go tests demonstrate that domain; they do not certify producer trust or merge safety.

## 11. Remaining application decisions and extension limits

The minimal library rules above are approved and deterministic for valid caller-prepared eligible inputs. Producer trust,
historical eligibility, scanner boundaries, qualification, discovery, and permission checks remain application-owned.
Supplying syntactically valid identifiers alone does not establish those admission facts.

Applications must define independent merge-safety predicates before applying potential targets. Strong selection and
fuzzy containment authorize no same-priority, lower-priority, graph-connected, or other candidate consolidation.
Any future contradiction rule beyond incoming multiplicity or fuzzy FQDN support requires an explicit domain decision;
none is inferred from candidate-only differences, absence, or retained history. Do not introduce new policy hooks or a
provenance framework to fill those gaps. `ErrUnresolvedMatchingRule` remains available for API compatibility, but the
approved multiplicity, key validation, weight, FQDN rejection, and timestamp branches no longer return it.

## 12. Out of scope

Database access/mutation, identifier/key generation, scanner/network discovery or equivalence, authorization, provenance
verification, history eligibility/retention, merge application, YAML/configuration loading, the future C adapter, and
unapproved contradiction/merge-safety rules. None is implemented through hidden defaults or added policy layers.
