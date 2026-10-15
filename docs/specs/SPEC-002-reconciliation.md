# SPEC-002: Asset Reconciliation and Merge Decisions

**Status:** Draft — configurable matching policy, strong selection/ranking, fuzzy fallback, and defined boundary admission APPROVED; remaining domain decisions require approval\
**Component:** asset-identity  
**Parents:** [SPEC-001](SPEC-001-identifiers.md), [SPEC-001A](SPEC-001A-identifier-model.md), [SPEC-001B](SPEC-001B-normalization.md)  
**Scope:** One native Go reconciliation algorithm with strong matching and a legacy containment-based fuzzy fallback

## 1. Purpose, authority, and approval boundaries

Define one shared identity decision algorithm for gvmd and gvmd-lite/gvmd-ng. The future C adapter must call the same Go
implementation. Callers discover candidates, perform OSI permitted-scope authorization, generate keys, and persist/apply
decisions. The library does none of those operations.

This document distinguishes:

- **Required architecture:** the two stages, absolute configurable strong priority, SPEC-001B semantic equality, no
  automatic connected-candidate merging, and caller-applied decisions requested for SPEC-002.
- **APPROVED domain rule:** fuzzy fallback is allowed only when the incoming observation has no eligible strong identifiers. Eligible strong no-match, ambiguity, and contradiction never permit fuzzy fallback.
- **APPROVED strong selection:** select at the highest configured priority with an eligible match; reuse a unique candidate key without containment or a weak-identifier veto. Lower-priority matches do not override that selection or authorize merges.
- **APPROVED configurable matching architecture:** supported types are independent of classification; callers select/reorder/disable strong members and configure fuzzy members/weights through one policy model. Algorithms must not embed the default type lists or weights.
- **APPROVED same-priority ranking:** after candidate eligibility and strong-conflict checks, reuse the newest present UTC LastSeen at nanosecond precision; missing ranks last and timestamp ties use the smallest exact-byte asset key. Ranking never changes strong priority or authorizes merges.
- **APPROVED boundary contract:** qualified logical BoundaryID, optional ScannerID provenance, caller-resolved equivalence, deterministic compatibility, strict/legacy fuzzy selection and merge evaluation, strict default for new deployments, and caller-partitioned history. Boundary-key qualification, producer provenance, and independent merge-safety predicates remain pending.
- **Established legacy behavior:** the inspected C source and existing tests, described in section 2. This is
  authoritative for the fuzzy containment kernel.
- **Proposals:** new Go representations, eligibility/conflict modes, and compatibility changes explicitly identified
  below. None constitutes an approved Greenbone business rule.
- **PENDING DOMAIN DECISION:** cases with no approved deterministic business outcome. Implementation must not fill these
  gaps through a hidden default.

Strong matching may establish value correspondence without proving scope sufficiency or merge safety. Syntactic
validity, semantic equality, matching eligibility, and merge eligibility are different responsibilities. Earlier
identifiers/history must not be discarded because later values differ.

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
| -------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
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

## 3. Proposed inputs, output, and native Go API

Reuse `IdentifierValue` and `ObservationHistory`; do not create a second identifier representation. The following are
proposed native data layouts, not implementation; BoundaryContext roles and the single-boundary matching-view contract are approved in section 6.1:

```go
type BoundaryContext struct {
BoundaryID string // caller-resolved, qualified logical boundary; empty: missing/unresolved
ScannerID  string // optional observation provenance, not boundary identity
}

type Observation struct {
Identifiers []IdentifierValue // caller's explicit current matching view
History     ObservationHistory
Boundary    BoundaryContext
ObservedAt  *time.Time
}

type Candidate struct {
AssetKey    string
Identifiers []IdentifierValue // explicit matching view of this snapshot
History     ObservationHistory
Boundary    BoundaryContext
LastSeen    *time.Time
}

type MergeDecision struct {
Action        DecisionAction // CREATE, REUSE, MERGE, CONFLICT
Stage         MatchingStage  // NONE, STRONG, FUZZY
Reason        ReasonCode
NeedsNewKey   bool
SelectedKey   string // empty: no survivor selected
SelectedIndex *int   // nil: no selected candidate
MergeIndices  []int
MergeKeys     []string // parallel to MergeIndices
Evidence      []IdentifierValue
Conflict      *ConflictDetails
}

func Decide(observation Observation, candidates []Candidate,
policy MatchPolicy) (MergeDecision, error)

```

`DecisionAction`, `MatchingStage`, and `ReasonCode` are proposed defined string types with constants. `ConflictDetails`
is proposed to contain a reason plus implicated candidate indices/keys and typed matched or contradictory values. It
must explain ambiguity without manufacturing a survivor. It is not a graph or automatic merge plan. The policy's fields
and valid modes are specified conceptually in section 7; final enum names and minimal Go struct layout require approval.

History is available for policies that explicitly evaluate historical evidence. It is **not automatically unioned** into
`Identifiers`, and no latest-value replacement or implicit timestamp aggregation is allowed. The explicit matching view
permits retained history to coexist with policy-selected active evidence. Callers must partition supplied historical evidence by logical boundary before reconciliation, as approved in section 6.1. Within that partition, how callers choose the active view and which historical values remain eligible are open domain decisions.

Normalization uses SPEC-001B; exact type and complete identifier scope remain significant unless an explicitly approved
stage projection applies. Duplicate semantically equal values collapse within each matching view, without collapsing
observation records. Unknown types/malformed supplied values are proposed input errors; syntactically valid but
ineligible values are filtered with diagnostic reasons. Treatment of known but unsupported producer formats requires the
explicit invalid-input policy below. Do not silently drop them.

Inputs include no authorization-scope object: OSI permission filtering is caller-owned. Asset keys are opaque exact
strings. The proposed algorithm does not mutate or retain caller slices/maps/pointers; all returned evidence and
collections must be independent copies. Calls are concurrent-safe while input data is not concurrently mutated.

### 3.1 Output invariants

| Action                   | NeedsNewKey | Selected key/index | Merge keys/indices | Meaning                                                                       |
| ------------------------ | ----------- | ------------------ | ------------------ | ----------------------------------------------------------------------------- |
| CREATE                   | true        | None               | Empty              | Caller generates a new key; no existing identity selected                     |
| REUSE                    | false       | Existing survivor  | Empty              | Preserve the existing key                                                     |
| MERGE, existing survivor | false       | Existing survivor  | Nonempty           | Approved existing keys consolidate into the survivor                          |
| MERGE, new survivor      | true        | None               | Nonempty           | Caller generates a new key and merges listed existing keys into it            |
| CONFLICT                 | false       | None               | Empty              | No actionable key creation/reuse/merge authorized; report implicated evidence |

`MERGE` denotes any nonempty merge plan, including Case B with one existing key plus the incoming identity. This action
labeling is a proposal; C exposes only fields. The new key's actual value is never present in a library decision. A
conflict must not be encoded as ordinary CREATE.

Indices always refer to the original supplied candidate array, including rows later excluded by eligibility. Merge
indices are ascending input order and do not contain the selected index. Keys mirror those indices, not a separately
sorted list. Duplicate-key handling is an explicit policy decision. A survivor key never appears as its own merge
target.

C-compatible fields `needs_new_key`, `selected_key`, `selected_index`, and `merge_indices` map to the native fields
above; needs-new-key, selected-key, and merge indices retain their logical meanings. Native selected-index presence is
explicit; C's zero is not a valid selected index when no key is selected. A future adapter must distinguish CONFLICT,
absent index/time, scopes, and reason/evidence data; define neither an ABI nor C ownership now.

## 4. Stage 1: Strong matching contract

### 4.1 APPROVED classification and absolute priority

The Greenbone default order, highest first, is:

1. Greenbone ID
2. Agent ID
3. Machine ID
4. BIOS UUID
5. SSH host key
6. TLS certificate public-key hash
7. Cloud identifier

The default is supplied by the Greenbone matching policy, not embedded in the selection algorithm. `MatchPolicy.StrongOrder` determines both membership and absolute priority using stable supported SPEC-001A type names. Callers may choose any supported types, reorder them, or omit them to disable strong participation. Compare eligible values using unchanged SPEC-001B semantic equality, including explicit scopes. Matching classification does not change a type's normalization contract.

Determine incoming strong eligibility before candidate correspondence. Evaluate configured types in order. At each priority level, determine the existing candidates matching any eligible incoming value of that type against eligible candidate values. If that level has no eligible match, continue to the next configured level: an unmatched Greenbone ID does not prevent an eligible Agent ID match from selecting a candidate.

Stop candidate selection at the first (highest-priority) level with an eligible match. A unique matching candidate at that level is selected and its existing `asset_key` is reused. Lower-priority matches must not override that selection. If multiple eligible candidates match the same strong value at that level, apply the approved same-priority ranking after strong-conflict checks. Priority alone selects no unique key; ranking is restricted to that winning level and must not descend to lower priority. Conflicting multiple values and duplicate asset-key rows remain pending.

Additional identifiers on either side do not prevent a match; identifier-set containment is not required. Under the default classification, differing fuzzy MAC, IP, or hostname values do not override a valid strong match. If a caller explicitly reclassifies a supported type, evaluate it in its configured stage; there is no hardcoded weak/strong type exception. No fuzzy score, threshold, candidate freshness, or count of lower-priority matches may override the configured precedence.

If eligible incoming strong identifiers exist but none match at any configured level, return CREATE with `NeedsNewKey=true` (`needs_new_key=1`), no selected key/index, and no merge targets, provided no unresolved strong conflict exists. Do not execute fuzzy matching. If no eligible incoming strong identifiers exist, enter the original C fuzzy containment stage as previously approved.

### 4.2 APPROVED selection separation; pending ambiguity/conflict/merge rules

Asset merging is a separate operation. Selecting an existing key does not automatically authorize merging any other candidate key. A strong selection alone returns REUSE with `NeedsNewKey=false`, the existing selected key/index, and empty merge lists. Do not merge lower-priority matching candidates, same-priority candidates, or transitively connected candidates through selection alone.

Absolute priority resolves **candidate-selection precedence** when different identifier types match different keys. For example, under the Greenbone default order, Machine ID selecting asset A takes precedence over BIOS UUID matching asset B. A caller-provided order determines precedence when these types are reordered. Selection of A is APPROVED; how to report that cross-key disagreement and whether a separate merge operation could ever admit B remain unresolved. Do not label the precedence choice itself pending, or silently convert a lower-priority match into a different survivor.

Once selection stops, additional evidence may be examined for diagnostics or a separately approved conflict/merge evaluation. Such evaluation must not continue candidate selection, override absolute precedence, or authorize an automatic merge. No new conflict reporting or merge eligibility rule is approved by this selection contract.

The following remain **PENDING DOMAIN DECISION**:

- Duplicate candidate rows sharing an asset key, including rows with differing timestamps/evidence. Do not silently union, discard, or select a representative row; their input handling and selected-index semantics remain pending.
- Multiple values of one strong type matching different candidates at the same applicable priority. Do not choose based on identifier input order or descend to a lower level; the same-priority resolution contract remains open.
- Whether differing strong values represent contradictions, permitted multiplicity, or historical evidence. Absence is not automatically a contradiction.
- Conflict diagnostics and separate merge eligibility for candidates matching different types at different priorities. The approved higher-priority selection remains distinct from these decisions.
- Handling an unresolved strong contradiction when no candidate matches; CREATE applies only when no unresolved strong conflict exists. Fuzzy fallback is never allowed with eligible strong evidence.

The same-priority ranking below is **APPROVED** for eligible matching candidates after strong-conflict checks. It complements unique-match selection without changing absolute precedence, fuzzy fallback, or merge authorization. Candidate-linked evidence/diagnostics, duplicate-key rows, and conflicting multiple incoming values remain separate pending decisions.

### 4.2.1 APPROVED same-priority ranking

Apply ranking only after candidate eligibility and strong-conflict checks, at the first, highest configured priority with an eligible match. Identify all eligible candidates matching the same incoming strong identifier value at that priority before ranking. Do not rank an unchecked matching set or use ranking to make contradictory evidence harmless. Conflicting multiple values and duplicate-key row cases remain pending under section 4.2.2.

Approved ranking, in order:

1. Candidates with a valid present `LastSeen` rank before candidates with missing `LastSeen`.
2. Among present timestamps, the most recent UTC instant ranks first.
3. For equal instants, choose the lexicographically smallest exact `AssetKey`.
4. If all timestamps are missing, choose the lexicographically smallest exact `AssetKey`.

Compare UTC timestamps at full nanosecond precision, consistent with SPEC-001A's timestamp representation. Convert offsets to the same UTC instant for comparison and disregard any process-local monotonic reading; do not round to seconds. Equal instants with different offsets are tied. Missing means `nil`, not Go zero time or the Unix epoch. A valid present zero time or pre-epoch instant ranks ahead of missing, even if it is older than every other present instant. Invalid supplied timestamps must follow the input-validation contract; do not coerce them to missing or current time. Timestamp precision, present/missing ordering, and instant comparison are APPROVED. Any unresolved input-admission behavior for invalid timestamps remains separate; invalid input must not be treated as a valid ranking timestamp.

Use APPROVED lexicographic unsigned byte ordering of exact Go string key bytes, independent of locale, case folding, or natural/numeric sorting. For example, `asset-10` sorts before `asset-2`. Candidate-array order must not determine the surviving key when matching keys are distinct. Merge output ordering and fuzzy input-order ties are unchanged. Duplicate candidate rows sharing an asset key remain PENDING DOMAIN DECISION regardless of timestamp differences. Equal key/time rows additionally show why ranking alone cannot choose an original row/index or evidence source. Do not add an input-order tie-break or silently collapse duplicate keys.

APPROVED result: REUSE the winning existing key, `NeedsNewKey=false`, selected original candidate index, and empty merge lists. Do not continue to a lower priority, compare fuzzy scores or weak identifiers, or merge any other matching candidate. A lower-priority candidate's newer time cannot affect the ranking set. Freshness selects a survivor within this set; it establishes neither eligibility by itself nor merge safety.

### 4.2.2 Multiple values and conflict boundary — STILL PENDING

When different eligible incoming values of the same strong type match different keys, ranking their union is not automatically permitted by the approved same-value ranking rule. An explicitly approved strong-conflict rule must first establish that those values are compatible for this operation. Until then, the outcome is PENDING DOMAIN DECISION; do not treat disagreement as harmless multiplicity, silently choose the newest row, descend to lower priority, or fall back to fuzzy.

The approved ranking does not define producer authenticity, strong contradiction detection, namespace sufficiency, boundary admission, or separate merge eligibility. Duplicate candidate rows sharing an asset key also remain pending; the ranking contract must not decide their representative row. It applies to an agreed eligible matching set and cannot resolve a substantive contradiction through timestamp recency.

### 4.2.3 Matching evidence for a later merge decision — PROPOSED

Propose retaining enough independently owned decision evidence to explain the selected winner and support later evaluation: winning type and configured priority position; all eligible matched values with complete scopes; every same-priority matching candidate's original index/key, matched values, and present/missing `LastSeen`; the selected candidate and ranking reason; and any known unresolved contradiction or exclusion diagnostics.

The current flat `Evidence []IdentifierValue` sketch cannot by itself associate values/timestamps with all candidates. A minimal candidate-linked evidence collection is therefore a proposed output extension; exact field names/layout require approval. Do not populate actionable merge indices/keys merely to carry nonselected candidates. Candidate-linked evidence is informational and grants no merge authorization.

### 4.2.4 Review against approved requirements

The APPROVED ranking is compatible with absolute priority, unique-match reuse, the approved fuzzy fallback gate, and separation of selection from merging when applied after eligibility and strong-conflict checks at one winning priority. This is an approved library rule; it is not claimed to exist in the inspected C fuzzy implementation.

Consequences and remaining boundaries:

- A newest timestamp identifies the selected survivor, not the most trustworthy identifier or a safe merge target. Future-dated inputs could win unless a separately approved validation/eligibility rule excludes them; do not invent an age/skew threshold here.
- Full nanosecond precision can choose a different survivor than whole-second comparison. This is an APPROVED strong-stage choice and does not change C fuzzy timestamp behavior.
- Lexicographic keys remove input-order dependence for distinct keys, but key representation/case can affect tie results. No natural sorting is inferred.
- Missing-oldest ordering is distinct from mapping missing to epoch, especially for pre-epoch or present-zero times.
- Ranking different incoming strong values without conflict approval could hide contradictions. Duplicate keys can leave original selected-index/evidence ambiguity even when the surviving key is fixed.

Ranking, nanosecond UTC comparison, missing-last ordering, exact-byte lexical ties, key reuse, and no automatic merging are APPROVED. This update authorizes no Go implementation. Candidate-linked evidence/diagnostics, conflicting multiple values, duplicate-key rows, and strong merge eligibility remain pending.

### 4.3 Strong stage result states and fallback

**APPROVED: Fuzzy fallback is allowed only when the incoming observation has no eligible strong identifiers.**

Determine incoming strong eligibility before testing candidate correspondence. Lack of a matching or eligible candidate does not make an incoming strong identifier ineligible.

- With no eligible incoming strong identifiers, execute the existing C fuzzy containment algorithm on the fuzzy matching views. Ineligible strong identifiers do not block entry when no other eligible strong identifier exists.
- With at least one eligible incoming strong identifier, do not execute fuzzy matching, regardless of matching MAC/IP/hostname values.
- If strong matching finds a unique valid candidate at the highest matching priority, reuse its asset key. Lower-priority disagreement does not change the approved precedence; unresolved conflict diagnostics and separate merge eligibility remain explicit.
- If no strong candidate matches and no unresolved strong conflict exists, return CREATE with no selected key or merge targets.
- After eligibility and strong-conflict checks, resolve same-value multiple-candidate selection through the approved ranking. Unresolved contradictions, incompatible multiple values, and duplicate-key rows remain separate domain cases. Never resolve them through fuzzy fallback.

This approved gate changes stage entry only. Once entered, preserve the existing C fuzzy containment behavior, including the empty-observation guard, scoring, tie-breaking, and Cases A/B/C. Other eligibility/projection proposals remain separate decisions.

| Strong state                                              | Established constraint / result                                                            | Pending outcome                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| No eligible incoming strong values                        | APPROVED: enter C fuzzy stage; reason `NO_ELIGIBLE_STRONG_EVIDENCE`                        | Eligibility definitions may explain exclusions; fallback gate resolved     |
| Eligible incoming strong values, no valid candidate match | APPROVED: CREATE without selected/merge keys if no unresolved strong conflict; never fuzzy | Strong-conflict definition/resolution remains pending                      |
| Unique candidate at highest matching priority | APPROVED: REUSE existing key; no containment or weak veto; no automatic merges | Conflict reporting/independent merge eligibility, where relevant, remain separate |
| Multiple candidates at highest matching priority | APPROVED: rank eligible same-value matches after strong-conflict checks, then REUSE; never fuzzy/lower-priority escape | Conflicting multiple values, duplicate-key rows, evidence/diagnostics, and merge eligibility remain pending |
| Different keys match different priorities | APPROVED: unique candidate at highest matching priority is selected; lower priority cannot override or auto-merge | Cross-key conflict reporting and separate merge eligibility remain pending |
| Strong contradiction                                      | Explain implicated types/values/keys; never fuzzy                                          | Strong-conflict definition/resolution remains pending; no silent selection |
| Strong match, weak differences                            | Strong correspondence remains usable without fuzzy containment                             | If other strong evidence contradicts, apply conflict rules                 |

The approved fallback gate is mandatory and cannot be relaxed by matching policy. Only absence of eligible incoming strong identifiers permits fuzzy entry; eligible strong no-match, ambiguity, and contradiction never do. No candidates can select an existing key; absent other conflicting input, CREATE is
required and there is no merge target.

## 5. Stage 2: Fuzzy containment contract

### 5.1 Projection and duplicate handling

Enter this stage only under the approved rule in section 4.3. Stage entry does not change the existing C fuzzy kernel once entered.

The default Greenbone policy supplies MAC, IP, and hostname with weights `1.0`, `0.4`, and `0.4`. Callers configure fuzzy membership and weights independently of the supported type definitions. The algorithm projects only configured fuzzy types and reads weights from policy; it must not hardcode these three types or constants. Apply approved
stage/candidate/evidence eligibility before constructing sets. Tokens consist of canonical type, canonical value, and
complete supplied identifier scope; timestamps are not token identity.

**Proposed DNS projection:** `coalesce_equal_names` maps hostname and FQDN into one temporary DNS bucket only when
normalized spelling and supplied scope agree. Duplicate spellings from both input types count once in set containment
and intersections. Do not rewrite underlying observations, call cross-type SPEC-001B equality, expand short names, or
infer DNS aliases. This is an explicit reconciliation projection, not a normalization amendment, and needs approval.

An alternative `hostname_only` projection ignores FQDN in this stage and never double-counts it. The Greenbone default classification enables hostname only and leaves FQDN unassigned. How an explicitly configured FQDN participates, including whether coalescing is enabled, remains **PENDING DOMAIN DECISION**. Configuring two separately scored DNS buckets that count the same DNS identity
twice is invalid. The policy must explicitly specify how FQDN contributes; supported model type does not automatically
mean separately scored evidence.

The new two-stage design projects out configured strong types before fuzzy containment. This differs from C's all-type
containment. Known out-of-stage types are retained as evidence/history but do not affect fuzzy subsets or scores.
Candidate merge eligibility must still consider strong contradictions when required by policy; projecting strong values
away cannot silently authorize unsafe merges.

Distinguish an originally empty candidate from one that becomes empty through projection/filtering. A policy that
excludes such a candidate from matching must not subsequently merge it through the vacuous empty-subset rule. Whether
otherwise eligible empty fuzzy sets may merge is an explicit compatibility decision.

### 5.2 Containment and score

For eligible projected sets `F(O)` and `F(C[i])`, preserve the C subset/intersection relations, including multiple
distinct values and duplicate elimination. No partial-overlap match or minimum-score threshold is added.

Use C's weighted intersection-count formula. Preserve MAC/DNS/IP evaluation order for the Greenbone defaults; custom fuzzy classifications require a documented deterministic accumulation order independent of map iteration. Changing classification or weights must not replace the containment-based algorithm. Proposed native weight representation is `float32`,
with finite nonnegative values and at least one positive enabled weight. The legacy preset uses `float32(1.0)` and
`float32(0.4)`, rounds count-to-weight terms and cumulative sums as float32 in MAC/DNS/IP order, and uses exact score
comparison without epsilon. A different numeric precision, rational scoring, accumulation order, tolerance, or threshold
needs explicit approval and compatibility tests. Overflow/nonfinite computed scores are proposed input-size errors, not
rankings.

All containing candidates have the same projected score for a fixed observation. Retain the scoring contract for
fidelity and configurable weights; do not replace containment selection with ranking arbitrary intersections merely to
make weights affect selection.

### 5.3 Cases A, B, and C

**A — existing candidate contains observation:** If `F(O)` is nonempty and at least one eligible keyed candidate
contains it, rank those candidates by score descending, then `LastSeen` descending under the approved missing-time rule,
then explicit tie-break. Preserve the selected key. In original index order, propose merges for other merge-eligible
candidates whose fuzzy sets are subsets of the selected fuzzy set, excluding survivor-key rows. No requirement for an
intersection with the observation is added in the legacy kernel.

**B — observation contains candidate (s):** When no eligible candidate contains the observation, collect merge-eligible
keyed candidates with `F(C[i]) ⊆ F(O)`. If nonempty, require a **new** asset key and list them to merge. Even one
candidate does not become the survivor. No age/score ordering limits the legacy subset list.

**C — no containment:** Require a new key without merges. Overlap alone is insufficient. If `F(O)` is empty, preserve
the C early-return behavior: CREATE without merges, rather than selecting every candidate through vacuous containment. A
preceding terminal strong result takes precedence.

The subset kernel does not establish merge safety. New eligibility/conflict restrictions applied to selection or any
merge target require explicit approval and must report diagnostic exclusions. With no approved restrictions, document
literal C consequences rather than silently adding safety guards.

## 6. Eligibility, boundaries, history, and freshness

Authorization scope, identifier namespace, and scanner/network boundary are separate:

- Caller-side OSI authorization determines which snapshots the library may receive; it is not implemented here.
- Identifier scope is SPEC-001A namespace data and remains part of semantic equality.
- Boundary context expresses observation provenance. Equal scanner IDs do not automatically mean one network, and
  different scanners do not automatically mean different identities.

Eligibility must be evaluated inside the algorithm using supplied context and explicit policy, not assumed from
candidate discovery. Logical boundary IDs, optional scanner provenance, current/history evidence, and candidate time must be representable.
Producer eligibility facts that cannot be derived from `IdentifierValue` (for example TLS name-check provenance) need an
agreed input extension or caller-attested admission data; the minimal input sketch does not pretend they can be
inferred. Their representation is **PENDING DOMAIN DECISION**.

The defined boundary model, compatibility outcomes, strict/legacy fuzzy admission, and caller partitioning requirements in section 6.1 are APPROVED. Independent merge-safety predicates, boundary-key qualification, and producer-specific provenance requirements remain pending. Boundary admission does not change approved priority, ranking, fallback, or the fuzzy kernel. Neither absent context nor scanner equality establishes compatibility; legacy relaxes UNKNOWN fuzzy admission only.

Future rules may exclude unspecified/multicast/randomized/duplicated weak identifiers, reused hostnames, unreliable
strong placeholders, insufficient namespaces, or unproven TLS evidence. No such exclusion follows from SPEC-001B syntax
validity alone. Do not implement unspecified thresholds or a blanket network-boundary rule.

Candidate `LastSeen`, observation time, and each history timestamp serve different purposes. Do not derive last-seen by
taking a history maximum without an approved rule. Present instants compare in UTC independent of zone; missing time is
explicit, not current time or zero time.

**Legacy fuzzy tie proposal:** Compare UTC instants at C's whole-second precision; require present candidate last-seen
values in the strict compatibility fixture domain. For missing values, the C constructor's zero can be reproduced only
through an explicitly selected `legacy_epoch` mapping. Alternatively require a time or rank missing oldest; these are
proposed modes with different consequences for pre-epoch observations. Do not select a mode implicitly. Nanosecond
ranking differs from C even when both values were recorded in the same second.

The legacy kernel has no expiry/window/observation-age filter. If new eligibility uses age, supply a fixed
`EvaluationTime` in policy; never read the wall clock. Age limits, future-dated evidence, historical value eligibility,
and contradictory histories remain domain decisions. Input-order ties are deterministic for identical arrays, not
permutation-invariant.

After a decision, callers may append observations, retain previous values/timestamps, preserve prior asset-key
relationships, and apply approved merges transactionally. The decision itself changes no asset state and mandates no
unlimited history retention.

### 6.1 APPROVED scanner/network boundary contract; pending qualification, provenance, and merge safety

#### 6.1.1 BoundaryContext and historical evidence — APPROVED responsibilities

Use a qualified logical `BoundaryID` as the network identity namespace and keep `ScannerID` as optional observation provenance. Boundary identity is not scanner identity: several scanners may observe one logical boundary, and one scanner may observe several boundaries. Equal scanner IDs neither establish network compatibility nor qualify identifiers. Boundary compatibility does not change SPEC-001B normalization, identifier scope, or semantic equality.

The initial API supports one logical boundary per incoming observation and per candidate matching view, resolved when supplied. Missing/unresolved context remains representable for the approved UNKNOWN handling below; it does not authorize a view containing several known boundaries. The minimal BoundaryContext sketch uses BoundaryID and optional ScannerID; final Go layout remains proposed. Every nonempty BoundaryID must be caller-resolved and qualified within an authoritative namespace. The exact qualification scheme, authoritative assignment, collision prevention across issuing realms/managers/tenants, and validation of supplied keys remain PENDING DOMAIN DECISION. Do not infer BoundaryID from IP ranges, scanner ID, OSI authorization scope, or identifier Scope.

Callers or shared configuration resolve network aliases and equivalence before invoking reconciliation. Equivalent boundaries must be supplied with the same qualified BoundaryID. The library compares supplied resolved context deterministically; it performs no equivalence graph traversal, database access, scanner discovery, clock access, or external-service lookup. Unequal raw local names alone do not prove incompatibility. Known distinct incompatible logical namespaces are INCOMPATIBLE; qualification must establish that the supplied IDs actually denote those namespaces, rather than unresolved aliases.

**APPROVED historical-evidence contract:** callers partition historical evidence by boundary before reconciliation, including history supplied with either observation or candidate matching view. Do not automatically assign old identifier values to a latest/current BoundaryID, union different boundary partitions, or rewrite identifier scopes. History from another boundary remains caller-owned and is not implicitly matching evidence for this call. Active/history eligibility within one partition remains separately pending. Partitioning must not silently create or deduplicate candidate rows sharing a key; duplicate-key input admission remains unresolved.

Advanced mixed-boundary or per-evidence boundary representations are outside the initial implementation scope unless a concrete requirement demands a separately reviewed extension. Empty BoundaryID represents missing/unresolved context in the minimal sketch; raw unresolved aliases are not resolved IDs. The sketch does not attest producer trust or retain unresolved reference/status diagnostics. Any concrete need for extra metadata and its final representation requires separate approval; do not add an advanced provenance system by default.

#### 6.1.2 Deterministic compatibility and fuzzy boundary modes — APPROVED

Boundary comparison returns `COMPATIBLE`, `INCOMPATIBLE`, or `UNKNOWN`. These are admission inputs, not reconciliation actions or authorization results. Exact reason codes and diagnostic layout remain pending.

- Equal caller-resolved, qualified BoundaryIDs are COMPATIBLE, regardless of whether ScannerIDs differ or are absent.
- Known distinct incompatible logical boundaries are INCOMPATIBLE.
- Missing or unresolved boundary context is UNKNOWN. Both-missing context, equal unresolved aliases, and matching scanner IDs do not establish equality or compatibility.

Compare resolved qualified BoundaryIDs by exact bytes without case folding, trimming, or locale dependence. Comparison is symmetric and independent of candidate order. Callers must resolve ambiguity before supplying a nonempty qualified key; the library must not guess a boundary from ScannerID. The unresolved qualification/validation contract must not be filled by treating raw aliases as authoritative keys.

Support exactly two explicit `FuzzyBoundaryMode` modes, `strict` and `legacy`. **APPROVED default: strict for new Greenbone deployments.** Defaults are obtained explicitly as in section 7; an omitted mode in a policy not constructed from that default is incomplete configuration, not implicit legacy. Unknown mode names are invalid configuration.

| Compatibility | `strict` fuzzy selection | `strict` fuzzy merge evaluation | `legacy` fuzzy selection | `legacy` fuzzy merge evaluation |
| --- | --- | --- | --- | --- |
| COMPATIBLE | Admitted by boundary check | Admitted by boundary check | Admitted by boundary check | Admitted by boundary check |
| INCOMPATIBLE | Excluded | Excluded | Excluded | Excluded |
| UNKNOWN | Excluded | Excluded | Admitted by boundary check | Admitted by boundary check |

Admission permits evaluation only. Every admitted row must still satisfy the original C containment rules, evidence/candidate eligibility, and independently approved merge-safety constraints. Legacy UNKNOWN merge evaluation is now APPROVED; it is no longer an open boundary-admission rule. Neither mode itself authorizes a merge or supplies missing safety facts. If a policy requires unresolved independent merge predicates, it remains incomplete under section 7.

Compatibility remains UNKNOWN when legacy admits a row. Legacy is an explicit migration compatibility option, not a globally safe matching mode or a claim of equivalent identity. It never admits known incompatible boundaries, supplies producer trust, or changes strong eligibility and the approved fuzzy-entry gate. Missing boundary context is not an input error solely because it is absent; strict excludes it, while legacy admits it for fuzzy evaluation. Invalid supplied keys remain a separate pending validation/admission issue, not automatically UNKNOWN or permitted by legacy.

#### 6.1.3 Admission before the unchanged fuzzy containment kernel — APPROVED

Evaluate boundary admission and eligible identifier sets before fuzzy selection and merge sweeps. Strict admits COMPATIBLE rows only; legacy admits COMPATIBLE and UNKNOWN rows. Exclude INCOMPATIBLE rows in both modes from all fuzzy selection and merge evaluation. Identical IP/MAC/hostname values and other configured fuzzy identifiers cannot bypass these exclusions. Different scanners sharing a boundary may match; reused private IPs in incompatible boundaries cannot establish fuzzy identity.

Exclude an ineligible row as a whole, preserving original candidate indices. Do not pass an excluded row's now-empty projection to the kernel, since empty-subset mathematics could otherwise create an unintended merge. Exclusion applies through every sweep. Diagnostic representation remains pending.

After all applicable admissions are determined, preserve the C Cases A/B/C, weighted count scoring, fuzzy freshness contract, input-order ties, and merge ordering. Boundary-admitted empty sets remain subject to the separate unresolved empty-set policy. Boundary filtering may change results compared with unfiltered C inputs; the containment kernel itself is unchanged. Legacy admission of UNKNOWN does not permit partial-overlap matching or establish merge safety.

#### 6.1.4 Strong cross-boundary selection — APPROVED gate; pending producer rules

Strong eligibility is evaluated independently from fuzzy boundary compatibility and strict/legacy mode. Strong identifiers may match across boundaries only when the configured identifier type, namespace, and producer provenance authorize cross-boundary validity. Classification as strong, semantic equality, freshness, or an identical raw identifier is not such authorization. Do not assume every configured strong type is globally unique.

The type-specific trust predicates, authoritative issuer/identity realms, required provenance facts, caller attestation responsibility, and their representation remain PENDING DOMAIN DECISION. Greenbone and Agent cross-boundary examples below are conditional on explicitly supplied valid producer contracts; no trusted-by-name default or universal Greenbone/Agent exemption is approved. Other configured strong types require their own approved admission contracts. Unchanged SPEC-001B equality, including identifier scope, remains necessary.

Separate incoming strong eligibility from pairwise candidate admission. If an incoming configured strong value remains eligible but every candidate is rejected by the type/provenance/boundary admission rule, no valid strong candidate matches: CREATE applies absent unresolved strong conflict, and fuzzy never runs. Candidate rejection must not retroactively make incoming strong evidence ineligible to enable fuzzy. If incoming evidence itself is ineligible and no eligible configured strong values remain, the approved fuzzy-entry gate applies with the selected fuzzy boundary mode.

Eligibility and strong-conflict checks precede approved same-priority ranking. A newer ineligible row cannot win. Neither boundary mode changes absolute configured priority, uses fuzzy evidence to break strong ties, or authorizes a merge target.

#### 6.1.5 Selection versus independent merge safety

**APPROVED:** strong selection reuses the selected key and never automatically authorizes merging other keys, including other same-value matches across boundaries. Cross-boundary strong selection and fuzzy legacy admission supply no independent merge authorization.

**PENDING DOMAIN DECISION:** independently approved merge-safety predicates must govern each target, using incoming context, any existing survivor context, target evidence, and the merge policy. Fuzzy boundary admission itself is fully defined above: strict excludes UNKNOWN and INCOMPATIBLE; legacy excludes INCOMPATIBLE and allows UNKNOWN into merge evaluation. Which additional safety predicates apply, what context a new survivor receives, how UNKNOWN safety facts are handled, whether target/survivor context adds restrictions, strong contradiction vetoes, and history retention remain unresolved. A future strong merge operation requires its own approved contract.

A complete policy must resolve the applicable safety predicates before an actionable merge plan can be returned. Candidate-linked evidence and diagnostics remain pending; merge lists must not be used to store informational nonselected candidates. Boundary admission must not silently resolve any of these independent requirements.

#### 6.1.6 Migration consequences

Existing gvmd candidates without boundary metadata compare UNKNOWN, including when incoming observations have resolved boundaries. Strict excludes them from fuzzy selection and merge evaluation. With no eligible configured strong values and no other admitted candidate, fuzzy runs and returns CREATE with no merges. Strict may therefore create additional keys where older behavior reused or merged an existing asset; it does not backfill stored metadata.

Explicit legacy mode allows these UNKNOWN candidates into both fuzzy selection and merge evaluation, preserving boundary-free legacy admission during migration. Case A may reuse and merge into an existing key; Case B may require a new key and merge contained candidates into it, subject to independent safety approval. Full C compatibility remains limited to the stated canonical values, scopes, admissions, timestamps, and other compatibility fixtures; it is not guaranteed for arbitrary gvmd data. A resolved known incompatible boundary excludes the row in both modes, so legacy cannot bypass an explicit boundary conflict.

Callers own authoritative BoundaryID backfill, shared equivalence resolution, and deployment-mode selection. They must partition historical evidence rather than assigning all history to a newly populated/latest boundary. Switching to strict affects later admission; it does not rewrite history, undo previous merges, or reconcile duplicated keys automatically. Trusted strong matching may still reuse a boundary-less candidate under its separately approved producer contract. Missing fuzzy boundary context does not confer that trust.

### 6.2 Remaining boundary qualification, provenance, and safety decisions

The roles of BoundaryID/ScannerID, caller-owned equivalence resolution, deterministic compatibility outcomes, strict/legacy selection and merge evaluation, strict new-deployment default, and single-boundary caller-partitioned history are APPROVED. These approvals do not define qualified-key syntax/issuance/validation, type-specific producer trust and attestation, independent merge-safety predicates, invalid-key handling, or candidate-linked diagnostic/native layout. Those remain pending and can still prevent a complete production policy. Advanced mixed-boundary provenance is outside initial scope unless a concrete requirement demands it.

## 7. APPROVED configurable matching policy and validation

`MatchPolicy` is one native value model used by the Go API and represented losslessly by a future typed C adapter. C callers must not use a separate classification algorithm or different defaults. It is independent of YAML, persistence, configuration loading, HTTP, and manager implementations. This update approves architecture and validation, not Go implementation or a C ABI.

### 7.1 Supported types versus policy membership — APPROVED

The supported type set is defined by SPEC-001A and its normalization contracts by SPEC-001B. A type's availability does not assign it to a matching stage. Callers may classify supported identifiers as strong, fuzzy, or unassigned. Reclassification does not register a new type, change normalization, imply eligibility, or authorize merges. The matching algorithm must iterate policy membership rather than switch over a fixed list of strong or fuzzy types.

`StrongOrder` is the complete configured strong list. List order is absolute priority. Reordering changes selection precedence; omission disables that type in this stage. An explicitly empty list disables strong matching, so incoming identifiers cannot qualify as strong merely because they occur in the Greenbone default. Defaults are obtained explicitly; an empty list must not silently restore them.

Fuzzy configuration consists of type/weight entries. Callers select participating supported types and configure their weights; omitted types do not participate in fuzzy containment or scoring. A type in neither stage remains supported and normalizable and may remain in history, but contributes no matching evidence under that policy. Preserve the approved containment/intersection algorithm for every configured fuzzy view.

The fallback gate counts eligible incoming identifiers belonging to the **configured strong list**. Removing a type from strong membership therefore removes its ability to block fuzzy entry; it does not automatically add that type to fuzzy membership. Any eligible configured strong identifier still prohibits fuzzy execution even if none of the candidates match it. Disabling strong membership is permitted; disabling the required fuzzy stage-entry rule is not.

### 7.2 Default Greenbone policy — APPROVED

Provide an explicitly obtainable Greenbone default matching policy, with independent caller-owned configuration data. Its classification and weights are:

| Stage | Supported type | Priority or weight |
| --- | --- | --- |
| Strong | `greenbone_id` | 1, highest |
| Strong | `agent_id` | 2 |
| Strong | `machine_id` | 3 |
| Strong | `bios_uuid` | 4 |
| Strong | `ssh_host_key` | 5 |
| Strong | `tls_certificate_public_key_hash` | 6 |
| Strong | `cloud_identifier` | 7 |
| Fuzzy | `mac` | 1.0 |
| Fuzzy | `ip` | 0.4 |
| Fuzzy | `hostname` | 0.4 |
| Unassigned | `fqdn` | Supported type; no default matching contribution |

Default priority numbers above describe list positions, not weights. They and the fuzzy constants belong in default policy construction, not the algorithm. Caller modification of one policy must not modify global defaults or another caller's policy. This classification table resolves default membership and weights only. Section 6.1 additionally approves strict boundary mode for new deployments; unresolved key qualification, producer eligibility, conflict, other freshness, and merge-safety rules are not filled with invented defaults.

### 7.3 Validation and FQDN participation — APPROVED architecture

Reject duplicate strong members, duplicate fuzzy entries, unknown types, and any type classified in both stages. Validate before matching, regardless of observation/candidate contents. Do not deduplicate invalid configuration silently or resolve overlap by stage precedence. A map-backed public representation must not silently overwrite duplicate entries during policy construction or future adapter conversion.

Reject negative, NaN, or infinite fuzzy weights. An enabled fuzzy configuration with all weights zero is invalid under the current proposed scoring contract. Exact zero-weight participation semantics and numeric/overflow limits remain explicitly pending; do not treat zero as an undocumented disable operation. Omission is the explicit membership operation.

FQDN remains supported and may be explicitly configured, but an approved DNS projection must define its contribution without double-counting equivalent hostname evidence. The default has only hostname, so FQDN is not an implicit alias or extra .4 contribution. A configuration enabling FQDN without a resolved projection is incomplete and must be rejected rather than guessed. If a projection implicitly consumes an additional supported type, that effective membership must participate in overlap validation too. Conflicting hostname/FQDN weight definitions within a shared DNS bucket need an explicit resolution; do not invent max/sum/preferred-type weighting.

Normalization receives no matching policy and remains unchanged when membership, priority, or weights change. The same value normalizes identically whether its type is strong, fuzzy, disabled, or unassigned. The policy does not introduce runtime registration or new identifier representations.

### 7.4 Remaining policy contracts

Final Go field/enum spelling and data layout remain proposed; other behavioral decisions are identified below:

| Policy field / concern        | Contract or proposed modes                                                                                                                                                         | Approval status                                                       |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `StrongOrder` | Ordered stable types; default seven in section 4; absolute precedence | APPROVED configurable absolute priority and default order |
| Strong omissions/disabling | Configured list determines membership; callers reorder/omit supported types; explicitly empty list disables strong stage and does not restore defaults | APPROVED architecture |
| Fuzzy membership and weights | Caller-configured supported type/weight entries; Greenbone defaults MAC=1, IP=.4, hostname=.4; not hardcoded in algorithm | APPROVED architecture and defaults; exact-zero/numeric details pending |
| Fuzzy types | Caller-configured supported membership, disjoint from strong list; FQDN requires explicitly resolved projection | Selection APPROVED; FQDN projection pending |
| `FuzzyDNSProjection` | Default leaves FQDN unassigned; explicitly configured FQDN needs a DNS projection and shared-weight contract without double counting | Default membership APPROVED; configured participation pending |
| `Eligibility`                 | Explicit evidence, candidate, and merge admission rules; no implicit reliability filter                                                                                            | Pending business rules/input facts                                    |
| Strong/fuzzy/merge boundaries | Qualified logical BoundaryID, caller-resolved equivalence, deterministic compatibility, separate strong provenance and merge-safety gates | Boundary roles/admission APPROVED; key qualification, producer predicates, independent merge safety pending |
| `FuzzyBoundaryMode` | `strict`: COMPATIBLE selection/merge evaluation only; `legacy`: COMPATIBLE/UNKNOWN selection/merge evaluation; INCOMPATIBLE excluded in both; strict default for new deployments | APPROVED modes, default, and boundary admission; independent merge safety pending |
| `StrongConflict` | Separate pending contradiction/reporting contract; cannot silently override approved cross-priority selection or permit fuzzy fallback | Pending contradiction definition and permitted resolutions |
| `StrongAmbiguity` | APPROVED same-value newest LastSeen, missing last, exact-byte lexical key ties, after eligibility/conflict checks | Ranking APPROVED; conflicting values and duplicate-key rows pending |
| Strong selection versus merge authorization | APPROVED: selection alone produces no automatic merges; any separate merge operation needs its own eligibility contract | Separation APPROVED; merge eligibility pending |
| Fuzzy fallback gate           | Only no eligible incoming strong identifiers enters fuzzy; eligible strong no-match returns CREATE absent unresolved conflict; ambiguity/contradiction uses strong-conflict policy | APPROVED; not a configurable relaxation                               |
| `Freshness` | APPROVED strong same-priority nanosecond UTC ranking, missing last, exact key ties; fuzzy precision/handling unchanged; expiry separate | Strong ranking APPROVED; other freshness/eligibility rules remain open |
| Fuzzy tie-break               | `input_order` for legacy; a proposed alternative key order must be explicitly selected and tested                                                                                  | Legacy behavior established; alternative pending                      |
| Empty fuzzy candidate sets    | Literal subset admission versus explicit exclusion, distinguishing projected-empty                                                                                                 | Legacy behavior established; production choice pending                |
| Candidate key handling        | Legacy `skip_unkeyed` versus proposed input rejection; legacy row duplicate handling versus proposed duplicate-key rejection                                                       | Pending native contract                                               |
| Invalid/unsupported evidence  | Proposal: return error before matching; alternative explicitly quarantines with diagnostics, never silently drops                                                                  | Pending input admission contract                                      |

Policy validation must reject configurations permitting fuzzy fallback with eligible incoming strong evidence, including no-match, ambiguity, or contradiction. It must also reject suppressing the required fuzzy stage when no eligible incoming strong identifiers exist.

Classification and fuzzy-weight validation above are APPROVED architectural requirements. Also reject unknown mode values, inconsistent modes, and missing required domain decisions for a requested policy. Supported type reassignment alone is not an unsupported stage assignment; it is explicitly allowed. An unresolved type-specific projection remains an incomplete contract. No weighted strong priority is permitted.

Exact-zero weight semantics remain pending: the earlier proposal retains the dimension in containment while giving it no score, but this must not become an implicit default before approval. Omission removes fuzzy membership and its projection. Custom-type accumulation order, numeric precision, and overflow handling must also be resolved explicitly.
Disabling fuzzy fallback is inconsistent with the approved rule. An empty effective fuzzy observation produces CREATE with no merges through the existing C guard after entering the fuzzy stage.

Omitted/disabled strong types are not unknown or unsupported. Classifying a default fuzzy type as strong, or a default strong type as fuzzy, is APPROVED when stage membership is nonoverlapping and the type's syntax/equality contract is supported. No automatic reassignment, normalization change, eligibility grant, or runtime registration follows.

A valid complete policy must make every applicable branch deterministic. A policy relying on unresolved semantics must
fail policy validation, not run a best-effort reconciliation. A legitimate identity conflict under a complete approved
policy returns CONFLICT with nil error; malformed input or incomplete/invalid policy returns an error and no actionable
decision.

## 8. Decision table and acceptance fixtures

Notation: `G(g)`, `A(a)`, `M(m)`, `P(p)`, `H(h)`, and `Q(h)` are Greenbone/agent/MAC/IP/hostname/FQDN canonical values
with the indicated scope. `p1/p2/p3` stand for valid distinct IPs, `m1` for a valid MAC, and `h1` for a valid hostname.
`K1:{...}@20` is an original keyed candidate with whole-second last-seen 20. Array order is the listed order; indices
remain original indices.

`MI(x)` denotes a syntactically valid Machine ID with its required explicit `kind`; `B(u)` denotes a valid canonical BIOS UUID. Their scopes are equal between corresponding observation/candidate values.

In the conditional boundary rows, `b1`, `b2`, and `b3` denote caller-resolved, qualified logical BoundaryIDs under the approved caller-resolution contract, assuming qualified keys. Boundaries described as incompatible are known distinct identity namespaces; unresolved aliases are not resolved IDs. Identical strong values use semantically equal identifier scopes, independently of boundary context. `P(192.168.1.10)` is a canonical private IP reused across logical boundaries.

Fixture policies:

- **L:** no active strong evidence; default fuzzy weights; already valid/canonical values; identical identifier scope
  states; all relevant candidate/merge admissions expressly permitted; present whole-second times; input-order ties;
  literal empty-subset and key-row behavior. L characterizes the C kernel, not an approved production eligibility
  preset.
- **S:** default strong order; indicated strong evidence is expressly eligible and boundary-allowed. Selection uses the highest matching priority and returns REUSE for one matching candidate, without automatic merges. Cross-key conflict reporting/merge eligibility and same-priority ambiguity remain pending unless explicitly specified.
- **N:** at least one incoming strong value is expressly eligible; no valid candidate matches it and no unresolved strong conflict exists. The APPROVED gate returns CREATE without fuzzy execution.
- **I:** all incoming strong values are expressly ineligible, then L. The APPROVED gate enters fuzzy; the fixture's eligibility exclusions are not newly approved production defaults.
- **D:** proposed DNS coalescing projection explicitly selected for a conditional fixture; it does not approve the production projection default.
- **B (APPROVED BOUNDARY ADMISSION):** section 6.1 applies, with strict unless a row explicitly states legacy; boundaries are expressly qualified/resolved as indicated. No eligible configured incoming strong values exist unless stated. Conditional rows still assume the separately stated evidence eligibility, producer provenance, and independent merge-safety predicates; B alone grants none of those.
- **R (APPROVED ranking):** the same incoming strong value matches multiple eligible distinct-key candidates at the highest applicable priority after strong-conflict checks. Apply section 4.2.1, reuse the selected key, and return no merge targets. This fixture does not resolve incompatible multiple incoming values, duplicate asset-key rows, or candidate-linked evidence layout.

A row with an assumed eligibility/projection approval is conditional on that separate contract, not a silent domain default. R rows use the APPROVED ranking rule after the stated eligibility/conflict checks. PENDING rows have no fully authorized decision until their separate domain rules are resolved.

| # / scenario                                          | Observation                                    | Candidates                                              | Relevant policy                                                     | Action                  | Selected key | Merge keys                 | Reason                                                                                                 |
| ----------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------- | ----------------------- | ------------ | -------------------------- | ------------------------------------------------------------------------------------------------------ |
| 1 Empty observation                                   | `{}`                                           | `K1:{P(p1)}@10`                                         | L                                                                   | CREATE                  | None         | `[]`                       | C nonempty-observation guard                                                                           |
| 2 No candidates                                       | `{G(g),P(p1)}`                                 | `[]`                                                    | Any otherwise valid policy; no observation-internal contradiction   | CREATE                  | None         | `[]`                       | No existing key available                                                                              |
| 3 Exact Greenbone match                               | `{G(g)}`                                       | `K1:{G(g)}@10`                                          | S                                                                   | REUSE                   | K1           | `[]`                       | Unique eligible strong match                                                                           |
| 4 Exact Agent match                                   | `{A(a)}`                                       | `K1:{A(a)}@10`                                          | S                                                                   | REUSE                   | K1           | `[]`                       | No higher-priority competing match                                                                     |
| 5 Strong match, changed IP                            | `{G(g),P(p2)}`                                 | `K1:{G(g),P(p1)}@10`                                    | S                                                                   | REUSE                   | K1           | `[]`                       | Weak difference does not require fuzzy containment                                                     |
| 6 Strong match, extra candidate values                | `{G(g)}`                                       | `K1:{G(g),P(p1),H(h1)}@10`                              | S                                                                   | REUSE                   | K1           | `[]`                       | No strong set-containment requirement                                                                  |
| 7 Different priority, different keys | `{G(g),A(a)}` | `K1:{G(g)}@10`, `K2:{A(a)}@20` | S | REUSE | K1 | `[]` | APPROVED Greenbone precedence despite newer Agent candidate; cross-key conflict reporting/merge eligibility pending |
| 8 Same highest-priority value, two keys | `{G(g)}` | `K1:{G(g)}@10`, `K2:{G(g)}@20` | R (APPROVED); eligibility and strong-conflict checks passed | REUSE | K2 | `[]` | APPROVED newer same-value LastSeen wins at winning priority; no automatic merge or fuzzy fallback |
| 9 Priority selection with disagreeing Agent evidence | `{G(g),A(a1)}` | `K1:{G(g),A(a2)}@20`, `K2:{A(a1)}@10` | S; G(g) expressly eligible | REUSE | K1 | `[]` | APPROVED Greenbone selection; interpretation/reporting of Agent disagreement and merge eligibility pending |
| 10 Strong no-match, matching MAC                      | `{G(g),M(m1)}`                                 | `K1:{M(m1)}@10`                                         | N                                                                   | CREATE                  | None         | `[]`                       | APPROVED: eligible Greenbone ID blocks fuzzy; MAC cannot select K1                                     |
| 11 Strong no-match, matching IP                       | `{A(a),P(p1)}`                                 | `K1:{P(p1)}@10`                                         | N                                                                   | CREATE                  | None         | `[]`                       | APPROVED: eligible Agent ID blocks fuzzy; IP cannot select K1                                          |
| 12 Strong no-match, matching hostname                 | `{A(a),H(h1)}`                                 | `K1:{H(h1)}@10`                                         | N                                                                   | CREATE                  | None         | `[]`                       | APPROVED: eligible Agent ID blocks fuzzy; hostname cannot select K1                                    |
| 13 Candidate contains observation                     | `{P(p1),P(p2)}`                                | `K1:{P(p1),P(p2),P(p3)}@10`                             | L                                                                   | REUSE                   | K1           | `[]`                       | Fuzzy Case A                                                                                           |
| 14 Observation contains candidate                     | `{P(p1),P(p2)}`                                | `K1:{P(p1)}@10`                                         | L                                                                   | MERGE; new key required | None         | `[K1]`                     | Fuzzy Case B, even for one row                                                                         |
| 15 Partial overlap                                    | `{P(p1),P(p3)}`                                | `K1:{P(p1),P(p2)}@10`                                   | L                                                                   | CREATE                  | None         | `[]`                       | Neither set contains the other                                                                         |
| 16 Multiple contained candidates                      | `{P(p1),P(p2),H(h1)}`                          | `K1:{P(p1)}@10`, `K2:{H(h1)}@20`, `K3:{P(p1),P(p3)}@30` | L                                                                   | MERGE; new key required | None         | `[K1,K2]`                  | K3 not a subset; input-order targets                                                                   |
| 17 Equal fuzzy scores                                 | `{P(p1)}`                                      | `K1:{P(p1)}@10`, `K2:{P(p1),H(h1)}@20`                  | L                                                                   | MERGE; existing key     | K2           | `[K1]`                     | Both score .4; greater last-seen selects superset                                                      |
| 18 Equal score/time                                   | `{P(p1)}`                                      | `K1:{P(p1)}@20`, `K2:{P(p1)}@20`                        | L                                                                   | MERGE; existing key     | K1           | `[K2]`                     | First input row survives                                                                               |
| 19 Same IP, different scanner | `{P(p1)}`, scanner s1 | `K1:{P(p1)}@20`, scanner s2 | Boundary context/mode and identifier eligibility unspecified | PENDING DOMAIN DECISION | — | — | Equality does not approve cross-boundary matching; boundary examples are rows 47–69 |
| 20 Same strong ID, different scanner | `{G(g)}`, scanner s1 | `K1:{G(g)}@20`, scanner s2 | Strong boundary/producer realm rules pending | PENDING DOMAIN DECISION | — | — | No automatic universal cross-scanner rule; boundary examples are rows 47–69 |
| 21 Duplicate values                                   | `{M(m1),M(m1)}`                                | `K1:{M(m1)}@10`                                         | L                                                                   | REUSE                   | K1           | `[]`                       | One distinct fuzzy token/count                                                                         |
| 22 Historical differing times                         | Current `{P(p2)}`, history `P(p1)@10,P(p2)@20` | `K1:{P(p1)}@10` with history                            | Active/history evidence policy not approved                         | PENDING DOMAIN DECISION | —            | —                          | No automatic history union, replacement, or expiry                                                     |
| 23 Missing candidate freshness                        | `{P(p1)}`                                      | `K1:{P(p1)}@missing`, `K2:{P(p1)}@0`                    | Missing-time handling not selected                                  | PENDING DOMAIN DECISION | —            | —                          | Nil differs from epoch; do not invent ordering                                                         |
| 24 No eligible incoming identifiers                   | `{P(0.0.0.0)}`                                 | `K1:{P(0.0.0.0)}@10`                                    | Fixture exclusion leaves no eligible strong or fuzzy values         | CREATE                  | None         | `[]`                       | APPROVED fuzzy entry, then C empty-observation guard; exclusion itself remains conditional             |
| 25 Duplicate candidate asset keys                     | `{P(p1)}`                                      | `K:{P(p1)}@10`, `K:{P(p2)}@20`                          | Duplicate-row handling not selected                                 | PENDING DOMAIN DECISION | —            | —                          | No silently unioned snapshot; C behavior documented separately                                         |
| 26 Candidate-order permutation                        | `{P(p1)}`                                      | Row order `[K2:{P(p1)}@20,K1:{P(p1)}@20]`               | L                                                                   | MERGE; existing key     | K2           | `[K1]`                     | Reversing row order reverses tie survivor; identical inputs remain deterministic                       |
| 27 Empty candidate identifiers                        | `{P(p1)}`                                      | `K1:{}@10`                                              | L                                                                   | MERGE; new key required | None         | `[K1]`                     | Literal C empty-subset behavior                                                                        |
| 28 Merge without observation intersection             | `{P(p1)}`                                      | `K1:{P(p1),H(h1)}@20`, `K2:{H(h1)}@10`                  | L                                                                   | MERGE; existing key     | K1           | `[K2]`                     | K2 is subset of survivor, not of observation                                                           |
| 29 Duplicate merge keys, Case B                       | `{P(p1),P(p2),H(h1)}`                          | `K:{P(p1)}@10`, `K:{P(p2)}@20`                          | L legacy row mode                                                   | MERGE; new key required | None         | `[K,K]` at indices `[0,1]` | C emits rows, not deduplicated keys; native production choice pending                                  |
| 30 FQDN and hostname duplicate                        | `{H(h1),Q(h1)}`                                | `K1:{H(h1)}@10`                                         | L plus D, equal canonical spelling/scope                            | REUSE                   | K1           | `[]`                       | Conditional one DNS bucket; one .4 contribution; projection approval pending                           |
| 31 Equal strong value/time, ambiguity reporting | `{G(g)}` | `K1:{G(g)}@20`, `K2:{G(g)}@20` | R (APPROVED); eligibility and strong-conflict checks passed | REUSE | K1 | `[]` | APPROVED equal timestamp tie selects lexicographically smallest exact key; no automatic merge |
| 32 Strong evidence with no fuzzy evidence             | `{G(g)}`                                       | `K1:{G(other)}@20`                                      | N; differing value not classified as unresolved conflict in fixture | CREATE                  | None         | `[]`                       | APPROVED no-match outcome; no fuzzy execution; general contradiction definition remains pending        |
| 33 Only ineligible strong values, matching MAC        | `{G(g),M(m1)}`                                 | `K1:{M(m1)}@10`                                         | I; G(g) expressly ineligible                                        | REUSE                   | K1           | `[]`                       | APPROVED: ineligible strong value does not block fuzzy Case A                                          |
| 34 Ineligible and eligible strong values, matching IP | `{G(g),A(a),P(p1)}`                            | `K1:{P(p1)}@10`                                         | N; G(g) ineligible, A(a) eligible, no strong match/conflict         | CREATE                  | None         | `[]`                       | APPROVED: one eligible strong value blocks fuzzy                                                       |
| 35 Strong ambiguity with matching weak values | `{G(g),P(p1)}` | `K1:{G(g),P(p1)}@20`, `K2:{G(g),P(p2)}@20` | R (APPROVED); eligibility and strong-conflict checks passed | REUSE | K1 | `[]` | APPROVED exact-key tie-break; weak IP is not considered; conflict checks precede ranking |
| 36 Greenbone no-match, Agent match | `{G(g),A(a)}` | `K1:{G(other),A(a)}@10` | S; no unresolved strong conflict | REUSE | K1 | `[]` | APPROVED: no Greenbone match, continue to Agent priority; no fuzzy execution |
| 37 Machine and BIOS match different assets | `{MI(x),B(u)}` | `KA:{MI(x)}@10`, `KB:{B(u)}@20` | S; both matches eligible | REUSE | KA | `[]` | APPROVED Machine ID precedence; cross-key conflict/merge handling pending; newer BIOS candidate cannot override |
| 38 No eligible strong identifiers | `{P(p1),H(h1)}` | `K1:{P(p1),H(h1)}@10` | L | REUSE | K1 | `[]` | APPROVED: execute unchanged C fuzzy Case A |
| 39 Example A, different times | `{G(GB-123)}` | `asset-100:{G(GB-123)}@100`, `asset-200:{G(GB-123)}@200` | R (APPROVED); eligibility and strong-conflict checks passed | REUSE | asset-200 | `[]` | APPROVED newest LastSeen at same winning priority; reuse asset-200; no merge |
| 40 Example B, equal times | `{G(GB-123)}` | `asset-100:{G(GB-123)}@200`, `asset-200:{G(GB-123)}@200` | R (APPROVED); eligibility and strong-conflict checks passed | REUSE | asset-100 | `[]` | APPROVED exact-byte lexical tie-break selects asset-100; array order does not decide |
| 41 Example C, different priorities | `{G(GB-123),A(Agent-456)}` | `asset-100:{G(GB-123)}@100`, `asset-200:{A(Agent-456)}@300` | S, default order | REUSE | asset-100 | `[]` | APPROVED Greenbone precedence; newer Agent candidate cannot override |
| 42 One missing LastSeen | `{G(g)}` | `K1:{G(g)}@missing`, `K2:{G(g)}@-1` | R (APPROVED); eligibility and strong-conflict checks passed | REUSE | K2 | `[]` | APPROVED valid present pre-epoch timestamp outranks missing; nil is not epoch |
| 43 All LastSeen missing | `{G(g)}` | `K2:{G(g)}@missing`, `K1:{G(g)}@missing` | R (APPROVED); eligibility and strong-conflict checks passed | REUSE | K1 | `[]` | APPROVED all-missing tie uses exact lexical key ordering |
| 44 Same second, distinct nanoseconds | `{G(g)}` | `K1:{G(g)}@200s+1ns`, `K2:{G(g)}@200s+2ns` | R (APPROVED); eligibility and strong-conflict checks passed | REUSE | K2 | `[]` | APPROVED nanosecond UTC comparison for strong ranking; fuzzy precision unchanged |
| 45 Example D, different incoming strong values | `{G(g1),G(g2)}` | `K1:{G(g1)}@100`, `K2:{G(g2)}@200` | Same-type compatibility/conflict rules unresolved | PENDING DOMAIN DECISION | — | — | Do not rank union unless explicitly approved as noncontradictory |
| 46 Duplicate key/time rows | `{G(g)}` | row 0 `K:{G(g)}@200`, row 1 `K:{G(g)}@200` | Duplicate-key row handling unresolved | PENDING DOMAIN DECISION | Key K may be determined; row/index pending | No automatic merge authorized | Lexical ranking alone cannot determine selected index/evidence row |
| 47 A: Reused private IP, incompatible boundaries | `{P(192.168.1.10)}`, BoundaryID b1 | `K1:{P(192.168.1.10)}@20`, incompatible BoundaryID b2 | B, incompatible candidate excluded | CONDITIONAL CREATE; other fixture admissions assumed | None | `[]` | Reused private IP cannot select or merge an asset in another incompatible namespace |
| 48 B: Same IP, compatible boundaries | `{P(p1)}`, BoundaryID b1 | `K1:{P(p1)}@20`, same BoundaryID b1 | B plus L | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | Normal C fuzzy Case A after explicit compatible admission |
| 49 C: Trusted Greenbone ID across boundaries | `{G(g)}`, b1, trusted issuing realm | `K1:{G(g)}@20`, b2, compatible trusted provenance/scope | B plus S, explicit Greenbone cross-boundary rule | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | Type, namespace, and provenance admit strong correspondence; no automatic merge |
| 50 D: Agent ID across boundaries | `{A(a)}`, b1, agent realm/provenance | `K1:{A(a)}@20`, b2, compatible agent scope/provenance | B plus S, explicit Agent cross-boundary rule | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | Agent producer contract required; raw identical ID alone insufficient |
| 51 E: Two scanners sharing a logical boundary | `{P(p1)}`, scanner s1, BoundaryID b1 | `K1:{P(p1)}@20`, scanner s2, BoundaryID b1 | B plus L | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | Different observers share one explicitly compatible network identity namespace |
| 52 F: Missing boundary under strict | `{P(p1)}`, missing BoundaryID | `K1:{P(p1)}@20`, resolved b1 | B, strict | CONDITIONAL CREATE; other fixture admissions assumed | None | `[]` | UNKNOWN excluded from fuzzy selection and merges |
| 53 F: Both boundaries missing, mode unset | `{P(p1)}`, missing BoundaryID, scanner s1 | `K1:{P(p1)}@20`, missing BoundaryID, scanner s1 | No explicit mode or constructed default | CONDITIONAL POLICY ERROR; other fixture admissions assumed | None | `[]` | Compatibility is UNKNOWN; incomplete mode configuration gives no actionable decision |
| 54 Same scanner, incompatible boundaries | `{M(m1),H(h1)}`, scanner s1, b1 | `K1:{M(m1),H(h1)}@20`, scanner s1, incompatible b2 | B | CONDITIONAL CREATE; other fixture admissions assumed | None | `[]` | Scanner equality and matching weak values cannot bypass boundary admission |
| 55 Eligible strong value, rejected candidate boundary | `{G(g),P(p1)}`, b1 | `K1:{G(g),P(p1)}@20`, b2, no permitted cross-boundary admission | B plus N; incoming G(g) remains eligible, no strong conflict | CONDITIONAL CREATE; other fixture admissions assumed | None | `[]` | Candidate exclusion does not enable fuzzy despite IP match |
| 56 Cross-boundary strong selection, another matched asset | `{G(g)}`, b1 | `K1:{G(g)}@20`, b2; `K2:{G(g)}@10`, b3 | B plus R; selection provenance allowed; merge admission unresolved | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | Approved ranking after conditional admission; selection does not authorize merging K2 |
| 57 Caller resolves different network aliases | `{P(p1)}`, local alias alpha resolved to b1 | `K1:{P(p1)}@20`, local alias beta resolved to b1 | B plus L; shared configuration resolves equivalence before Decide | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | Library compares supplied b1 only; it performs no equivalence lookup |
| 58 Identical unresolved boundary aliases | `{P(p1)}`, unresolved alias alpha, empty BoundaryID | `K1:{P(p1)}@20`, unresolved alias alpha, empty BoundaryID | B, strict | CONDITIONAL CREATE; other fixture admissions assumed | None | `[]` | Equal unresolved labels remain UNKNOWN; strict excludes them |
| 59 Optional scanner provenance absent | `{P(p1)}`, resolved b1, no ScannerID | `K1:{P(p1)}@20`, resolved b1, no ScannerID | B plus L; no separate producer requirement for ScannerID | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | Complete logical boundary compatibility does not require scanner equality or presence |
| 60 Missing boundaries under legacy | `{P(p1)}`, missing BoundaryID | `K1:{P(p1)}@20`, missing BoundaryID | B plus L, legacy; no other merge targets | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | UNKNOWN selection admitted; normal C Case A reuses key without establishing boundary equivalence |
| 61 Existing gvmd candidate without boundary, strict | `{P(p1)}`, resolved b1 | `K1:{P(p1)}@20`, historical gvmd row with no BoundaryID | B, strict | CONDITIONAL CREATE; other fixture admissions assumed | None | `[]` | UNKNOWN legacy row is excluded; possible new asset key during migration |
| 62 Existing gvmd candidate without boundary, legacy | `{P(p1)}`, resolved b1 | `K1:{P(p1)}@20`, historical gvmd row with no BoundaryID | B plus L, legacy; no other merge targets | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | UNKNOWN admitted for selection while caller backfills boundary data |
| 63 Candidate resolved to conflicting boundary | `{P(p1)}`, resolved b1 | `K1:{P(p1)}@20`, resolved known incompatible b2 | B, strict or legacy | CONDITIONAL CREATE; other fixture admissions assumed | None | `[]` | Explicit incompatibility prohibits selection and fuzzy merges in either mode |
| 64 Agent ID lacks cross-boundary provenance | `{A(a),P(p1)}`, b1; incoming A(a) expressly eligible | `K1:{A(a),P(p1)}@20`, b2, insufficient Agent cross-boundary provenance | B plus N; explicit proposed type rule rejects pair, no unresolved conflict | CONDITIONAL CREATE; other fixture admissions assumed | None | `[]` | Pairwise strong match denied; incoming eligible Agent ID still prohibits fuzzy in either mode |
| 65 Strict excludes an UNKNOWN subset merge target | `{P(p1)}`, b1 | `K1:{P(p1),H(h1)}@20`, b1; `K2:{H(h1)}@10`, missing boundary | B plus L, strict | CONDITIONAL REUSE; other fixture admissions assumed | K1 | `[]` | K2 excluded before merge sweep despite being a subset of K1 |
| 66 Legacy UNKNOWN contained candidate | `{P(p1),P(p2)}`, b1 | `K1:{P(p1)}@20`, missing boundary | B plus L, legacy; independent merge safety expressly permitted | CONDITIONAL MERGE; new key required | None | `[K1]` | APPROVED UNKNOWN boundary admission; C Case B requires a new key and merges the contained candidate |
| 67 Legacy UNKNOWN merge safety unresolved | `{P(p1),P(p2)}`, missing boundary | `K1:{P(p1)}@20`, missing boundary | B, legacy; independent merge-safety predicate unresolved | PENDING DOMAIN DECISION | — | — | Boundary admits UNKNOWN for merge evaluation, but cannot supply the unresolved independent safety authorization |
| 68 Legacy UNKNOWN subset of existing survivor | `{P(p1)}`, b1 | `K1:{P(p1),H(h1)}@20`, b1; `K2:{H(h1)}@10`, missing boundary | B plus L, legacy; independent merge safety expressly permitted | CONDITIONAL MERGE; existing survivor | K1 | `[K2]` | APPROVED UNKNOWN merge evaluation; unchanged C Case A merges K2 as subset of K1 |
| 69 Historical evidence partitioned by caller | Current `{P(p2)}`, b1; historical P(p1) from b2 omitted from this call by partitioning | `K1:{P(p1)}@10`, b1 | B plus L; current view excludes other-boundary history | CONDITIONAL CREATE | None | `[]` | APPROVED partitioning prevents implicit assignment of historical P(p1) to latest b1; no fuzzy containment |

For policy-free legacy characterization, also test agent/container/unknown C enum values affecting containment without
score, null/empty strings ignored by the C builder, pre-epoch/zero timestamp ranking, and multiple equivalent keyed
rows. Those inputs do not all have valid direct SPEC-001B representations; adapters must explicitly account for that
difference.

Reason-code vocabulary is proposed: `NO_CANDIDATES`, `NO_ELIGIBLE_EVIDENCE`, `STRONG_UNIQUE_MATCH`, `STRONG_NO_MATCH`,
`STRONG_CONFLICT`, `STRONG_AMBIGUITY`, `FUZZY_CONTAINING`, `FUZZY_CONTAINED`, and `FUZZY_NO_CONTAINMENT`. Diagnostics should retain `NO_ELIGIBLE_STRONG_EVIDENCE` and exclusions when the final action came from fuzzy matching; `STRONG_NO_MATCH` never leads to fuzzy execution. Final reason
enumeration and conflict detail layout require approval.

## 9. Acceptance criteria and compatibility validation

- [ ] One native Go decision function serves Go and the future C adapter; no
      database/config-file/GLib/cgo/authorization/key-generation dependency is added.
- [ ] Existing identifier APIs and semantic equality behavior remain unchanged; all matching views and result evidence
      reuse SPEC-001A/B types.
- [ ] APPROVED: `MatchPolicy` configures an absolute strong priority order with the seven-type Greenbone default; comparison uses SPEC-001B semantic equality.
- [ ] Supported identifier types and normalization remain independent of matching classification; changing policy leaves normalized output and SPEC-001A/B behavior unchanged.
- [ ] The Greenbone default contains exactly the approved seven strong types in order and MAC/IP/hostname fuzzy weights 1.0/.4/.4, with FQDN supported but unassigned.
- [ ] Callers can select/reorder/omit supported strong types and configure fuzzy membership/weights; algorithms contain no hardcoded strong member list or fuzzy constants.
- [ ] Reordered Agent-before-Greenbone priority selects the unique Agent candidate when both match different keys; omitting Greenbone prevents it from blocking fuzzy entry or selecting a key under that policy.
- [ ] Reclassifying a supported type between stages is permitted only after removal from the other stage; no automatic reassignment or changed normalization occurs.
- [ ] Duplicate strong members, duplicate fuzzy entries, unknown types, overlap, and invalid fuzzy weights fail policy validation before matching; no silent overwrite or deduplication occurs.
- [ ] Configurable fuzzy views retain containment Cases A/B/C; changed weights never permit partial-overlap selection or introduce a minimum threshold.
- [ ] One policy model and default definitions serve native Go and the future C adapter; independent policy instances cannot mutate each other's defaults.
- [ ] Explicit FQDN participation requires approved projection/weight handling without duplicate hostname evidence; incomplete configurations are rejected.
- [ ] No YAML parsing, persistence, or configuration loading is implemented by this specification.
- [ ] Selection continues past an unmatched higher-priority type and stops at the highest priority with an eligible match; Greenbone no-match plus one Agent match reuses the Agent candidate key.
- [ ] A unique candidate at the highest matching priority reuses its existing key despite additional identifiers on either side or different MAC/IP/hostname values; no containment is required.
- [ ] Machine ID matching A and BIOS UUID matching B selects A by default priority; B cannot override selection or become an automatic merge target. Cross-key conflict reporting and separate merge eligibility remain pending.
- [ ] APPROVED: same-priority ranking runs only after candidate eligibility and strong-conflict checks at the highest matching priority; identify all eligible same-value matches before selection.
- [ ] APPROVED ranking places present LastSeen before missing, compares UTC instants newest first at nanosecond precision, then exact asset-key bytes lexicographically ascending; all-missing uses the same key ordering.
- [ ] Ranking fixtures cover different/equal timestamps, equivalent offsets, subsecond differences, present-zero/pre-epoch versus nil, all-missing, and candidate-order permutations with distinct keys.
- [ ] A newer lower-priority candidate, weak identifier difference, or fuzzy score cannot affect same-priority strong ranking; no lower-priority escape or fuzzy fallback occurs.
- [ ] APPROVED strong ranking produces REUSE with NeedsNewKey=false, the selected existing key/index, and empty merge lists; it does not authorize merging other matching candidates.
- [ ] Candidate-linked matching evidence and diagnostics remain PENDING DOMAIN DECISION; ranking approval does not approve the proposed output extension or use merge lists as evidence storage.
- [ ] Multiple incoming values matching different keys require an approved compatibility/conflict rule before ranking their union; conflicting values remain pending and are not silently declared harmless.
- [ ] All duplicate candidate rows sharing an asset key remain pending, including differing timestamps; equal key/time rows expose unresolved selected-index/evidence handling. No representative-row or final input-order rule is invented.
- [ ] APPROVED: no eligible incoming strong identifiers executes the existing C fuzzy stage; any eligible incoming strong identifier prohibits fuzzy execution.
- [ ] Eligible strong no-match without unresolved strong conflict returns CREATE with no selected/merge keys, even when candidate MAC, IP, or hostname values match.
- [ ] Ineligible strong values do not block fuzzy if none remain eligible; mixed eligible/ineligible values still block fuzzy whenever one is eligible.
- [ ] Same-value ambiguity uses approved strong ranking after conflict checks; unresolved strong contradictions never trigger fuzzy fallback. Cross-priority precedence, conflict reporting, and merge eligibility remain separate.
- [ ] Stage-entry tests verify which stage actually executes, including no eligible matching candidates; candidate correspondence and weak scores do not determine incoming strong eligibility.
- [ ] Policy validation rejects relaxation or suppression of the approved gate; existing C fuzzy behavior is preserved when the stage is entered.
- [ ] Strong key selection returns no automatic merge targets; asset merging is a separate operation requiring independently approved eligibility, including for lower-priority matching keys.
- [ ] The fuzzy subset/intersection kernel reproduces source Cases A/B/C, early returns, multiple values, exact
      weight/count behavior, empty-set and input-order edge cases on compatibility fixtures.
- [ ] DNS projection never counts the same qualified DNS identity twice; no unapproved cross-type normalization or
      short-name expansion exists.
- [ ] Boundary, namespace, authorization, and producer admission remain distinct, including separate strong/fuzzy/merge
      cases across scanner boundaries.
- [ ] Boundary admission fixtures use the APPROVED contract; conditional outputs still require qualified keys and explicitly assumed evidence eligibility, producer provenance, and independent merge safety.
- [ ] Conditional boundary comparison distinguishes COMPATIBLE/INCOMPATIBLE/UNKNOWN, is symmetric/deterministic, and compares caller-resolved qualified BoundaryIDs by exact bytes under an approved assignment contract.
- [ ] Conditional fuzzy tests exclude incompatible IP/MAC/hostname matches from selection and merging in both modes, including empty-subset merge traps; fully admitted inputs run the unchanged C kernel.
- [ ] Two scanners sharing one logical BoundaryID pass fuzzy admission; identical scanners in known incompatible boundaries do not. Reused private IPs cannot select or merge across incompatible boundaries.
- [ ] APPROVED strict excludes UNKNOWN selection/merge evaluation; legacy admits UNKNOWN selection/merge evaluation while retaining UNKNOWN compatibility. Fixtures cover both-missing inputs, identical unresolved aliases, old gvmd rows, and known conflicts that neither mode admits.
- [ ] Strict is the APPROVED Greenbone default for new deployments; policies obtained without default construction require an explicit strict/legacy mode. Unsupported/missing modes yield no actionable decision.
- [ ] Legacy UNKNOWN merge evaluation is APPROVED; Cases A and B retain their C merge behavior when independent safety permits. Unresolved independent safety remains a policy error/no actionable plan, never implicit authorization.
- [ ] Migration fixtures demonstrate possible CREATE under strict versus REUSE under legacy for old boundary-less candidates, and exclusion in both modes once a conflicting boundary is resolved.
- [ ] Cross-boundary strong fixtures require semantic equality plus approved namespace/provenance admission before ranking; stronger/newer labels alone are insufficient.
- [ ] Agent cross-boundary matching with insufficient provenance is rejected under an explicitly assumed type rule; the fixtures distinguish eligible incoming evidence from pairwise candidate rejection. Strong eligibility is independent of strict/legacy fuzzy admission.
- [ ] An eligible incoming strong value with boundary-rejected candidates still blocks fuzzy; only incoming strong ineligibility can permit the existing fallback gate.
- [ ] Strong selection allowance does not authorize cross-boundary merge targets; merge-boundary predicates and candidate-linked diagnostics remain pending.
- [ ] Callers/shared configuration resolve network aliases and equivalence before reconciliation; library tests use supplied canonical BoundaryIDs and require no equivalence graph, database, scanner discovery, or external services.
- [ ] Optional ScannerID absence does not defeat resolved boundary compatibility; a separate producer eligibility rule may require provenance. The initial API has one logical boundary per matching view; callers partition observation/candidate history by boundary and never assign old values to the latest boundary. Advanced mixed-boundary provenance is outside initial scope absent a concrete reviewed requirement.
- [ ] Logical boundary comparisons do not mutate identifier scopes or change normalization/classification; authorization remains caller-owned.
- [ ] Nil freshness, epoch, pre-epoch, same-second/subsecond times, ties, history conflicts, and explicit evaluation
      time have policy-specific tests.
- [ ] Identical input arrays/policy yield identical selected indices, merge index order, keys, reasons, and conflict
      details; map iteration cannot decide ranking.
- [ ] Row-order permutation tests document legacy survivor changes on exact ties rather than claiming permutation
      invariance.
- [ ] Duplicate keys, unkeyed rows, malformed/unsupported inputs, and disabled policy stages have approved
      validation/admission behavior.
- [ ] Unknown/duplicate/overlapping types, invalid weights/modes, incomplete required policy, and computed nonfinite
      scores produce errors, not actionable decisions.
- [ ] A CONFLICT result contains explanatory evidence and no actionable selected/new/merge key plan; invalid input is
      separately an error.
- [ ] Inputs/history are unchanged and result data independently owned; concurrency tests pass for shared immutable
      inputs.
- [ ] Differential tests against the pinned C kernel cover all compatible fixtures and explicit counterexamples before
      any compatibility claim is made.
- [ ] Pending table rows remain unresolved until signed-off domain decisions specify complete expected outputs;
      implementation cannot simply ignore those rows.

## 10. Comparison with C and intentional differences

The aim is one common algorithm, not two permanently maintained reconcilers. The C source provides the reference and
future differential oracle for the fuzzy kernel.

| Area                           | C implementation                                    | Proposed common library / compatibility limit                                                                                          |
| ------------------------------ | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Stages | Containment-only | APPROVED highest-priority unique strong selection; fuzzy only without eligible incoming strong evidence; eligible strong no-match creates despite weak matches |
| Equality                       | Exact type/string sets                              | SPEC-001B canonical typed/scope equality changes differently formatted inputs                                                          |
| Scored types | MAC/IP/hostname | APPROVED configurable fuzzy members/weights; default MAC/IP/hostname values preserved; classifications are not algorithm constants |
| Containment types              | All stored enum keys                                | Explicit fuzzy projection removes strong/out-of-stage evidence; changes some outcomes                                                  |
| FQDN                           | No separate enum here                               | Keep supported model type; approved stage projection needed to coalesce/ignore                                                         |
| Candidate rank                 | Score, whole-second last_seen, first row            | Legacy rank preserved in explicit fixture mode; missing/subsecond/key-tie modes are changes                                            |
| Merge admission                | Key plus subset only                                | Domain-approved boundary/conflict/evidence filters may change merge lists                                                              |
| Empty subsets                  | Mergeable                                           | Exclusion would be an intentional eligibility change                                                                                   |
| Same priority strong ambiguity | Not represented | APPROVED eligible same-value newest/missing-last/exact-key ranking; candidate-linked evidence and merge eligibility remain pending; fuzzy unchanged |
| Unknown/unscored types         | Can affect subsets, score zero                      | Typed rejection/projection is an intentional contract difference                                                                       |
| Duplicate asset keys           | Row semantics, sometimes repeated targets           | Rejection/deduplication/aggregation are separate proposals, not silent cleanup                                                         |
| Decisions                      | New-key flag, survivor pointer/index, merge indices | Same meaningful fields plus action/stage/reasons/conflict and explicit presence                                                        |
| Persistence/key generation     | Not performed in this function                      | Remains caller-owned; preserve old key when selected                                                                                   |

Exact legacy compatibility is limited to already canonical supported fuzzy values, matching scope treatment, equivalent
eligible row sets, equivalent timestamp representation, approved DNS projection, and legacy subset/key/tie modes. It
must be demonstrated with differential tests, not asserted for all gvmd data. Canonicalization alone can change
duplicate counts, intersections, or containment; producer adaptation is part of compatibility work.

## 11. Open decisions blocking deterministic implementation

1. Define contradictory strong evidence, same-type multiplicity/history, and absent versus disagreeing values. Cross-priority candidate-selection precedence is APPROVED; conflict diagnostics and any separate merge evaluation remain unresolved and must not silently override that selection.
2. **RESOLVED — APPROVED same-priority ranking:** newest LastSeen at nanosecond UTC precision, missing last, exact-byte lexical key ties, existing-key reuse, and no automatic merging, after eligibility/conflict checks. Conflicting multiple incoming values, duplicate candidate rows sharing a key, candidate-linked matching evidence/diagnostics, and strong merge eligibility remain PENDING DOMAIN DECISION.
3. Define separate merge eligibility and cross-key conflict handling, including any fuzzy merge vetoes for candidate strong evidence. Strong selection does not authorize merging lower-priority or graph-connected matches.
4. **RESOLVED — APPROVED fallback:** only absence of eligible incoming strong identifiers enters fuzzy. Eligible strong no-match returns CREATE absent unresolved strong conflict; ambiguity and contradiction stay within the strong-conflict policy. Eligibility definitions and conflict resolution remain open, not the fallback rule.
5. **RESOLVED — APPROVED boundary roles/admission:** qualified logical BoundaryID, optional ScannerID provenance, caller-resolved equivalence, COMPATIBLE/INCOMPATIBLE/UNKNOWN outcomes, strict/legacy selection and merge evaluation, strict default for new deployments, and caller-partitioned single-boundary history. Qualified-key issuance/syntax/validation, authoritative assignment/trust, invalid-key handling, type-specific strong producer provenance, and independent merge-safety predicates remain pending. Advanced mixed-boundary representations are outside initial scope absent a concrete requirement.
6. Resolve explicitly configured FQDN participation, DNS projection, and shared-bucket weights without double counting or changing SPEC-001B. Supported-type reclassification is APPROVED; the default leaves FQDN unassigned.
7. Approve literal empty-set merge behavior or an explicit exclusion, including candidates made empty by stage
   projection or eligibility filtering.
8. Choose historical evidence admission, active-view construction, expiry/evaluation-time rules, and candidate
   `LastSeen` derivation/missingness. Specify how changed weak values affect eligibility without erasing history.
9. Approve duplicate-key and unkeyed-row admission, malformed/unsupported evidence behavior, and whether any key-level
   merge-plan deduplication may differ from C row semantics.
10. Resolve exact-zero weight behavior, custom fuzzy accumulation order, numeric/overflow limits, final native enums/structs, diagnostics, and conflict/provenance representation. Supported-type selection, strong reordering/omission/disabling, default membership/weights, and duplicate/unknown/overlap validation are APPROVED and no longer open architectural decisions.

Until these decisions have explicit approved values, there is no complete production policy and no safe deterministic
implementation contract for all requested cases. The documented legacy kernel and conditional fixtures can be
implemented/tested only within their stated assumptions.

## 12. Out of scope

Go implementation, the C adapter, candidate discovery/querying, OSI authorization, database mutation, identifier/key
generation, evidence persistence or retention systems, YAML/database policy loading, and unapproved business-rule
defaults. Advanced mixed-boundary provenance representations are outside initial scope unless a concrete requirement demands a separately reviewed extension.
