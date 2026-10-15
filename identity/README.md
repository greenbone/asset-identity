# Identity matching

`Decide(observation, candidates, policy)` matches caller-prepared eligible views.
Applications own boundaries/equivalence, discovery, filtering, permissions, active
identifier views, producer admission, and applying results. Scope remains part of
identifier identity and is never discarded for scanner filtering.

`MatchPolicy` contains `StrongOrder` and ordered `Fuzzy` type/weight entries.
Greenbone defaults use the approved strong priority and C fuzzy accumulation order
MAC/hostname/IP with weights 1/.4/.4. Policies and clones own their slices.

Strong matching runs first, ranks same-value candidates by newest UTC nanosecond
LastSeen, missing last, then key bytes. Strong no-match creates a key without fuzzy
fallback. Distinct incoming values at the winning strong priority produce CONFLICT;
if nothing matches, multiplicity of any configured strong type produces CONFLICT.
Lower-priority disagreements and candidate-only values do not veto selection.

The internal fuzzy kernel uses C float32 scoring, whole-second timestamp ranking,
nil-as-Unix-epoch fuzzy times, input-order ties, and literal empty subsets. No public compatibility modes remain.
Potential targets produce non-actionable REVIEW with proposed survivor/new-key
information preserved. No result authorizes merges or mutates database state.

Nonpositive/nonfinite fuzzy weights, fuzzy FQDN membership, empty candidate keys,
and duplicate candidate keys are rejected. FQDN remains supported as strong. Inputs are not
mutated or retained; callers synchronize concurrent mutation.

See [SPEC-002](../docs/specs/SPEC-002-reconciliation.md) and the
[C reference fixtures](testdata/README.md) for contracts and compatibility limits.
