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
fallback. Undefined strong contradictions remain `ErrUnresolvedMatchingRule`;
CONFLICT is reserved for a defined rule, not inferred from differing values.

The internal fuzzy kernel uses C float32 scoring, whole-second timestamp ranking,
input-order ties, and literal empty subsets. No public compatibility modes remain.
Potential targets produce non-actionable REVIEW with proposed survivor/new-key
information preserved. No result authorizes merges or mutates database state.

Zero weights, fuzzy FQDN projection, missing fuzzy timestamps, and unkeyed rows
remain explicit unresolved cases. Duplicate keys are rejected. Inputs are not
mutated or retained; callers synchronize concurrent mutation.

See [SPEC-002](../docs/specs/SPEC-002-reconciliation.md) and the
[C reference fixtures](testdata/README.md) for contracts and compatibility limits.
