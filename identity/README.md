# Identity matching

Native Go identifier models, normalization, and matching helpers. Contracts and
open domain decisions are in [SPEC-002](../docs/specs/SPEC-002-reconciliation.md).

- `GreenboneMatchPolicy()` returns independent defaults; `Validate()` checks
  foundation configuration, not a complete production policy.
- `CompareBoundaries()` compares caller-resolved qualified keys. `ScannerID` is
  provenance only; empty boundary keys are UNKNOWN.
- `FuzzyBoundaryMode.Admit()` governs fuzzy selection and merge evaluation.
- `MatchingIdentifiers()` returns distinct canonical semantic matches.
- `EvaluateStrongPriority()` reports matches at the highest matching priority.
- `RankStrongCandidates()` ranks an admitted, conflict-checked same-value set.
- `MatchFuzzyKernel()` reports a proposed survivor and potential merge targets.
  Its result is non-actionable and grants no merge authorization.

Callers supply admitted matching views and partition history by boundary. Before
fuzzy evaluation, they must satisfy the strong-stage entry gate. No helper infers
producer trust, strong cross-boundary eligibility, or independent merge safety.

The fuzzy kernel requires explicit `LegacyCCompatibility` and `AccumulationOrder`.
This profile uses float32 scoring, present whole-second timestamps, input-order
ties, and literal empty subsets. C's default score order is MAC, hostname, IP.
See [reference fixtures](testdata/README.md) for compatibility limits and provenance.

Pending zero-weight/FQDN semantics, duplicate/unkeyed rows, and unsupported fuzzy
timestamp cases return `ErrUnresolvedMatchingRule`. `Decide()`, conflict resolution,
history eligibility, merge authorization, and the C adapter remain deferred.

Helpers do not mutate or retain inputs. Concurrent callers must synchronize input
mutation; returned maps, slices, and pointers are independently owned.
