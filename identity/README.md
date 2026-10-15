# Matching foundations (SPEC-002 Phase 1)

These native Go helpers implement the approved policy, boundary, correspondence,
priority, and ranking foundations. They do not implement reconciliation or merging.

- `GreenboneMatchPolicy()` returns independent defaults: seven strong types in
  approved order, MAC/IP/hostname fuzzy weights, and strict boundary admission.
- `MatchPolicy.Validate()` checks foundation configuration only. Success does not
  establish a complete production policy. `Clone()` copies membership slices.
- `CompareBoundaries()` requires caller-resolved qualified compatibility-class
  keys: equal keys identify compatible contexts, distinct keys identify known
  incompatible contexts, and an empty key means missing/unresolved. The library
  validates no qualification format and does not make arbitrary strings trusted.
  Scanner IDs are optional provenance and do not affect comparison.
- `FuzzyBoundaryMode.Admit()` applies strict/legacy admission to both fuzzy
  selection and merge evaluation. Admission is not merge authorization. This gate
  does not determine incoming strong eligibility or trigger fuzzy execution.
- `MatchingIdentifiers()` returns distinct canonical semantic intersections with
  independent scope storage, using the existing SPEC-001B equality contract.
- `EvaluateStrongPriority()` accepts explicitly admitted identifier views and
  reports correspondence at the first matching configured priority. It reports
  whether incoming configured strong evidence exists independently of candidate
  correspondence. Multiple matches remain informational; no survivor is chosen.
- `RankStrongCandidates()` accepts one already eligible, noncontradictory,
  same-value set at the winning priority. It returns input positions in newest
  UTC nanosecond order, present before missing, then exact-byte lexical key order.
  The first position identifies the existing key to reuse under those preconditions.
  Do not automatically rank a union of conflicting incoming values.

No helper infers strong cross-boundary validity. Producer, namespace, eligibility,
and conflict checks remain explicit preconditions with pending domain contracts.
Callers partition history by boundary; the helpers take no history and perform no
implicit union, timestamp derivation, replacement, expiry, or wall-clock lookup.

`ErrInvalidMatchPolicy` identifies violated approved configuration constraints.
`ErrUnresolvedMatchingRule` explicitly defers zero-weight fuzzy semantics, fuzzy
FQDN projection/weighting, duplicate asset-key rows, and unkeyed ranking rows.
Normalization errors propagate without partial correspondence; this does not
choose the final reconciliation input-admission/quarantine policy. Ranking rejects
out-of-range UTC timestamps under the existing year 1..9999 model contract.
Fuzzy weights are configuration data; no scoring precision or accumulation order
is implemented or approved by their Go representation.

`Decide()`, conflict resolution, multiple-value compatibility, producer trust,
independent merge safety, duplicate-key admission, historical eligibility, fuzzy
containment/scoring, and the C adapter are deferred. The Greenbone default does not
grant any of these permissions. Boundary-key qualification and advanced provenance
representations also remain outside these foundations.

All helpers are read-only and safe for concurrent calls sharing immutable inputs.
Callers must synchronize concurrent mutation of their slices, maps, and pointers.
