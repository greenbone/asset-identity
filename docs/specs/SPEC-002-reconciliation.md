# SPEC-002: Asset Reconciliation

`Decide(observation, candidates, policy)` returns CREATE or REUSE and a merge plan.
The Go and GLib C APIs use the same algorithm.
The application selects inputs and applies the result.
The library does not store results or use the current time.

## Inputs and results

| Input         | Content                                                                      |
| ------------- | ---------------------------------------------------------------------------- |
| `Observation` | Identifiers from the incoming scan                                           |
| `Candidate`   | One stored scan snapshot: `AssetKey`, `Identifiers`, and optional `LastSeen` |
| `MatchPolicy` | Strong priorities, continuity types, and fuzzy members                       |

One candidate represents one scan snapshot.
All its identifiers share the observation time in `LastSeen`.
Several candidates can have the same asset key.
Do not combine identifiers from different scans in one candidate.

Supply complete eligible identifiers for each snapshot.
Include the strong evidence needed for conflict checks across each asset's snapshots.
The application controls access, scanner scope, network scope, freshness, and retention.
A snapshot qualifies if it meets the rules of its matching stage.

| Action | `NeedsNewKey` | `SelectedKey`            | `SelectedIndex`                             |
| ------ | ------------- | ------------------------ | ------------------------------------------- |
| CREATE | true          | Empty                    | Absent                                      |
| REUSE  | false         | Existing destination key | Selected snapshot's original input position |

`Stage` is STRONG, CONTINUITY, or FUZZY.
Only STRONG can return merge indices.
Each merge index identifies a source asset key through one snapshot.
Each source key occurs once. The destination key is excluded.

Keep the candidate array unchanged until you apply the result.
Invalid input returns an error and a zero decision.
The library does not change or retain inputs.
Returned data is independent of the inputs.
Concurrent calls can share inputs that no caller changes.

## Policy

The default strong priority is:

Cloud identifier → Greenbone ID → Machine ID → BIOS UUID.

Default continuity types are Agent ID, SSH host key, and TLS public-key hash.
Their order does not select a continuity match.

Default fuzzy members are MAC (1.0), hostname (0.4), IP (0.4), and FQDN (0.4).
This order controls score calculation.
Hostname and FQDN are separate types.

A custom policy can change roles, priorities, and weights.
An empty list disables its stage.
An empty policy is valid.
Unknown types, repeated members, and types in several stages are invalid.
Weights must be positive and finite.
They must remain positive and finite when converted to float32.
Default policies and policy copies own their lists.

## Normalization

Normalize each input once using [SPEC-001B](SPEC-001B-normalization.md).
Ignore placeholders and repeated values as matching evidence.
Other invalid identifiers cause an error.

A raw `x509:` certificate must name the host in its subject CN or DNS SAN.
The same input record must contain the matching hostname or FQDN.
Compare ASCII names without letter case or a final dot.
Wildcard names do not match.
Convert accepted certificates to SPKI hashes.
Supplied `spki-sha256:` values remain eligible.
`EvaluateStrongPriority` and `MatchingIdentifiers` use the same certificate rules.

## Snapshot evidence and selection

### Strong conflicts across snapshots

Use these rules for each asset key and each configured strong type:

1. Find the newest known time among snapshots containing that type.
2. Keep all evidence with that time.
3. Also keep evidence with missing times.
4. Exclude older timestamped evidence of that type from the asset-level conflict check.

For conflict checks, newer timestamped evidence replaces older timestamped evidence of the same strong type.
A newer observation of another type does not replace it.
This rule does not establish permanent device identity.

Find the highest-priority strong type shared with the incoming observation.
Every retained evidence set at that type must match.
Otherwise, exclude the asset from all matching stages.
A missing type is not a conflict.
A higher-priority match takes precedence over differences at lower priorities.
An older snapshot cannot bypass these asset-level checks.
Continuity types do not participate in these asset-level strong checks.

### Timestamp ranking

Check eligibility before ranking snapshots.
For strong matching, first select the winning strong priority.
Then rank its qualifying snapshots by:

1. Known observation time before missing time.
2. Newest UTC time, including nanoseconds.
3. Smallest asset key in byte order.

Fuzzy matching uses the same timestamp and key order.
A newer snapshot that does not qualify cannot affect selection.
Key order makes ties repeatable. It does not prove identity.

For equal times within one key, compare the normalized identifier sets in a stable order.
The implementation sorts quoted type/value pairs for this comparison.
Identical snapshots use the first input position.
Reordering the input can change numeric indices.
It does not change the destination key or the set of source keys.

## Strong matching

Apply the asset-level conflict checks first.
Then compare the incoming observation with each permitted snapshot.

1. Find the highest-priority strong type present in both records.
2. Reject the snapshot if that type conflicts.
3. Otherwise, record the match and its priority.
4. Select the highest-priority match.
5. Use timestamp ranking for ties at that priority.

Default strong types need one equal normalized value.
If a custom policy makes TLS strong, TLS requires equal complete key sets.

Return REUSE for the selected key.
A stronger incoming type missing from the stored record does not require CREATE.
If no strong match qualifies, continue to continuity matching.

## Continuity matching

Any shared configured continuity value can qualify a snapshot without a strong conflict.
Agent IDs use normalized equality.
SSH and TLS use normalized public keys.
A difference in another continuity type does not reject the match.
Weak differences do not reject a unique continuity match.

TLS needs one shared eligible key.
For example, `{A,B}` matches `{A}`, `{A,C}`, or `{A,B,C}`.
Repeated values and value order do not affect equality.

| Distinct matching asset keys | Result                                                         |
| ---------------------------- | -------------------------------------------------------------- |
| One                          | REUSE at CONTINUITY; use that key's newest matching snapshot   |
| Several                      | Run fuzzy matching only on their continuity-matching snapshots |
| None                         | Run fuzzy matching on all snapshots without a strong conflict  |

Several matching snapshots of one key count as one asset.
Continuity decisions never return merges.
A shared service key does not prove that several assets are one asset.

## Fuzzy matching

Compare configured weak types in each permitted snapshot.

- Require a shared value of a configured type other than MAC.
- Allow a type to be missing from either record.
- Do not use MAC to accept or reject a candidate.
- For types other than IP and MAC, require a shared value when both records contain that type.
- If both records contain IPs but none matches, require a shared FQDN.
- The policy must include FQDN to accept that IP change.
- A short hostname cannot support an IP change.

If snapshots qualify, use timestamp ranking and return REUSE.
If none qualifies, return CREATE.
Fuzzy decisions always return empty `MergeIndices`.

Weights calculate a shared-value score with float32 arithmetic in policy order.
Scores do not set an acceptance threshold or select a candidate.
A nonfinite score causes an error.
MAC normalization and strong-stage MAC merge checks still apply.

The application supplies only values permitted by its scope and freshness rules.
Retired values must not remain eligible.
An IP-only observation cannot detect reassignment if only the previous asset still supplies that IP.

## Merge plan

Only a strong match can permit merges.
Use the selected snapshot as the destination record.
For snapshot merge checks, order types as `StrongOrder` followed by `Continuity`.
Continuity order affects these checks only.

| Source and destination                        | Requirement                                                           |
| --------------------------------------------- | --------------------------------------------------------------------- |
| Both contain strong or continuity identifiers | The source's highest type matches the destination or incoming record  |
| Either lacks those identifiers                | Every source weak value occurs in the destination's nonempty weak set |

Check the incoming and destination records separately.
Do not combine their partial TLS sets into a match.
A source type missing from both records cannot match through a lower type.
An empty source weak set is contained by a nonempty destination weak set.

Let the selecting priority be the strong priority that selected the destination.
Reject snapshot sources with these conflicts:

- An incoming conflict above the selecting priority.
- A stored-destination conflict at or above the selecting priority.

Differences at lower priorities can follow a higher match.
TLS merge checks require complete key-set equality when TLS is the source's deciding type.
A match at a higher priority still takes precedence.

Also apply the asset-level checks:

1. Reject source keys that fail the incoming strong-conflict check.
2. Require each retained set of the source's highest strong type to match the incoming record or destination evidence.
3. Reject source/destination strong conflicts at or above the selecting priority.

An older snapshot cannot hide a conflicting or unlinked current strong identifier.
Snapshot merge checks must also pass.
Do not combine snapshots to create a qualifying snapshot match.

Return one index per source key.
Use that source key's newest qualifying snapshot and the same tie rule.
Return indices in original input order.
Exclude all snapshots of the selected key.
CREATE returns no merge indices.

The application applies each merge to the whole source asset.
It preserves earlier observations and their times.
It stores the incoming observation and applies merges in one transaction.

## Examples

These examples use the default policy.
Candidate numbers identify original input positions.

| Stored snapshots                                             | Incoming           | Result              | Merge keys  |
| ------------------------------------------------------------ | ------------------ | ------------------- | ----------- |
| A: Nov 1 IP1; A: Nov 15 IP2; B: Nov 14 IP1                   | IP1                | FUZZY REUSE B       | None        |
| X: Nov 1 Machine M; X: Nov 15 Machine N; Y: Nov 14 Machine M | Machine M          | STRONG REUSE Y      | None        |
| X: Nov 1 Machine M; X: Nov 15 IP2; Y: Nov 14 Machine M       | Machine M          | STRONG REUSE Y      | X           |
| K0: older Agent A; K0: newer Machine Y, Agent A              | Machine X, Agent A | FUZZY CREATE        | None        |
| K0: Agent A                                                  | Machine X, Agent A | CONTINUITY REUSE K0 | None        |
| Candidate 0 K0: Agent A; candidate 1 K1: Machine X           | Machine X, Agent A | STRONG REUSE K1     | K0, index 0 |
| K0: IP1, MAC M                                               | IP2, MAC M         | FUZZY CREATE        | None        |
| K0: IP1, FQDN F                                              | IP2, FQDN F        | FUZZY REUSE K0      | None        |
| K0: TLS keys {A}                                             | TLS keys {A,B}     | CONTINUITY REUSE K0 | None        |

## Validation

Validate the policy first.
Then validate all candidate keys and times.
Then validate all identifiers, including unmatched candidates and disabled types.

Reject empty keys with `ErrEmptyCandidateKey`.
Accept repeated asset keys.
Reject present times outside UTC years 1–9999.
Keep original input indices.
Policy errors support `errors.Is(err, ErrInvalidMatchPolicy)`.
Identifier and timestamp errors keep their existing error categories.

## C API

The [public header](../../include/gvm_asset_identity.h) defines the C interface.
Constructors copy raw values. `gvm_asset_identity_decide` normalizes them.
SSH values can include a leading port.
TLS values can use `x509:<base64-DER-certificate>`.

### Ownership and calls

- Constructors return owned objects.
- Parent objects own their children.
- Matching free functions accept NULL.
- `policy_new` creates all three policy arrays.
- Clearing an array disables its stage.
- `policy_free` releases all policy arrays.
- `decide` borrows inputs and returns an owned decision.
- Do not change inputs during the call.
- On failure, the decision is NULL.
- Output slots must not share storage with inputs or each other.
- Initialize `GError *` to NULL.
- Release errors with `g_clear_error`.

Use real GLib arrays and live, aligned objects of the declared types.
Strings must end with NUL and must not contain embedded NUL bytes.
No Go pointer crosses the ABI.

### Timestamps and limits

A C timestamp contains a presence flag, signed Unix seconds, and nanoseconds.
Nanoseconds must be 0–999999999.
Present times must be within UTC years 1–9999.
Absent timestamps must have zero seconds and nanoseconds.

Each call permits:

- At most 1,048,576 entries per collection.
- At most 16 MiB per string.
- At most 64 MiB for private wire arrays and string bytes.

Errors are `INVALID_INPUT`, `INVALID_POLICY`, or `INTERNAL`.
Recoverable Go panics return `INTERNAL`.
Fatal runtime errors and allocation failures keep their normal process behavior.

### Installation and compatibility

ABI 3 installs this library chain:

```text
libgvm_asset_identity.so -> libgvm_asset_identity.so.3 -> libgvm_asset_identity.so.<version>-<arch>
```

The ABI version is separate from the package version.
The earlier ABI 3 policy change added the C `continuity` array.
Consumers from older ABIs must rebuild against the ABI 3 header.
Do not load ABI 3 through an older ABI symlink.

Consumers need the installed header, library, and GLib.
Go and Cgreen are build or test dependencies.
`DESTDIR` stages installation without changing package metadata.
Uninstall removes project files only.
CTest sets `CGREEN_NO_FORK=1` for the Go runtime and clears loader overrides.
Cross-builds need matching GLib files, a compiler, and a sysroot.
See the [build instructions](../../README.md#c-build-test-and-install).

## Consumer migration

Snapshot matching keeps the Go/C signatures and structures unchanged.
ABI 3 remains in use.
Callers must supply individual snapshots with actual observation times.
See [consumer migration](../../README.md#consumer-migration) for the required gvmd changes.

## Verification

Run:

```sh
make test
make test-install
go test -race ./...
CGO_ENABLED=0 go test ./...
go vet ./...
```

The [snapshot tests](../../identity/snapshot_test.go) cover timestamp ranking, repeated keys, conflicts, candidate order, and merge safety.
The [counting matrix](../../identity/counting_matrix_test.go) covers identifier combinations and scan sequences.
The [weak tests](../../identity/fuzzy_regression_test.go) and [MAC tests](../../identity/fuzzy_mac_regression_test.go) cover fuzzy eligibility.
The [continuity tests](../../identity/continuity_test.go) cover rotation, shared keys, fallback, and strong merges.
C tests cover the same public behavior, validation, and ownership.

The [historical reference fixtures](../../identity/testdata/fuzzy_reference.json) verify score arithmetic only.
Their earlier matching and merge decisions do not define current fuzzy behavior.
