# How Asset Identity Works

Asset-identity compares a new scan result with stored scan snapshots.
It returns `CREATE` or `REUSE`.
It can also return asset keys to merge through `MergeIndices`.
The Go and C APIs use the same algorithm.

## 1. The decision in one example

A stored snapshot has IP `192.0.2.10` and key K0.
A new scan reports the same IP.
The library returns `REUSE K0` at the `FUZZY` stage.
The application stores the new scan result under K0.

## 2. Prepare the inputs

| Input                | Meaning                                                 |
| -------------------- | ------------------------------------------------------- |
| `Observation`        | Identifiers from the new scan                           |
| `Candidate`          | Identifiers from one stored scan snapshot               |
| `Candidate.AssetKey` | The asset key assigned to that snapshot                 |
| `Candidate.LastSeen` | The time when that snapshot's identifiers were observed |
| `MatchPolicy`        | Identifier roles, priorities, and fuzzy weights         |

Several candidates can have the same asset key.
All identifiers in one candidate share its `LastSeen` time.
Do not combine identifiers from different scans in one candidate.
Leave an unknown time missing.

Supply each snapshot's complete eligible identifiers.
Include the strong evidence needed to detect conflicts for each asset key.
A snapshot can supply this evidence even if its weak identifiers do not match the new scan.

The application selects the permitted scanners, networks, tenants, and stored values.
It also applies access and freshness rules.
A snapshot qualifies when its identifiers meet the matching rules.
The library uses only the supplied inputs.
It does not read a database.

## 3. Identifier roles

The default strong priority is:

Cloud identifier → Greenbone ID → Machine ID → BIOS UUID.

The default continuity types are Agent ID, SSH host key, and TLS public-key hash.
Any shared continuity value can support a match.
No continuity type has priority over another.

The default fuzzy types are:

| Type     | Weight |
| -------- | ------ |
| MAC      | 1.0    |
| Hostname | 0.4    |
| IP       | 0.4    |
| FQDN     | 0.4    |

Scores do not select a candidate.
MAC does not accept or reject a fuzzy match.
Hostname and FQDN are separate identifier types.

A custom policy can change these roles and priorities.
An empty list disables its stage.

## 4. Normalize the values

Normalization converts equivalent inputs to a common format.
`Decide` does this automatically.
It does not change the supplied inputs.

| Input                               | Matching value                               |
| ----------------------------------- | -------------------------------------------- |
| MAC `02-AB-CD-EF-01-23`             | `02:ab:cd:ef:01:23`                          |
| IP `2001:0DB8::1`                   | `2001:db8::1`                                |
| FQDN `WEB.EXAMPLE.COM.`             | `web.example.com`                            |
| SSH `22 <algorithm> <key>`          | Algorithm and public key                     |
| TLS `x509:<base64-DER-certificate>` | SHA-256 hash of the certificate's public key |

The library ignores placeholder values such as `localhost`, a loopback IP, or a zero MAC.
Other invalid values cause an error.

An `x509:` certificate must name the host in its subject CN or DNS SAN.
The same snapshot or incoming observation must supply the matching hostname or FQDN.
Name comparison ignores letter case and a final dot.
Wildcard names do not match.
The library does not check certificate trust or expiry.

See [SPEC-001B](specs/SPEC-001B-normalization.md) for all input formats and normalization rules.

## 5. Matching order

1. Check strong conflicts for each asset key.
2. Try strong matching against each permitted snapshot.
3. If no strong match exists, try continuity matching.
4. If continuity does not select one asset, try fuzzy matching.
5. If no snapshot qualifies, return `CREATE`.

Only a strong-stage decision can return merges.
The application creates keys and applies the result.

## 6. Strong and continuity matching

### Strong matching

Compare the highest-priority strong type present in both records.
A missing type is not a conflict.
A match at a higher priority takes precedence over differences at lower priorities.

Select the highest-priority match first.
Then select its newest qualifying snapshot.

### Strong conflicts across snapshots

Check each strong type separately for each asset key:

1. Find the newest known observation time for that type.
2. Keep all snapshots with that time for the type's conflict check.
3. Also keep evidence with missing times.
4. Ignore older timestamped values of that type in the conflict check.

At the highest shared strong priority, every retained evidence set must match the incoming observation.
Otherwise, exclude the asset.
An older snapshot cannot bypass this check.

New evidence replaces old evidence only for the same strong type.
A newer IP-only snapshot does not replace earlier Machine ID evidence.
These rules do not prove that device identity is permanent.

| Stored snapshots for K0                        | Incoming identifiers | Result   |
| ---------------------------------------------- | -------------------- | -------- |
| Older: Agent A; newer: Machine Y, Agent A      | Machine X, Agent A   | CREATE   |
| Older: Machine X; newer: Machine Y             | Machine X            | CREATE   |
| Older: Machine X; newer: IP2                   | Machine X            | REUSE K0 |
| Same time: Machine X and Machine Y             | Machine X            | CREATE   |
| Unknown time: Machine Y; known time: Machine X | Machine X            | CREATE   |

These examples assume that no other asset qualifies.

### Continuity matching

A shared Agent ID, SSH key, or TLS key can select an asset without a strong conflict.
Differences in weak identifiers or other continuity types do not reject a unique match.
TLS needs only one shared eligible key: `{A,B}` can match `{A,C}`.

Count distinct asset keys:

| Matching keys | Action                                                           |
| ------------- | ---------------------------------------------------------------- |
| One key       | REUSE at CONTINUITY; select its newest matching snapshot         |
| Several keys  | Try fuzzy matching among their continuity-matching snapshots     |
| No keys       | Try fuzzy matching among all snapshots without a strong conflict |

Several matching snapshots of K0 still count as one asset.
Continuity decisions never return merges.

## 7. Fuzzy matching

Apply these rules to each snapshot without a strong conflict:

1. Require a shared value of a configured type other than MAC.
2. Allow a type to be missing from either record.
3. Require a shared name when both records supply that name type.
4. If both records have IP addresses but none matches, require a shared FQDN.
5. Do not use MAC to accept or reject the match.

The policy must include FQDN for rule 4.
A short hostname cannot support an IP change.

| Incoming identifiers   | Stored identifiers     | Result |
| ---------------------- | ---------------------- | ------ |
| IP1                    | IP1, FQDN F, MAC M     | REUSE  |
| IP2, FQDN F            | IP1, FQDN F            | REUSE  |
| IP2, hostname H, MAC M | IP1, hostname H, MAC M | CREATE |
| IP1, MAC M2            | IP1, MAC M1            | REUSE  |
| IP1, hostname H2       | IP1, hostname H1       | CREATE |
| MAC M                  | MAC M                  | CREATE |

These examples assume one candidate without a strong conflict.

If several snapshots qualify, select the newest one.
Known times rank before missing times.
Equal or missing times use the smallest asset key in byte order.
This key order makes the result repeatable. It does not prove identity.
Fuzzy decisions never return merges.

For example:

| Asset | Observation time | IP  |
| ----- | ---------------- | --- |
| A     | Nov 1            | IP1 |
| A     | Nov 15           | IP2 |
| B     | Nov 14           | IP1 |

An incoming IP1-only observation selects B.
A's Nov 15 snapshot does not qualify because it reports IP2.

## 8. The returned decision

| Field           | Meaning                                              |
| --------------- | ---------------------------------------------------- |
| `Action`        | `CREATE` or `REUSE`                                  |
| `NeedsNewKey`   | True for CREATE                                      |
| `Stage`         | STRONG, CONTINUITY, or FUZZY                         |
| `SelectedKey`   | Existing destination key for REUSE                   |
| `SelectedIndex` | Position of the selected snapshot in the input array |
| `MergeIndices`  | One input position per source asset key to merge     |

`SelectedIndex` is absent for CREATE.
Go uses nil. C uses `has_selected_index = FALSE`.

A merge index identifies a whole source asset through one snapshot.
Move all snapshots of that source key to the destination key.
Each source key occurs once.
The destination key never appears in the merge list.

For equal times within one asset, normalized identifier order selects the representative snapshot.
Identical snapshots use the first input position.
Reordering candidates can change the numeric indices.
It does not change the selected key or the set of source keys.

### Merge example

| Input                | Identifiers        | Asset key |
| -------------------- | ------------------ | --------- |
| Incoming observation | Machine X, Agent A | None      |
| Candidate 0          | Machine X          | K0        |
| Candidate 1          | Agent A            | K1        |

The result is:

```text
Action: REUSE
Stage: STRONG
SelectedKey: K0
SelectedIndex: 0
MergeIndices: [1]
```

The incoming observation links Agent A to Machine X.
This permits merging K1 into K0.
Current conflicting Machine ID evidence on K1 prevents the merge.
The library checks other snapshots of K1 before it permits the merge.

All source keys must pass the strong merge checks.
These checks also cover weak subsets and complete TLS key sets.
See [SPEC-002](specs/SPEC-002-reconciliation.md#merge-plan) for the complete rules.

## 9. Call from Go or C

Go:

```go
decision, err := identity.Decide(observation, candidates, identity.GreenboneMatchPolicy())
```

C:

```c
gvm_asset_identity_decide(observation, candidates, policy, &decision, &error);
```

Invalid input returns an error. It does not return CREATE.
Keep the candidate array unchanged until you apply the result.
Free the C decision with `gvm_asset_identity_decision_free`.
See the [README](../README.md#c-build-test-and-install) for a complete C example.

## 10. Apply the result

1. If the call returns an error, stop.
2. For REUSE, use `SelectedKey`.
3. For CREATE, generate a new key.
4. Store the incoming observation under that key.
5. Move each source asset from `MergeIndices` to that key.

Apply the storage changes in one transaction.
Keep the original observation times when you move snapshots.
The application manages storage, access rules, and snapshot retention.

The Go/C signatures and structures are unchanged. ABI 3 remains in use.
Applications must supply separate snapshots with actual observation times.
See [consumer migration](../README.md#consumer-migration) for the required gvmd changes.

## 11. Further reading

- [SPEC-001B](specs/SPEC-001B-normalization.md): identifier formats and normalization.
- [SPEC-002](specs/SPEC-002-reconciliation.md): complete matching, merge, and API rules.
- [Public C header](../include/gvm_asset_identity.h): types and functions.
