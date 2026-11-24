![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# asset-identity

Asset-identity compares new scan results with stored scan snapshots.
It returns CREATE or REUSE.
A strong match can also permit merges between existing assets.

The library provides Go and GLib C APIs.
Both APIs use the same algorithm. The C ABI version is 3.
The application supplies the inputs and stores the result.

## Build status

[![Build and tests](https://github.com/greenbone/asset-identity/actions/workflows/build-and-tests.yaml/badge.svg)](https://github.com/greenbone/asset-identity/actions/workflows/build-and-tests.yaml)
[![Release](https://github.com/greenbone/asset-identity/actions/workflows/release.yml/badge.svg)](https://github.com/greenbone/asset-identity/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/greenbone/asset-identity/branch/main/graph/badge.svg)](https://codecov.io/gh/greenbone/asset-identity)

## Go

```sh
go get github.com/greenbone/asset-identity
```

```go
package main

import (
	"github.com/greenbone/asset-identity/identity"
	"log"
)

func main() {
	observation := identity.Observation{Identifiers: []identity.IdentifierValue{
		{Type: identity.TypeIP, Value: "192.0.2.10"},
	}}
	decision, err := identity.Decide(observation, nil, identity.GreenboneMatchPolicy())
	if err != nil {
		log.Fatal(err)
	}
	log.Print(decision.Action) // CREATE
}
```

Supply only identifiers from permitted sources.
Normalization makes values comparable. It does not establish trust in the source.

| Action | Application action             |
| ------ | ------------------------------ |
| CREATE | Generate a new asset key.      |
| REUSE  | Use the selected existing key. |

## Matching

The library tries these stages in order:

| Stage      | Default identifier types                         | Selection                                                |
| ---------- | ------------------------------------------------ | -------------------------------------------------------- |
| Strong     | Cloud ID → Greenbone ID → Machine ID → BIOS UUID | Highest shared priority, then newest qualifying snapshot |
| Continuity | Agent ID, SSH key, TLS public-key hash           | One distinct matching asset key                          |
| Fuzzy      | MAC, hostname, IP, FQDN                          | Newest snapshot that meets the weak matching rules       |

Strong conflicts exclude an asset from matching.
Missing strong types are allowed.
A match at a higher priority takes precedence over differences at lower priorities.

For continuity, any shared value can select one compatible asset key.
Several matching snapshots of that key still count as one asset.
If several keys match, fuzzy matching checks only their continuity-matching snapshots.
If no key matches, fuzzy matching checks all snapshots without a strong conflict.

For fuzzy matching:

- Require a shared configured value other than MAC.
- Allow missing identifier types.
- Reject conflicting names when both records supply that name type.
- If both records have IPs but none matches, require a shared FQDN.
- Do not use a short hostname to accept an IP change.
- Do not use MAC to accept or reject a match.

Default fuzzy weights are MAC (1.0), hostname (0.4), IP (0.4), and FQDN (0.4).
Scores do not select a candidate.
A snapshot qualifies when it meets the matching rules.
If no snapshot qualifies, return CREATE.

## Snapshot candidates

One candidate represents one scan snapshot.
All identifiers in that candidate share its `LastSeen` observation time.
Several candidates can have the same asset key.
Do not combine identifiers from different scans in one candidate.
Leave an unknown time missing.

For strong conflict checks, use the latest evidence for each strong type within each asset.
New evidence replaces older timestamped evidence of the same type.
Keep all equally recent evidence.
Also keep evidence with missing times, because its order is unknown.
A newer observation of another type does not replace that evidence.
These rules do not establish permanent device identity.

Check eligibility before comparing times.
Known times rank before missing times.
Equal or missing times use the smallest asset key in byte order.
This order makes ties repeatable. It does not prove identity.

For example, A reports IP1 on Nov 1 and IP2 on Nov 15.
B reports IP1 on Nov 14.
An incoming IP1-only observation reuses B.
A's newer IP2 snapshot does not qualify.

## Merge results

`SelectedIndex` identifies the selected snapshot in the original candidate array.
`MergeIndices` identifies source asset keys through their original snapshot positions.
Each source key occurs once. The destination key is excluded.
Apply each merge to the whole source asset.

Only strong-stage decisions can return merges.
Incoming Agent, SSH, or TLS evidence can link related records during a strong merge.
All source assets must pass the strong merge checks.
An older snapshot cannot hide current strong conflicts.
Continuity and fuzzy decisions never return merges.

See [the algorithm guide](docs/how-asset-identity-works.md#8-the-returned-decision) for examples.
See [SPEC-002](docs/specs/SPEC-002-reconciliation.md) for the complete rules.

## Consumer migration

The Go/C signatures and structures are unchanged.
ABI 3 remains in use.
Existing callers still compile.
They must supply separate snapshots to provide correct observation times.
`RankStrongCandidates` remains a separate helper with one entry per asset key.

For gvmd integration:

1. Load candidates by snapshot ID.
2. Load each snapshot's complete eligible identifiers.
3. Preserve its assigned asset key.
4. Include the strong evidence needed for conflict checks across the asset's snapshots.
5. Apply the existing scanner, access, and freshness rules.
6. Set `LastSeen` to the actual observation time.
7. Leave unknown times missing.

Update `asset_target_add_candidates` and `asset_candidate_load_identifiers` in `manage_sql_assets.c`.
Group identifier rows by `asset_snapshot`.
Use the existing snapshot storage.

Key assignment and merging change snapshot `modification_time`.
Do not use that field as the observation time.
Verify the time from the associated scan or report-host event before integration.
Do not substitute import time, merge time, or asset-level last-seen time.
Keep the original observation times when merging snapshots.
The gvmd code is unchanged in this repository.

## Scanner identifier values

Pass raw values in `IdentifierValue.Value`.
The library removes surrounding spaces and converts values to a common format.
It ignores placeholders such as `localhost`, loopback IPs, and zero MAC or BIOS UUID values.
Other invalid values cause an error.

| Type                   | Example input                                |
| ---------------------- | -------------------------------------------- |
| `TypeSSHHostKey`       | `22 ecdsa-sha2-nistp256 <base64-public-key>` |
| `TypeTLSPublicKeyHash` | `x509:<base64-DER-certificate>`              |

The library removes the SSH port and uses the public key for comparison.
For TLS, it calculates the public-key hash from the certificate.
The certificate's subject CN or DNS SAN must match a hostname or FQDN in the same input record.
Existing `spki-sha256:` values are also accepted.
Certificate fingerprints and `SSLDetails` or `SSLInfo` metadata cannot supply the public key.

In C, add raw values with `gvm_asset_identity_identifier_new`:

```c
g_ptr_array_add(observation->identifiers,
    gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_SSH_HOST_KEY, ssh_value));
g_ptr_array_add(observation->identifiers,
    gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH, tls_value));
```

Constructors copy the values. `Decide` parses and normalizes them.
The caller does not need to extract or hash keys.
See [SPEC-001B](docs/specs/SPEC-001B-normalization.md) for all accepted formats.

## Formatting and linting

Install golangci-lint v2, clang-format, and Gersemi, then run:

```sh
make format              # format Go, C headers/sources, and CMake files
make format-go           # gofmt and goimports using .golangci.yml
make format-c            # clang-format using .clang-format
make format-cmake        # Gersemi using .gersemirc
make format-check-c      # check C formatting without modifying files
make format-check-cmake  # check CMake formatting without modifying files
make lint                # run the configured Go linters
```

Set `GOLANGCI_LINT`, `CLANG_FORMAT`, or `GERSEMI` to override executable paths.

## Coverage

Run `make cover` to test the `identity` package with the race detector.
This command creates `coverage.out` and `coverage.html`.
These reports exclude the C adapter and C sources.
Run `make test-c` to test the C interface.

CI saves both reports in the `coverage-report` artifact.
It also uploads coverage to Codecov.
Enable `greenbone/asset-identity` in Codecov.
Set the repository secret `CODECOV_TOKEN` for uploads.

## C build, test, and install

For Linux builds, install Go matching [go.mod](go.mod).
Also install a C compiler, pkg-config, and GLib development headers.
For C tests, install CMake 3.18+ and Cgreen 1.6.4+.

```sh
make build                       # dist/libgvm_asset_identity.so
make test                        # Go and native C tests
make test-install                # staged install, consumer tests, uninstall
make install                     # /opt/gvm
make uninstall                   # same PREFIX/LIBDIR/INCLUDEDIR as install
```

Use `PREFIX`, `LIBDIR`, and `INCLUDEDIR` to change installation paths.
Use `DESTDIR` to stage an installation.
For a custom Cgreen location, set `CMAKE_ARGS=-DCMAKE_PREFIX_PATH=/path/to/cgreen`.
`make clean` removes `dist/` and `build/`.

Save this example as `example.c`:

```c
#include <gvm_asset_identity.h>

int main(void) {
    GError *error = NULL;
    gvm_asset_identity_policy_t *policy = gvm_asset_identity_policy_new_default(&error);
    if (!policy) { g_clear_error(&error); return 1; }
    gvm_asset_identity_observation_t *observation = gvm_asset_identity_observation_new();
    g_ptr_array_add(observation->identifiers,
        gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_IP, "192.0.2.10"));
    GPtrArray *candidates = g_ptr_array_new();
    gvm_asset_identity_decision_t *decision = NULL;
    gboolean ok = gvm_asset_identity_decide(observation, candidates, policy, &decision, &error);
    if (ok) g_print("New key: %d\n", decision->needs_new_key);
    else g_printerr("%s\n", error->message);
    gvm_asset_identity_decision_free(decision);
    g_clear_error(&error);
    g_ptr_array_unref(candidates);
    gvm_asset_identity_observation_free(observation);
    gvm_asset_identity_policy_free(policy);
    return ok ? 0 : 1;
}
```

```sh
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
cc example.c $(pkg-config --cflags --libs libgvm_asset_identity) \
    -Wl,-rpath,/opt/gvm/lib -o example
./example
```

Constructors return objects that the caller owns.
Parent objects own their children.
`decide` borrows inputs and returns an owned decision.
Do not change inputs during the call.
Free functions accept NULL. Errors use `GError`.
Consumers need the installed header, library, and GLib.
See the [public header](include/gvm_asset_identity.h) and [C contract](docs/specs/SPEC-002-reconciliation.md#c-api).

## Container image

Build the library image with Docker:

```sh
docker build -f .docker/Dockerfile -t asset-identity .
```

The image stores the library, header, and pkg-config file under `/install/usr/local`.
A consuming image can copy `/install/` into `/` during its build.
Consumers need GLib during build and runtime.

The container workflow uses Greenbone's shared build and push workflow.
It publishes `ghcr.io/greenbone/asset-identity` on main branch and version tag pushes.
It also supports pull request builds and manual runs.

## Algorithm guide

[How Asset Identity Works](docs/how-asset-identity-works.md) explains matching and merging with examples.

## Technical reference

- [SPEC-001](docs/specs/SPEC-001-identifiers.md): identifier requirements.
- [SPEC-001A](docs/specs/SPEC-001A-identifier-model.md): model, timestamps, ownership.
- [SPEC-001B](docs/specs/SPEC-001B-normalization.md): formats, normalization, equality.
- [SPEC-002](docs/specs/SPEC-002-reconciliation.md): reconciliation and C compatibility.

## License

Copyright (C) 2026 Greenbone AG.

Licensed under the GNU Affero General Public License v3.0 only (`AGPL-3.0-only`).
See [LICENSE](LICENSE) for the full text.
