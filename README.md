![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# asset-identity

A Go library for identifier normalization and strong-first asset reconciliation.
`libgvm_asset_identity.so` exposes the same algorithm through a GLib C API (ABI 1). Applications supply eligible
identifiers and candidates; they own scanner boundaries, authorization, persistence, and merge approval.

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

Pass caller-prepared active views; normalization does not establish producer trust. Identifier scopes remain
significant, including absent versus explicitly empty scope.

| Action | Meaning                        |
|--------|--------------------------------|
| CREATE | A new key is required.         |
| REUSE  | Use the selected existing key. |

Strong types follow the configured priority. Reuse requires an existing key with an equally strong or higher-priority
identity and a match at the highest strong type shared by both views. A shared conflict blocks lower-priority matches.
Stronger incoming evidence returns CREATE; compatible older records can merge under the new key. For example, Machine
X + Agent A upgrades an Agent-A-only key, while an Agent-A-only scan reuses a Machine-X + Agent-A key.

Among reusable candidates, the highest-priority shared match wins, then newest timestamp and asset-key ordering. When
incoming strong IDs exist but no candidate qualifies, return CREATE without fuzzy fallback. With no incoming strong IDs,
reuse a candidate containing every incoming weak identifier, or CREATE if none qualifies. Default fuzzy weights are MAC
(1.0), hostname (0.4), IP (0.4), and FQDN (0.4); hostname and FQDN remain distinct types.

TLS compares complete normalized public-key sets, ignoring order and duplicates: `{A,B}` matches `{B,A}`, but not
`{A}` or `{A,B,C}`. A TLS conflict cannot be bypassed by a lower-priority type; a higher-priority match still wins.
Other strong types match any equal scoped value.

`MergeIndices` lists the supplied candidates to move to the destination key. Retrieve each candidate and its asset key
from the original candidate array using the returned index. On CREATE, the application generates the destination key; on
REUSE it uses `SelectedKey`. The application applies the observation and key moves atomically. A strong source must
match its own highest-priority strong type in the destination; records without strong IDs require full fuzzy
containment. A weak destination cannot combine sources with conflicting strong IDs.
See [the algorithm guide](docs/how-asset-identity-works.md#8-the-returned-decision).

## Scanner identifier values

Every identifier type has its own normalizer, run before matching. Pass raw producer values directly in
`IdentifierValue.Value`; the library trims, normalizes, and leaves out placeholders such as `127.0.0.1`, a zero MAC or
BIOS UUID, or `localhost`. Use `NormalizeIdentifier` to get the canonical value to store. For example:

| Type                   | Scanner value                                |
|------------------------|----------------------------------------------|
| `TypeSSHHostKey`       | `22 ecdsa-sha2-nistp256 <base64-public-key>` |
| `TypeTLSPublicKeyHash` | `x509:<base64-DER-certificate>`              |

The library removes the SSH port and normalizes the public key. For TLS, it parses the certificate and calculates the
public-key hash internally; during matching the certificate counts only when its CN or a DNS SAN equals an FQDN or
hostname supplied in the same view. Callers do not need to calculate hashes or strip these value prefixes. `Decide`
performs this normalization automatically. Existing SSH public-key lines and `spki-sha256:` values remain accepted.
Certificate fingerprints and `SSLDetails`/`SSLInfo` metadata alone cannot supply a public key.

In C, pass the same values to `gvm_asset_identity_identifier_new` and add them to the observation (or a candidate's
identifiers):

```c
/* ssh_value is "22 ecdsa-sha2-nistp256 ..."; tls_value is "x509:...". */
g_ptr_array_add(observation->identifiers,
    gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_SSH_HOST_KEY, ssh_value));
g_ptr_array_add(observation->identifiers,
    gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH, tls_value));
```

`gvm_asset_identity_decide` performs parsing and normalization through the same Go implementation. Constructors copy the
supplied values; malformed values produce `GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT`
when deciding. No caller-side key extraction or hashing is required.

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

Run `make cover` to test the core `identity` package with the race detector and generate `coverage.out` and an HTML
report at `coverage.html`. The Go C API adapter in `capi` and C sources are excluded from this report; the separate C
integration tests exercise that boundary through `make test-c`.

CI saves both reports as the `coverage-report` artifact and uploads coverage to Codecov. Enable
`greenbone/asset-identity` in Codecov and configure the repository secret `CODECOV_TOKEN` to match the upload setup used
by `gvm-report-service`.

## C build, test, and install

Linux builds require Go matching [go.mod](go.mod), a C compiler, pkg-config, and GLib development headers. C tests also
require CMake 3.18+ and Cgreen 1.6.4+.

```sh
make build                       # dist/libgvm_asset_identity.so
make test                        # Go and native C tests
make test-install                # staged install, consumer tests, uninstall
make install                     # /opt/gvm
make uninstall                   # same PREFIX/LIBDIR/INCLUDEDIR as install
```

Use `PREFIX`, `LIBDIR`, and `INCLUDEDIR` to change installation paths, or `DESTDIR`
for staging. For a nonstandard Cgreen location, pass
`CMAKE_ARGS=-DCMAKE_PREFIX_PATH=/path/to/cgreen`. `make clean` removes `dist/` and `build/`.

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

Constructors return owned objects; parents own their children. `decide` borrows immutable inputs and returns an
independently owned decision. Free functions accept NULL; errors use `GError`. Consumers need only the installed
header/library and GLib. See the [public header](include/gvm_asset_identity.h) and
[C contract](docs/specs/SPEC-002-reconciliation.md#c-api) for details.

## Container image

Build the library image with Docker:

```sh
docker build -f .docker/Dockerfile -t asset-identity .
```

Like `gvm-auth-lib`, the image carries installation files under `/install/usr/local`:
the shared library, public header, and pkg-config metadata. A consuming image can copy `/install/` into `/` during its
build. Consumers still need GLib at build and runtime as described above.

The container workflow uses Greenbone's shared build and push workflow to publish
`ghcr.io/greenbone/asset-identity` on main branch and version tag pushes, with pull request builds and a manual ref
input.

## Algorithm guide

[How Asset Identity Works](docs/how-asset-identity-works.md) explains the decision flow, strong priority, exact TLS
key-set matching, weak evidence, and Go/C usage through examples.

## Technical reference

- [SPEC-001](docs/specs/SPEC-001-identifiers.md): identifier requirements.
- [SPEC-001A](docs/specs/SPEC-001A-identifier-model.md): model, scope, timestamps, ownership.
- [SPEC-001B](docs/specs/SPEC-001B-normalization.md): formats, normalization, equality.
- [SPEC-002](docs/specs/SPEC-002-reconciliation.md): reconciliation and C compatibility.

## License

Copyright (C) 2026 Greenbone AG.

Licensed under the GNU Affero General Public License v3.0 only (`AGPL-3.0-only`). See [LICENSE](LICENSE) for the full
license text.
