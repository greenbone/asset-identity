# Asset identity

A Go library for identifier normalization and strong-first asset reconciliation.
`libgvm_asset_identity.so` exposes the same algorithm through a GLib C API (ABI 1). Applications supply eligible
identifiers and candidates; they own scanner boundaries, authorization, persistence, and merge approval.

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

Strong types are checked in configured priority order. At the first type with matches, the newest candidate wins; equal
timestamps use asset-key ordering. Multiple incoming values of that type participate in the same ranking. If strong
evidence exists but no candidate matches, return CREATE without fuzzy fallback. Otherwise fuzzy matching returns REUSE
for a selected containing candidate, or CREATE if none exists.

At the TLS priority, the observation and candidate must have identical normalized public-key sets. Order and duplicate
values do not matter, but an extra or missing TLS key prevents a TLS match: `{A,B}` matches `{B,A}`, not `{A}` or
`{A,B,C}`. Other strong types retain any-value matching. Priority still applies: higher-priority identifiers can select
an asset independently, and a TLS mismatch allows later configured strong types to be checked.

`MergeIndices` lists the supplied candidates to move to the destination key. Retrieve each candidate and its
asset key from the original candidate array using the returned index. On CREATE, the application generates the
destination key; on REUSE it uses `SelectedKey`. The application applies the observation and key moves atomically. Strong IDs protect merge eligibility; records without
strong IDs require full fuzzy containment. A weak destination cannot combine sources with conflicting strong IDs.
See [the algorithm guide](docs/how-asset-identity-works.md#8-the-returned-decision).

## Scanner identifier values

Pass scanner values directly in `IdentifierValue.Value`:

| Type                   | Scanner value                                |
|------------------------|----------------------------------------------|
| `TypeSSHHostKey`       | `22 ecdsa-sha2-nistp256 <base64-public-key>` |
| `TypeTLSPublicKeyHash` | `x509:<base64-DER-certificate>`              |

The library removes the SSH port and normalizes the public key. For TLS, it parses the certificate and calculates the
public-key hash internally. Callers do not need to calculate hashes or strip these value prefixes. `Decide` performs
this normalization automatically. Existing SSH public-key lines and `spki-sha256:` values remain accepted. Certificate
fingerprints and `SSLDetails`/`SSLInfo` metadata alone cannot supply a public key.

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

With golangci-lint v2 installed:

```sh
make format  # gofmt and goimports using .golangci.yml
make lint    # run the configured linters
```

Set `GOLANGCI_LINT` to override the executable path.

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

## Algorithm guide

[How Asset Identity Works](docs/how-asset-identity-works.md) explains the decision flow, strong priority, exact TLS
key-set matching, fuzzy containment, and Go/C usage through examples.

## Technical reference

- [SPEC-001](docs/specs/SPEC-001-identifiers.md): identifier requirements.
- [SPEC-001A](docs/specs/SPEC-001A-identifier-model.md): model, scope, timestamps, ownership.
- [SPEC-001B](docs/specs/SPEC-001B-normalization.md): formats, normalization, equality.
- [SPEC-002](docs/specs/SPEC-002-reconciliation.md): reconciliation and C compatibility.

## License

Copyright (C) 2026 Greenbone AG.

Licensed under the GNU Affero General Public License v3.0 only (`AGPL-3.0-only`). See [LICENSE](LICENSE) for the full
license text.
