# Asset identity

A Go library for identifier normalization and strong-first asset reconciliation.
`libgvm_asset_identity.so` exposes the same algorithm through a GLib C API (ABI 1).
Applications supply eligible identifiers and candidates; they own scanner boundaries,
authorization, persistence, and merge approval.

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

Pass caller-prepared active views; normalization does not establish producer trust.
Identifier scopes remain significant, including absent versus explicitly empty scope.

| Action | Meaning |
| --- | --- |
| CREATE | A new key is required. |
| REUSE | Use the selected existing key. |
| REVIEW | Non-actionable survivor/new-key proposal with potential merge targets. |
| CONFLICT | Contradictory incoming strong values; no actionable key plan. |

No result authorizes a database merge. Candidate indices refer to the supplied array.

## C build, test, and install

Linux builds require Go matching [go.mod](go.mod), a C compiler, pkg-config, and GLib
development headers. C tests also require CMake 3.18+ and Cgreen 1.7+.

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

Constructors return owned objects; parents own their children. `decide` borrows
immutable inputs and returns an independently owned decision. Free functions accept
NULL; errors use `GError`. Consumers need only the installed header/library and GLib.
See the [public header](include/gvm_asset_identity.h) and
[C contract](docs/specs/SPEC-002-reconciliation.md#32-c-adapter-contract) for details.

## Technical reference

- [SPEC-001](docs/specs/SPEC-001-identifiers.md): identifier requirements.
- [SPEC-001A](docs/specs/SPEC-001A-identifier-model.md): model, scope, timestamps, ownership.
- [SPEC-001B](docs/specs/SPEC-001B-normalization.md): formats, normalization, equality.
- [SPEC-002](docs/specs/SPEC-002-reconciliation.md): reconciliation and C compatibility.
