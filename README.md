# Asset identity

The Go `identity` package provides normalization and strong-first reconciliation.
`libgvm_asset_identity.so` exposes the same `identity.Decide()` implementation through
ABI 1 of the GLib C API. Applications own candidate filtering, scanner boundaries,
producer eligibility, persistence, and merge authorization.

## Build and test

Linux builds need Go matching `go.mod`, a C compiler, pkg-config, and GLib development
headers. Native tests additionally need CMake 3.18+ and Cgreen 1.7 or later. Cgreen is not
linked into the production library. Install Cgreen from its
[upstream release](https://github.com/cgreen-devs/cgreen/releases/tag/1.7.0) if your
system does not provide it.

```sh
make build
make test
make test-c
make test-install
```

For a Cgreen installation outside standard paths, use
`make test CMAKE_ARGS=-DCMAKE_PREFIX_PATH=/path/to/cgreen` (also for `test-install`).
CMake discovers Cgreen's package configuration or pkg-config metadata. CTest sets
`CGREEN_NO_FORK=1`: forking after initialization of the Go runtime is unsupported.
CTest also clears loader overrides so another installed library cannot replace the
built or staged artifact during tests.

Additional checks:

```sh
go test -race ./...
CGO_ENABLED=0 go test ./...
go vet ./...
go test ./identity -run TestFuzzyKernelCReferenceFixtures -count=1
```

The 78 captured C differential fixtures remain Go regression tests. Native C tests
exercise the actual shared library. No CI workflow is included.

## Install and consume

```sh
make install                     # /opt/gvm; requires directory write access
make install DESTDIR=/tmp/gvm-asset-identity-stage
make install PREFIX=/usr/local LIBDIR=/usr/local/lib INCLUDEDIR=/usr/local/include
```

Install creates the public header, `gvm-asset-identity.pc`, and the verified SONAME
layout `libgvm_asset_identity.so -> .so.1 -> .so.1.0.0`. `DESTDIR` is staging only;
it is never embedded in pkg-config metadata or the shared library. `make uninstall`
accepts the same path overrides and removes only this project's installed files.
`make clean` removes the generated `dist/` and `build/` directories.

```sh
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
cc tests/c/consumer.c $(pkg-config --cflags --libs gvm-asset-identity) \
    -Wl,-rpath,/opt/gvm/lib -o consumer
./consumer
```

Production consumers can set RUNPATH as above or configure the system loader;
`LD_LIBRARY_PATH` is not required. The staged installation test compiles and runs
this consumer outside the repository, runs the Cgreen suites against installed
artifacts, and checks uninstall without touching the real `/opt/gvm`. Only the
installed public header, shared library, and GLib development files are needed;
Go source, cgo-generated headers, and Cgreen are not needed by consumers.

## GLib API and ownership

See [gvm_asset_identity.h](include/gvm_asset_identity.h) and the small
[consumer](tests/c/consumer.c). Constructors create independently owned objects.

- Observation/candidate `identifiers` are `GPtrArray` collections of typed identifiers.
  Insert constructor-created identifiers with `g_ptr_array_add`; the parent owns them.
- Identifier `scope` is an owned string-to-string `GHashTable`. Create it with
  `g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free)` and owned strings.
  NULL means absent; an empty table means explicitly present and empty.
- Candidate arrays are caller-owned. Use `g_ptr_array_new_with_free_func` with
  `gvm_asset_identity_candidate_free` to own the candidates. Empty collections must
  be real GLib arrays, not NULL. Policy arrays use the element types in the header.
- `policy_new_default()` obtains defaults from Go; callers may edit its owned arrays.
  `policy_new()` creates an explicitly empty policy. No defaults are inferred.
- `decide()` borrows inputs without mutation. A successful result and all nested
  strings/containers are independent of inputs; release it with `decision_free()`.
  Other constructors have matching NULL-safe free functions. Do not free borrowed
  child pointers separately. Shared inputs must not be concurrently mutated.
- Errors use `GVM_ASSET_IDENTITY_ERROR` with INVALID_INPUT, INVALID_POLICY, or INTERNAL
  codes. Pass a NULL-initialized `GError *` and release it with `g_clear_error()`.
  An error leaves the decision NULL; output slots must not alias inputs or each other.
- Timestamp `present` distinguishes missing from epoch; seconds are signed Unix
  seconds, and nanoseconds must be 0..999999999. Present instants must be within UTC
  years 1..9999. Absent timestamps have zero-valued seconds/nanoseconds.

CREATE requests a new key; REUSE selects an existing key. CONFLICT supplies evidence
and no actionable key plan. REVIEW preserves a proposed survivor or new-key flag
and informational `GArray` indices/`GPtrArray` keys. **REVIEW authorizes no writes or
merges.** Indices always refer to the candidate array supplied to that call.

Strings are NUL-terminated `gchar` byte strings, not necessarily UTF-8; embedded NUL
bytes are outside this GLib API. No case folding or trimming is added by the adapter.
Inputs are limited to 1,048,576 entries per collection, 16 MiB per string, and 64 MiB
of private wire arrays/string bytes per call; excess input is rejected, not truncated.
Pointers must reference live, correctly aligned objects of the declared types. As
with other C APIs, dangling pointers and fabricated GLib objects cannot be verified.
Go panics become INTERNAL errors; process-fatal runtime failures and GLib allocation
failure retain their normal process behavior. No Go pointer crosses the ABI.

Locally verified: Linux amd64, glibc 2.39, GLib 2.80, Cgreen 1.7. Native arm64 and
other libc combinations have not been tested. Builds target the host by default;
`GOARCH`/`CC` overrides require a matching target C compiler, GLib, and sysroot.
