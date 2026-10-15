#!/bin/sh
set -eu
stage=$(mktemp -d "${TMPDIR:-/tmp}/gvm-asset-identity-install.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
make install DESTDIR="$stage" PREFIX="$PREFIX" LIBDIR="$LIBDIR" INCLUDEDIR="$INCLUDEDIR"
lib="$stage$LIBDIR"
include="$stage$INCLUDEDIR"
pc="$lib/pkgconfig/libgvm_asset_identity.pc"
test -f "$lib/libgvm_asset_identity.so.1.0.0"
test "$(readlink "$lib/libgvm_asset_identity.so")" = libgvm_asset_identity.so.1
test "$(readlink "$lib/libgvm_asset_identity.so.1")" = libgvm_asset_identity.so.1.0.0
cmp include/gvm_asset_identity.h "$include/gvm_asset_identity.h"
test -f "$pc"
if grep -F "$stage" "$pc"; then exit 1; fi
original_pkg_config_path=${PKG_CONFIG_PATH:-}
export PKG_CONFIG_PATH="$lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
flags=$(PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --cflags --libs libgvm_asset_identity)
printf '%s\n' "$flags" | grep -F -- "-I$INCLUDEDIR"
printf '%s\n' "$flags" | grep -F -- "-L$LIBDIR"
cp tests/c/consumer.c "$stage/consumer.c"
export PKG_CONFIG_PATH="$original_pkg_config_path"
${CMAKE:-cmake} -S tests/c -B "$stage/tests" -DCMAKE_C_COMPILER="${CC:-cc}" \
    -DIDENTITY_LIBDIR="$lib" -DIDENTITY_INCLUDEDIR="$include" \
    -DIDENTITY_CONSUMER_SOURCE="$stage/consumer.c" ${CMAKE_ARGS:-}
${CMAKE:-cmake} --build "$stage/tests"
${CTEST:-ctest} --test-dir "$stage/tests" --output-on-failure
printf 'unrelated\n' > "$lib/unrelated-file"
make uninstall DESTDIR="$stage" PREFIX="$PREFIX" LIBDIR="$LIBDIR" INCLUDEDIR="$INCLUDEDIR"
test -f "$lib/unrelated-file"
test ! -e "$lib/libgvm_asset_identity.so.1.0.0"
test ! -L "$lib/libgvm_asset_identity.so"
test ! -L "$lib/libgvm_asset_identity.so.1"
test ! -e "$include/gvm_asset_identity.h"
test ! -e "$pc"
printf 'Staged installation, C consumer, Cgreen suites and scoped uninstall passed.\n'
