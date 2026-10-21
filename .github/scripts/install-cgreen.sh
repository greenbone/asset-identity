#!/bin/sh
# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

# Cgreen 1.6.4 includes CGREEN_NO_FORK, required when testing the Go shared library.
commit=91ba387904d7f43c6564486690386e76d4f8bc76
source_dir="$RUNNER_TEMP/cgreen-source"
prefix="$RUNNER_TEMP/cgreen"
mkdir -p "$source_dir"
curl --fail --show-error --silent --location \
    "https://github.com/cgreen-devs/cgreen/archive/$commit.tar.gz" \
    -o "$RUNNER_TEMP/cgreen.tar.gz"
tar -xzf "$RUNNER_TEMP/cgreen.tar.gz" --strip-components=1 -C "$source_dir"
cmake -S "$source_dir" -B "$source_dir/build" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCGREEN_WITH_UNIT_TESTS=OFF -DCGREEN_WITH_LIBXML2=OFF
cmake --build "$source_dir/build" --parallel 2
cmake --install "$source_dir/build"
printf 'CMAKE_ARGS=-DCMAKE_PREFIX_PATH=%s\n' "$prefix" >> "$GITHUB_ENV"
