# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-only

PREFIX ?= /opt/gvm
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
DESTDIR ?=
GO ?= go
GOLANGCI_LINT ?= golangci-lint
CLANG_FORMAT ?= clang-format
GERSEMI ?= gersemi
GOARCH ?= $(shell $(GO) env GOARCH)
CC ?= cc
CMAKE ?= cmake
CTEST ?= ctest
CMAKE_ARGS ?=
DIST := $(CURDIR)/dist
# Use the nearest release tag;
VERSION ?= $(patsubst v%,%,$(shell git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || echo v0.0.1))
LIBRARY := libgvm_asset_identity.so
LIBRARY_FILE := $(LIBRARY).$(VERSION)-$(GOARCH)
C_SOURCES := $(wildcard capi/*.c capi/*.h include/*.h tests/c/*.c tests/c/*.h)
CMAKE_SOURCES := tests/c/CMakeLists.txt

.PHONY: build format format-go format-c format-cmake format-check-c format-check-cmake lint test cover test-c test-install install uninstall clean

build:
	mkdir -p "$(DIST)/include" "$(DIST)/internal"
	CGO_ENABLED=1 GOOS=linux GOARCH=$(GOARCH) CC="$(CC)" $(GO) build -buildmode=c-shared -ldflags '-extldflags "-Wl,-soname,$(LIBRARY).1 -Wl,--version-script=$(CURDIR)/capi/exports.map"' -o "$(DIST)/internal/$(LIBRARY_FILE)" ./capi
	cp "$(DIST)/internal/$(LIBRARY_FILE)" "$(DIST)/$(LIBRARY_FILE)"
	ln -sfn "$(LIBRARY_FILE)" "$(DIST)/$(LIBRARY).1"
	ln -sfn "$(LIBRARY).1" "$(DIST)/$(LIBRARY)"
	cp include/gvm_asset_identity.h "$(DIST)/include/"

format: format-go format-c format-cmake

format-go:
	$(GOLANGCI_LINT) fmt

format-c:
	$(CLANG_FORMAT) -i -style=file $(C_SOURCES)

format-cmake:
	$(GERSEMI) --in-place $(CMAKE_SOURCES)

format-check-c:
	$(CLANG_FORMAT) --dry-run --Werror -style=file $(C_SOURCES)

format-check-cmake:
	$(GERSEMI) --check $(CMAKE_SOURCES)

lint:
	$(GOLANGCI_LINT) run ./...

test:
	$(GO) test ./...
	$(MAKE) test-c

cover:
	$(GO) test -race -covermode=atomic -coverprofile=coverage.out ./identity/...
	$(GO) tool cover -func=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html

test-c: build
	$(CMAKE) -S tests/c -B build/c -DCMAKE_C_COMPILER="$(CC)" -DIDENTITY_ROOT="$(DIST)" $(CMAKE_ARGS)
	$(CMAKE) --build build/c
	$(CTEST) --test-dir build/c --output-on-failure

test-install: build
	VERSION="$(VERSION)" GOARCH="$(GOARCH)" PREFIX="$(PREFIX)" LIBDIR="$(LIBDIR)" INCLUDEDIR="$(INCLUDEDIR)" CC="$(CC)" CMAKE="$(CMAKE)" CTEST="$(CTEST)" CMAKE_ARGS='$(CMAKE_ARGS)' sh tests/c/test_install.sh

install: build
	install -d "$(DESTDIR)$(LIBDIR)/pkgconfig" "$(DESTDIR)$(INCLUDEDIR)"
	install -m 755 "$(DIST)/$(LIBRARY_FILE)" "$(DESTDIR)$(LIBDIR)/$(LIBRARY_FILE)"
	ln -sfn "$(LIBRARY_FILE)" "$(DESTDIR)$(LIBDIR)/$(LIBRARY).1"
	ln -sfn "$(LIBRARY).1" "$(DESTDIR)$(LIBDIR)/$(LIBRARY)"
	install -m 644 include/gvm_asset_identity.h "$(DESTDIR)$(INCLUDEDIR)/gvm_asset_identity.h"
	sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@LIBDIR@|$(LIBDIR)|g' -e 's|@INCLUDEDIR@|$(INCLUDEDIR)|g' -e 's|@VERSION@|$(VERSION)|g' libgvm_asset_identity.pc.in > "$(DIST)/libgvm_asset_identity.pc"
	install -m 644 "$(DIST)/libgvm_asset_identity.pc" "$(DESTDIR)$(LIBDIR)/pkgconfig/libgvm_asset_identity.pc"

uninstall:
	$(RM) "$(DESTDIR)$(LIBDIR)/$(LIBRARY)" \
		"$(DESTDIR)$(LIBDIR)/$(LIBRARY).1" \
		"$(DESTDIR)$(LIBDIR)/$(LIBRARY_FILE)" \
		"$(DESTDIR)$(LIBDIR)/pkgconfig/libgvm_asset_identity.pc" \
		"$(DESTDIR)$(INCLUDEDIR)/gvm_asset_identity.h"

clean:
	$(RM) -r dist build
