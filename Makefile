# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-only

PREFIX ?= /opt/gvm
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
DESTDIR ?=
GO ?= go
GOLANGCI_LINT ?= golangci-lint
GOARCH ?= $(shell $(GO) env GOARCH)
CC ?= cc
CMAKE ?= cmake
CTEST ?= ctest
CMAKE_ARGS ?=
DIST := $(CURDIR)/dist
VERSION ?= 1.0.0
LIBRARY := libgvm_asset_identity.so
LIBRARY_FILE := $(LIBRARY).$(VERSION)-$(GOARCH)

.PHONY: build format lint test test-c test-install install uninstall clean

build:
	mkdir -p "$(DIST)/include" "$(DIST)/internal"
	CGO_ENABLED=1 GOOS=linux GOARCH=$(GOARCH) CC="$(CC)" $(GO) build -buildmode=c-shared -ldflags '-extldflags "-Wl,-soname,$(LIBRARY).1 -Wl,--version-script=$(CURDIR)/capi/exports.map"' -o "$(DIST)/internal/$(LIBRARY_FILE)" ./capi
	cp "$(DIST)/internal/$(LIBRARY_FILE)" "$(DIST)/$(LIBRARY_FILE)"
	ln -sfn "$(LIBRARY_FILE)" "$(DIST)/$(LIBRARY).1"
	ln -sfn "$(LIBRARY).1" "$(DIST)/$(LIBRARY)"
	cp include/gvm_asset_identity.h "$(DIST)/include/"

format:
	$(GOLANGCI_LINT) fmt

lint:
	$(GOLANGCI_LINT) run ./...

test:
	$(GO) test ./...
	$(MAKE) test-c

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
