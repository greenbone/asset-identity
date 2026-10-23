# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-only

FROM golang:1.27-trixie AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libglib2.0-dev \
    make \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . /source
WORKDIR /source

RUN make install PREFIX=/usr/local DESTDIR=/install

FROM busybox:stable

COPY --from=builder /install/ /install/
