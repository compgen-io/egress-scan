# Devcontainer for egress-scan — Debian 13 (trixie) with Go and the Tesseract
# toolchain, so `make build-ocr` / `make test-ocr` build the cgo OCR binary with
# no path juggling (apt installs headers at standard locations).
FROM debian:13

ARG GO_VERSION=1.25.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git make pkg-config build-essential \
        tesseract-ocr tesseract-ocr-eng \
        libtesseract-dev libleptonica-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go from the official tarball (Debian's may lag the required version).
RUN ARCH="$(dpkg --print-architecture)" \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV CGO_ENABLED=1

WORKDIR /workspace
