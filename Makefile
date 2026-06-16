# egress-scan — build, test, and fixtures.
#
# The default (no-OCR) binary is pure-Go and cross-compiles from any host.
# The OCR binary is cgo + Tesseract; build it on Linux (the .devcontainer is set
# up for exactly this — `make build-ocr` / `make test-ocr` just work there).

BIN_DIR    := bin
BINARY     := egress-scan
LINUX_BIN  := $(BIN_DIR)/$(BINARY).linux_amd64
OCR_BIN    := $(BIN_DIR)/$(BINARY)-ocr.linux_amd64
TESTDATA   := testdata
LDFLAGS    := -s -w
GO         := go
OCR_IMAGE  := egress-scan:ocr

.PHONY: all build build-linux build-ocr docker-ocr fixtures test test-ocr demo demo-ocr fmt vet clean

all: build-linux

## build: local dev binary for the host platform (no OCR)
build:
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) .

## build-linux: static linux/amd64 binary, no OCR (the primary release artifact)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(LINUX_BIN) .
	@echo "built $(LINUX_BIN)"

## build-ocr: cgo binary WITH OCR. cgo cannot cross-compile without a cross
## toolchain, so this builds for the build host's arch — run it on linux/amd64
## (the CI runner or the devcontainer on an amd64 host) to get a real amd64
## binary. The output name reflects the intended release target.
build-ocr:
	CGO_ENABLED=1 $(GO) build -tags ocr -trimpath -o $(OCR_BIN) .
	@echo "built $(OCR_BIN)"

## docker-ocr: build the deployable linux/amd64 OCR image (Tesseract at runtime).
docker-ocr:
	docker build --platform linux/amd64 -f Dockerfile.ocr -t $(OCR_IMAGE) .
	@echo "built image $(OCR_IMAGE) (linux/amd64)"

## fixtures: write sample tar + approved list + OCR PNG to testdata/
fixtures:
	$(GO) run ./cmd/gen-fixtures --dir $(TESTDATA)

## test: unit + integration tests (no OCR)
test:
	$(GO) test ./...

## test-ocr: include the OCR path (needs Tesseract + tessdata; use the devcontainer)
test-ocr:
	$(GO) test -tags ocr ./...

## demo: build and scan the sample tar (regenerates fixtures)
demo: build fixtures
	-$(BIN_DIR)/$(BINARY) --tar $(TESTDATA)/egress-sample.tar --approved-ids $(TESTDATA)/approved.txt

## demo-ocr: same, with OCR enabled (devcontainer)
demo-ocr: build-ocr fixtures
	-$(OCR_BIN) --tar $(TESTDATA)/egress-sample.tar --approved-ids $(TESTDATA)/approved.txt --ocr

fmt:
	gofmt -w .

vet:
	$(GO) vet ./...

clean:
	rm -rf $(BIN_DIR) $(TESTDATA)/egress-sample.tar $(TESTDATA)/approved.txt $(TESTDATA)/ocr-sample.png
