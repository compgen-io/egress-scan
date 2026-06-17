# egress-scan

Scans an egress **tar artifact** for leaks of internal biobank identifiers
(**IB-IDs**) before release. It runs as a standalone workflow step alongside the
egress worker: point it at the tar, optionally give it the approved-ID set, and
it emits a JSON report with a plain-text recommendation and a 0–100 risk score.

The IB-ID pattern (`\bIB[_-]?\d+\b`), normalisation, PHI patterns, and scoring
model mirror the existing Python worker (`worker.py`, `risk_scoring.py`) so the
output drops into the same review workflow.

## What it scans

| Input | How |
|---|---|
| tar (the artifact), nested `.tar`, `.tar.gz`/`.tgz` | streamed, recursed |
| `.zip` (nested) | unzipped, every member dispatched |
| `.gz` `.bz2` `.xz` `.zst` wrappers | transparently decompressed, then scanned |
| `.csv` `.tsv` `.txt` `.json` `.ipynb` `.svg` `.html` `.xml` code/config | UTF-8 decode + regex |
| `.xlsx` `.xlsm` `.docx` `.pptx` `.ods` `.odt` `.odp` | open as zip, regex the content XML parts |
| `.sqlite` `.db` `.sqlite3` | structured read of every TEXT/BLOB cell + column names |
| `.parquet` | structured read of string columns + column names |
| `.pdf` | text-layer extraction (scanned/image PDFs flagged for review) |
| `.rds` `.RData` | outer compression stripped, then string scan (R stores strings inline) |
| images (`.png` `.jpg` `.tiff` …) | OCR — **only** with `--ocr` on an OCR build |
| any other binary | raw-bytes fallback finds literal ASCII IDs |
| `.h5` `.mat` `.rds`-less `.npy` `.pkl` `.xls` `.doc` `.duckdb` `.7z` `.rar` | flagged **unscanned** for manual review (plus a raw pass) |

Files that cannot be scanned (unsupported binaries, scanned PDFs, oversized
files) are listed in `unscanned` and raise the risk score, so nothing is silently
skipped.

## Usage

```
egress-scan --tar request.tar --approved-ids approved.txt --out report.json
```

Flags:

- `--tar` (required) — the tar artifact to scan.
- `--approved-ids FILE` — text file of approved IB-IDs to compare against.
- `--approved-dir DIR` — directory of approved dataset files to extract IDs from.
  (Or set `APPROVED_IB_IDS=IB-1,IB-2` in the environment.)
- `--approved-s3-bucket` / `--approved-s3-prefix` — scan an approved-datasets S3
  prefix for IDs (off unless a bucket is set; env: `APPROVED_DATASETS_BUCKET`,
  `APPROVED_DATASETS_PREFIX`). Uses the default AWS credential chain. Object-count
  and size caps come from `IB_SCAN_MAX_APPROVED_OBJECTS` / `IB_SCAN_MAX_OBJECT_BYTES`.
  Precedence: `--approved-ids` > `--approved-dir` > S3 > `APPROVED_IB_IDS`.
- `--ib-pattern` — override the IB-ID regex.
- `--max-bytes` — per-file size cap (default 100 MiB); larger files are flagged.
- `--max-depth` — nested-archive recursion guard (default 12).
- `--ocr` — OCR images (needs a binary built with `-tags ocr`).
- `--out` — write JSON here (default stdout); `--pretty` toggles indentation.

**Exit codes:** `0` no novel IB-IDs · `1` novel IB-IDs found · `2` error. The
workflow step can gate on a non-zero exit.

## Output

```json
{
  "recommendation": "Check this file for potential IDs — 7 novel IB-ID(s) ...",
  "risk_score": 71,
  "risk_level": "HIGH",
  "summary": "...",
  "reasons": ["..."],
  "ib_id_scan": { "approved_source": "ids_file", "egress_ib_id_count": 8,
                  "overlap_ib_id_count": 1, "novel_ib_id_count": 7,
                  "novel_ib_ids_sample": ["IB-4321"], "overlap_ib_ids_sample": ["IB-1234"] },
  "findings":  [{ "path": "data/cohort.sqlite", "id": "IB-2099", "format": "sqlite", "via": "structured" }],
  "unscanned": [{ "path": "data/matrix.h5", "format": "h5", "reason": "unsupported binary format; manual review required" }],
  "scan_stats": { "entries": 8, "scanned": 7, "skipped_too_large": 0, "errors": 0 }
}
```

## Builds

- **Default** (`Dockerfile`) — `CGO_ENABLED=0`, pure-Go static binary, no OCR.
  Cross-compiles from any host.
- **OCR** (`Dockerfile.ocr`, `-tags ocr`) — links Tesseract/Leptonica for image
  and scanned-PDF text. cgo, so it builds natively per-arch and needs Tesseract +
  tessdata at runtime.

### Makefile

| Target | Result |
|---|---|
| `make build-linux` | `bin/egress-scan.linux_amd64` — static, no OCR |
| `make build-ocr` | `bin/egress-scan-ocr.linux_amd64` — cgo OCR (build on linux/amd64) |
| `make build` | local dev binary for the host (no OCR) |
| `make docker-ocr` | deployable `linux/amd64` OCR image (`egress-scan:ocr`) |
| `make fixtures` | write the sample tar + approved list + OCR PNG to `testdata/` |
| `make test` / `make test-ocr` | tests without / with the OCR path |
| `make demo` / `make demo-ocr` | build and scan the sample tar |

## Releases

Pushing a `vX.Y.Z` tag triggers `.github/workflows/release.yml`, which runs the
tests (including the OCR path) and publishes a GitHub Release with both
`linux/amd64` binaries attached plus `checksums.txt`:

- `egress-scan.linux_amd64` — static, no OCR
- `egress-scan-ocr.linux_amd64` — OCR build (needs Tesseract at runtime)

```sh
git tag v0.0.1 && git push origin v0.0.1
```

### Devcontainer (for OCR / cgo)

`.devcontainer/` is a Debian 13 image with Go and the Tesseract toolchain, so
cgo builds need no path juggling. Open the folder in a devcontainer (or
`docker build -f .devcontainer/Dockerfile -t egress-scan-dev .`) and run
`make test-ocr` / `make build-ocr` / `make demo-ocr` inside it.

The static no-OCR binary (`make build-linux`) builds fine straight on macOS.

## Tests & fixtures

`internal/fixtures` builds a sample tar in memory exercising every scanner path —
each IB-ID is unique to one file, so a test proving an ID was found also proves
that file's format was parsed. `IB-7788` is rendered **only** into a PNG, so it is
reachable solely via OCR: the non-OCR test asserts it is *not* found and the PNG
is flagged unscanned; the `-tags ocr` test asserts it *is* found.

`make fixtures` writes the same files to `testdata/` (committed) so you can scan
them by hand:

```sh
make build && make fixtures
bin/egress-scan --tar testdata/egress-sample.tar --approved-ids testdata/approved.txt
```

## Wiring into the egress-worker container

Because releases are public, the worker image can pull a pinned binary at build
time — no Go toolchain in the worker image:

```dockerfile
ARG EGRESS_SCAN_VERSION=v0.0.1
RUN curl -fsSL -o /usr/local/bin/egress-scan \
      https://github.com/compgen-io/egress-scan/releases/download/${EGRESS_SCAN_VERSION}/egress-scan.linux_amd64 \
 && chmod +x /usr/local/bin/egress-scan
```

Then, as a workflow step, run it against the built tar before upload and route on
the result, e.g.:

```sh
egress-scan --tar "$TAR" --approved-ids "$APPROVED" --out scan.json || review=required
```
