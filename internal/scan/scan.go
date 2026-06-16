// Package scan walks a tar archive and looks for IB-ID leaks inside each member,
// recursing into nested archives and parsing structured formats (Office/OpenDocument,
// SQLite, Parquet, PDF, RDS/RData) plus a raw-bytes fallback for everything else.
package scan

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/compgen-io/egress-scan/internal/idmatch"
)

// Finding is a single IB-ID located in a file.
type Finding struct {
	Path   string `json:"path"`   // logical path, e.g. "data/sub.zip!inner.csv"
	ID     string `json:"id"`     // normalised IB-ID
	Format string `json:"format"` // csv, xlsx, sqlite, parquet, pdf, rds, raw, ...
	Via    string `json:"via"`    // regex | structured | ocr
}

// Unscanned records a file that could not be scanned and needs manual review.
type Unscanned struct {
	Path   string `json:"path"`
	Format string `json:"format"`
	Reason string `json:"reason"`
}

// Stats are coarse counters for the run.
type Stats struct {
	Entries         int `json:"entries"`
	Scanned         int `json:"scanned"`
	SkippedTooLarge int `json:"skipped_too_large"`
	Errors          int `json:"errors"`
}

// Result accumulates everything found during a scan.
type Result struct {
	EgressIDs  map[string]struct{} // distinct normalised IB-IDs across the whole tar
	PHIMatches int
	Findings   []Finding
	Unscanned  []Unscanned
	Stats      Stats

	seenIDLoc map[string]struct{} // dedupe findings by path|id
}

// Config controls a Scanner.
type Config struct {
	Matcher  *idmatch.Matcher
	MaxBytes int64 // per-file size cap; larger files are flagged, not read
	MaxDepth int   // archive recursion guard against zip bombs
	OCR      bool  // attempt OCR on images (requires the ocr build tag)
}

// Scanner runs scans with a fixed configuration.
type Scanner struct {
	cfg Config
}

// New returns a Scanner with sensible defaults applied.
func New(cfg Config) *Scanner {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 100 * 1024 * 1024
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 12
	}
	return &Scanner{cfg: cfg}
}

// OCRRequestedButUnavailable reports a config asking for OCR on a binary built
// without the ocr tag, so the caller can warn.
func (s *Scanner) OCRRequestedButUnavailable() bool {
	return s.cfg.OCR && !ocrAvailable()
}

func newResult() *Result {
	return &Result{
		EgressIDs: make(map[string]struct{}),
		seenIDLoc: make(map[string]struct{}),
	}
}

// ScanTarFile streams the top-level tar from disk and scans every member.
func (s *Scanner) ScanTarFile(tarPath string) (*Result, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := newResult()
	if err := s.scanTarStream(f, "", res); err != nil {
		return nil, err
	}
	return res, nil
}

// ScanTarReader scans a tar stream from any reader (e.g. in-memory bytes).
func (s *Scanner) ScanTarReader(r io.Reader) (*Result, error) {
	res := newResult()
	if err := s.scanTarStream(r, "", res); err != nil {
		return nil, err
	}
	return res, nil
}

// scanTarStream iterates a tar reader, dispatching each regular file. prefix is
// the logical path of an enclosing archive (empty for the top level).
func (s *Scanner) scanTarStream(r io.Reader, prefix string, res *Result) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || isMacMetadata(hdr.Name) {
			continue
		}
		name := joinLogical(prefix, hdr.Name)
		res.Stats.Entries++

		if hdr.Size > s.cfg.MaxBytes {
			res.Stats.SkippedTooLarge++
			res.Unscanned = append(res.Unscanned, Unscanned{
				Path: name, Format: formatFor(name),
				Reason: fmt.Sprintf("exceeds max-bytes limit (%d bytes)", hdr.Size),
			})
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, s.cfg.MaxBytes+1))
		if err != nil {
			res.Stats.Errors++
			res.Unscanned = append(res.Unscanned, Unscanned{
				Path: name, Format: formatFor(name), Reason: "read error: " + err.Error(),
			})
			continue
		}
		s.dispatch(name, data, 1, res)
	}
}

// dispatch routes a single in-memory file to the right handler by extension,
// falling back to content sniffing and then a raw-bytes scan.
func (s *Scanner) dispatch(name string, data []byte, depth int, res *Result) {
	if depth > s.cfg.MaxDepth {
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: formatFor(name), Reason: "archive nesting too deep",
		})
		return
	}

	ext := strings.ToLower(path.Ext(name))
	lower := strings.ToLower(name)

	switch {
	// --- nested archives -------------------------------------------------
	case ext == ".tar":
		s.recurseTar(name, data, res)
	case ext == ".zip":
		s.recurseZip(name, data, depth, res)
	case strings.HasSuffix(lower, ".tar.gz") || ext == ".tgz":
		if dec, ok := gunzip(data, s.cfg.MaxBytes); ok {
			s.recurseTar(name, dec, res)
		} else {
			s.markErr(name, res, "gzip decode failed")
		}
	case ext == ".gz" || ext == ".bz2" || ext == ".xz" || ext == ".zst":
		if dec, ok := decompressExt(ext, data, s.cfg.MaxBytes); ok {
			s.dispatch(strings.TrimSuffix(name, ext), dec, depth+1, res)
		} else {
			s.markErr(name, res, "decompression failed")
		}

	// --- structured parsers ----------------------------------------------
	case isOfficeExt(ext):
		s.scanOffice(name, data, ext, res)
	case ext == ".sqlite" || ext == ".sqlite3" || ext == ".db":
		s.scanSQLite(name, data, res)
	case ext == ".parquet":
		s.scanParquet(name, data, res)
	case ext == ".pdf":
		s.scanPDF(name, data, res)
	case ext == ".rds" || ext == ".rdata":
		s.scanRDS(name, data, res)

	// --- text-ish: decode + regex ----------------------------------------
	case isTextExt(ext):
		s.scanText(name, data, formatFor(name), res)

	// --- images: OCR only when enabled -----------------------------------
	case isImageExt(ext):
		s.scanImage(name, data, res)

	// --- hard binaries: flag for manual review (still raw-scan as a net) --
	case isUnsupportedBinaryExt(ext):
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: formatFor(name),
			Reason: "unsupported binary format; manual review required",
		})
		s.scanRaw(name, data, "raw", res) // cheap bonus pass for literal ASCII IDs

	// --- unknown: sniff, else raw-bytes fallback -------------------------
	default:
		if looksUTF8Text(data) {
			s.scanText(name, data, "text", res)
		} else {
			s.scanRaw(name, data, "raw", res)
		}
	}
}

func (s *Scanner) recurseTar(name string, data []byte, res *Result) {
	if err := s.scanTarStream(bytes.NewReader(data), name, res); err != nil {
		s.markErr(name, res, "nested tar: "+err.Error())
	}
}

// record adds an IB-ID finding, deduped by path+id, and tracks the global ID set.
func (r *Result) record(p, id, format, via string) {
	id = idmatch.Normalize(id)
	r.EgressIDs[id] = struct{}{}
	key := p + "|" + id
	if _, ok := r.seenIDLoc[key]; ok {
		return
	}
	r.seenIDLoc[key] = struct{}{}
	r.Findings = append(r.Findings, Finding{Path: p, ID: id, Format: format, Via: via})
}

func (s *Scanner) markErr(name string, res *Result, reason string) {
	res.Stats.Errors++
	res.Unscanned = append(res.Unscanned, Unscanned{
		Path: name, Format: formatFor(name), Reason: reason,
	})
}

// joinLogical builds a readable nested path using "!" to separate archive layers.
func joinLogical(prefix, name string) string {
	name = strings.TrimPrefix(name, "./")
	if prefix == "" {
		return name
	}
	return prefix + "!" + name
}
