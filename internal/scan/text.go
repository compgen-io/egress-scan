package scan

import (
	"path"
	"strings"
	"unicode/utf8"
)

// scanText decodes bytes as UTF-8 (lossy) and regex-scans for IB-IDs and PHI.
func (s *Scanner) scanText(name string, data []byte, format string, res *Result) {
	text := string(data)
	for id := range s.cfg.Matcher.IBIDs(text) {
		res.record(name, id, format, "regex")
	}
	res.PHIMatches += s.cfg.Matcher.PHICount(text)
	res.Stats.Scanned++
}

// scanRaw regex-scans raw bytes for literal ASCII IB-IDs. This is the universal
// fallback: it catches IDs in any uncompressed binary without a parser. It does
// not run the PHI patterns, which are too noisy against binary data.
func (s *Scanner) scanRaw(name string, data []byte, format string, res *Result) {
	for id := range s.cfg.Matcher.IBIDs(string(data)) {
		res.record(name, id, format, "regex")
	}
	res.Stats.Scanned++
}

// scanRDS handles .rds/.RData. R stores every CHARSXP string inline as raw bytes;
// the only encoding is the outer gzip/bzip2/xz wrapper. Decompressing and raw-
// scanning therefore catches IDs in every string variable, factor level, and
// name/key without needing a full (and fragile) R deserialiser. Numeric data is
// stored as binary doubles and cannot hold an "IB"-prefixed ID.
func (s *Scanner) scanRDS(name string, data []byte, res *Result) {
	decoded := decompressByMagic(data, s.cfg.MaxBytes)
	s.scanRaw(name, decoded, "rds", res)
}

// ---------------------------------------------------------------------------
// Extension classification
// ---------------------------------------------------------------------------

var textExts = map[string]struct{}{
	".csv": {}, ".tsv": {}, ".txt": {}, ".json": {}, ".ipynb": {}, ".jsonl": {},
	".html": {}, ".htm": {}, ".xml": {}, ".svg": {}, ".md": {}, ".rst": {},
	".yaml": {}, ".yml": {}, ".toml": {}, ".ini": {}, ".cfg": {}, ".log": {},
	".tex": {}, ".sql": {}, ".tab": {}, ".rtf": {},
	".py": {}, ".r": {}, ".rmd": {}, ".sh": {}, ".pl": {}, ".js": {}, ".do": {},
}

var officeExts = map[string]struct{}{
	".xlsx": {}, ".xlsm": {}, ".docx": {}, ".pptx": {},
	".ods": {}, ".odt": {}, ".odp": {},
}

var imageExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".tif": {}, ".tiff": {},
	".bmp": {}, ".gif": {}, ".webp": {},
}

// Heavy/opaque binaries we deliberately do not parse; flagged for manual review.
var unsupportedBinaryExts = map[string]struct{}{
	".h5": {}, ".hdf5": {}, ".mat": {}, ".npy": {}, ".npz": {}, ".pkl": {},
	".pickle": {}, ".xls": {}, ".doc": {}, ".ppt": {}, ".duckdb": {},
	".7z": {}, ".rar": {}, ".feather": {}, ".sav": {}, ".dta": {},
}

func isTextExt(ext string) bool              { _, ok := textExts[ext]; return ok }
func isOfficeExt(ext string) bool            { _, ok := officeExts[ext]; return ok }
func isImageExt(ext string) bool             { _, ok := imageExts[ext]; return ok }
func isUnsupportedBinaryExt(ext string) bool { _, ok := unsupportedBinaryExts[ext]; return ok }

// formatFor returns a short format label derived from the extension.
func formatFor(name string) string {
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))
	if ext == "" {
		return "unknown"
	}
	return ext
}

// isMacMetadata reports whether a name is a macOS sidecar (AppleDouble resource
// fork or .DS_Store) that carries no real content and should be skipped.
func isMacMetadata(name string) bool {
	base := name
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	return strings.HasPrefix(base, "._") || base == ".DS_Store" ||
		strings.HasPrefix(name, "__MACOSX/")
}

// looksUTF8Text heuristically decides whether unknown bytes are text: valid
// UTF-8 with no NUL bytes in the sampled prefix.
func looksUTF8Text(data []byte) bool {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if !utf8.Valid(sample) {
		return false
	}
	for _, b := range sample {
		if b == 0 {
			return false
		}
	}
	return true
}
