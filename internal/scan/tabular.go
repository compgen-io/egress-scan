package scan

import "github.com/compgen-io/egress-scan/internal/grid"

// scanDelimited scans a CSV/TSV file for IB-IDs/PHI and records its grid area.
func (s *Scanner) scanDelimited(name string, data []byte, ext string, res *Result) {
	s.scanText(name, data, formatFor(name), res)

	comma := ','
	if ext == ".tsv" || ext == ".tab" {
		comma = '\t'
	}
	if rows, cols, ok := grid.DelimitedArea(data, comma); ok {
		res.addGrid(name, formatFor(name), rows, cols)
	}
}

// scanNpy records a NumPy array's grid area (from its header) and raw-scans the
// bytes for any literal IB-IDs (string arrays).
func (s *Scanner) scanNpy(name string, data []byte, res *Result) {
	if dims, ok := grid.NpyShape(data); ok {
		rows, cols, _ := grid.AreaOfDims(dims)
		res.addGrid(name, "npy", rows, cols)
	}
	s.scanRaw(name, data, "npy", res)
}
