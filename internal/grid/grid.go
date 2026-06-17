// Package grid computes the area (rows x cols) of tabular/array data and the
// associated 0-1 "data volume" risk. A large grid in an egress artifact suggests
// a raw data dump (or a re-encoding of the input) rather than the small aggregate
// results expected for release.
package grid

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// RiskFullArea is the area at or above which data-volume risk is 1.0.
const RiskFullArea = 200

// Risk maps a total grid area to a 0-1 risk, linearly: area/200, capped at 1.
// (area 100 -> 0.5, area >= 200 -> 1.0.)
func Risk(totalArea int) float64 {
	if totalArea <= 0 {
		return 0
	}
	r := float64(totalArea) / float64(RiskFullArea)
	if r > 1 {
		return 1
	}
	return r
}

// DelimitedArea counts rows and columns of a CSV/TSV byte stream. cols is taken
// from the widest record (headers and ragged rows tolerated); rows is the record
// count. Returns ok=false if nothing parseable was found.
func DelimitedArea(data []byte, comma rune) (rows, cols int, ok bool) {
	rd := csv.NewReader(bytes.NewReader(data))
	rd.Comma = comma
	rd.FieldsPerRecord = -1
	rd.LazyQuotes = true
	rd.ReuseRecord = true
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed lines but keep counting what we can.
			continue
		}
		rows++
		if len(rec) > cols {
			cols = len(rec)
		}
	}
	return rows, cols, rows > 0 && cols > 0
}

var dimensionRe = regexp.MustCompile(`<dimension[^>]*\bref="([^"]+)"`)
var rowTagRe = regexp.MustCompile(`<row\b`)

// XlsxSheetArea returns the used area of one xlsx worksheet XML part. It reads
// the <dimension ref="A1:H50"> range when present, else falls back to counting
// <row> elements (cols unknown -> 1).
func XlsxSheetArea(sheetXML []byte) (rows, cols int) {
	if m := dimensionRe.FindSubmatch(sheetXML); m != nil {
		ref := string(m[1])
		if i := strings.IndexByte(ref, ':'); i >= 0 {
			c1, r1, ok1 := parseCellRef(ref[:i])
			c2, r2, ok2 := parseCellRef(ref[i+1:])
			if ok1 && ok2 {
				return abs(r2-r1) + 1, abs(c2-c1) + 1
			}
		} else if _, r, ok := parseCellRef(ref); ok {
			return r, 1
		}
	}
	return len(rowTagRe.FindAll(sheetXML, -1)), 1
}

// parseCellRef converts an A1-style cell ref to (col, row), both 1-based.
func parseCellRef(ref string) (col, row int, ok bool) {
	ref = strings.TrimSpace(ref)
	i := 0
	for i < len(ref) && ref[i] >= 'A' && ref[i] <= 'Z' {
		col = col*26 + int(ref[i]-'A'+1)
		i++
	}
	if i == 0 || i == len(ref) {
		return 0, 0, false
	}
	r, err := strconv.Atoi(ref[i:])
	if err != nil {
		return 0, 0, false
	}
	return col, r, true
}

var npyShapeRe = regexp.MustCompile(`'shape'\s*:\s*\(([^)]*)\)`)

// NpyShape parses the shape from a .npy header without a NumPy dependency.
// Returns the dimension sizes (e.g. [100, 50]) or ok=false.
func NpyShape(data []byte) (dims []int, ok bool) {
	if len(data) < 10 || !bytes.Equal(data[:6], []byte("\x93NUMPY")) {
		return nil, false
	}
	major := data[6]
	var headerLen, headerStart int
	if major == 1 {
		if len(data) < 10 {
			return nil, false
		}
		headerLen = int(binary.LittleEndian.Uint16(data[8:10]))
		headerStart = 10
	} else {
		if len(data) < 12 {
			return nil, false
		}
		headerLen = int(binary.LittleEndian.Uint32(data[8:12]))
		headerStart = 12
	}
	if headerStart+headerLen > len(data) {
		return nil, false
	}
	header := string(data[headerStart : headerStart+headerLen])

	m := npyShapeRe.FindStringSubmatch(header)
	if m == nil {
		return nil, false
	}
	for _, part := range strings.Split(m[1], ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		dims = append(dims, n)
	}
	return dims, len(dims) > 0
}

// AreaOfDims returns rows, cols, area for a shape: rows = first dim, cols =
// product of the rest (1 for a 1-D shape).
func AreaOfDims(dims []int) (rows, cols, area int) {
	if len(dims) == 0 {
		return 0, 0, 0
	}
	rows = dims[0]
	cols = 1
	for _, d := range dims[1:] {
		cols *= d
	}
	return rows, cols, rows * cols
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
