// Package rdata extracts grid dimensions (rows x cols) from R serialization
// (.rds and .RData) without any R/Python dependency.
//
// It is a deliberately partial R deserialiser: it walks the SEXP tree only far
// enough to recover, for each top-level object, a data-frame's row/column count
// (from its "row.names"/"names" attributes) or a matrix/array's "dim" attribute.
// Anything it cannot interpret degrades to "not a grid" rather than failing the
// whole scan. It handles ALTREP nodes (e.g. compact_intseq columns) by consuming
// them structurally.
package rdata

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// SEXP type tags (subset) from R's serialize.c / Rinternals.h.
const (
	nilSxp   = 0
	symSxp   = 1
	listSxp  = 2
	langSxp  = 6
	charSxp  = 9
	lglSxp   = 10
	intSxp   = 13
	realSxp  = 14
	cplxSxp  = 15
	strSxp   = 16
	vecSxp   = 19
	exprSxp  = 20
	rawSxp   = 24
	altrep   = 238
	refSxp   = 255
	nilValue = 254
	naInt    = -2147483648
)

// Grid is one rectangular data object found in an R file.
type Grid struct {
	Rows int
	Cols int
}

// Area returns Rows*Cols.
func (g Grid) Area() int { return g.Rows * g.Cols }

// Grids decodes raw .rds/.RData bytes and returns the grid dimensions of every
// top-level data frame / matrix / array it can interpret.
func Grids(raw []byte, maxBytes int64) ([]Grid, error) {
	decoded, isRData := Decode(raw, maxBytes)
	r := &reader{b: decoded}
	if err := r.header(); err != nil {
		return nil, err
	}

	var grids []Grid
	if isRData {
		// Top object is a pairlist of name -> value; grid each value.
		for {
			flags := r.i32()
			if r.err != nil {
				break
			}
			if flags&0xff != listSxp {
				break // NILVALUE terminates the pairlist
			}
			hasAttr := (flags>>9)&1 == 1
			hasTag := (flags>>10)&1 == 1
			if hasAttr {
				r.item()
			}
			if hasTag {
				r.item() // variable name symbol
			}
			n := r.item() // the value
			if g, ok := n.grid(); ok {
				grids = append(grids, g)
			}
		}
	} else {
		if g, ok := r.item().grid(); ok {
			grids = append(grids, g)
		}
	}
	if r.err != nil && len(grids) == 0 {
		return nil, r.err
	}
	return grids, nil
}

// Decode strips an optional outer compression layer and the RData "RDXn\n"
// magic, returning the bare serialization stream and whether it was an .RData
// (multi-object) file.
func Decode(raw []byte, maxBytes int64) (decoded []byte, isRData bool) {
	decoded = sniffDecompress(raw, maxBytes)
	for _, m := range []string{"RDX3\n", "RDX2\n", "RDXs\n"} {
		if bytes.HasPrefix(decoded, []byte(m)) {
			return decoded[len(m):], true
		}
	}
	return decoded, false
}

// node is the partial result of consuming one SEXP.
type node struct {
	typ      int
	vlen     int   // vector/list length
	dim      []int // "dim" attribute, if any
	rowNames int   // nrow derived from "row.names", if any
	namesLen int   // length of "names" attribute, if any
}

// grid decides whether a node is a rectangular grid and returns its dims.
func (n node) grid() (Grid, bool) {
	if len(n.dim) >= 2 { // matrix / array
		rows := n.dim[0]
		cols := 1
		for _, d := range n.dim[1:] {
			cols *= d
		}
		if rows > 0 && cols > 0 {
			return Grid{Rows: rows, Cols: cols}, true
		}
	}
	if n.typ == vecSxp && n.rowNames > 0 { // data.frame
		cols := n.namesLen
		if cols == 0 {
			cols = n.vlen
		}
		if cols > 0 {
			return Grid{Rows: n.rowNames, Cols: cols}, true
		}
	}
	return Grid{}, false
}

type reader struct {
	b       []byte
	p       int
	sym     []string
	lastSym string
	err     error
}

func (r *reader) header() error {
	if len(r.b) < 2 || r.b[0] != 'X' || r.b[1] != '\n' {
		return errors.New("unsupported RDS format (not XDR)")
	}
	r.p = 2
	version := r.i32()
	r.i32() // writer version
	r.i32() // min reader version
	if version >= 3 {
		// Version 3 carries a native-encoding string (length-prefixed).
		r.skip(int(r.i32()))
	}
	return r.err
}

func (r *reader) i32() int32 {
	if r.err != nil || r.p+4 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := int32(binary.BigEndian.Uint32(r.b[r.p:]))
	r.p += 4
	return v
}

func (r *reader) vecLen() int {
	v := r.i32()
	if v == -1 { // long vector: 64-bit length in two ints
		hi := r.i32()
		lo := r.i32()
		return int(hi)<<32 | int(uint32(lo))
	}
	return int(v)
}

func (r *reader) skip(n int) {
	if r.err != nil {
		return
	}
	if n < 0 || r.p+n > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return
	}
	r.p += n
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || r.p+n > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	b := r.b[r.p : r.p+n]
	r.p += n
	return b
}

// item consumes one SEXP fully and returns a partial node describing it.
func (r *reader) item() node {
	flags := r.i32()
	if r.err != nil {
		return node{}
	}
	typ := int(flags & 0xff)
	hasAttr := (flags>>9)&1 == 1

	switch typ {
	case nilValue, nilSxp, 253, 252, 251, 250, 242, 241:
		return node{typ: typ}

	case refSxp:
		if flags>>8 == 0 {
			r.i32()
		}
		return node{typ: typ}

	case symSxp:
		c := r.item() // printname CHARSXP; lastSym set there
		r.sym = append(r.sym, r.lastSym)
		_ = c
		return node{typ: typ}

	case charSxp:
		n := int(r.i32())
		if n >= 0 {
			r.lastSym = string(r.take(n))
		} else {
			r.lastSym = ""
		}
		return node{typ: typ, vlen: max0(n)}

	case listSxp, langSxp:
		if (flags>>9)&1 == 1 {
			r.item() // attributes
		}
		if (flags>>10)&1 == 1 {
			r.item() // tag
		}
		r.item() // CAR
		r.item() // CDR
		return node{typ: typ}

	case intSxp, lglSxp:
		n := r.vecLen()
		r.skip(4 * n)
		nd := node{typ: typ, vlen: n}
		if hasAttr {
			r.attrs(&nd)
		}
		return nd

	case realSxp:
		n := r.vecLen()
		r.skip(8 * n)
		nd := node{typ: typ, vlen: n}
		if hasAttr {
			r.attrs(&nd)
		}
		return nd

	case cplxSxp:
		n := r.vecLen()
		r.skip(16 * n)
		nd := node{typ: typ, vlen: n}
		if hasAttr {
			r.attrs(&nd)
		}
		return nd

	case rawSxp:
		n := r.vecLen()
		r.skip(n)
		nd := node{typ: typ, vlen: n}
		if hasAttr {
			r.attrs(&nd)
		}
		return nd

	case strSxp:
		n := r.vecLen()
		for i := 0; i < n && r.err == nil; i++ {
			r.item()
		}
		nd := node{typ: typ, vlen: n}
		if hasAttr {
			r.attrs(&nd)
		}
		return nd

	case vecSxp, exprSxp:
		n := r.vecLen()
		for i := 0; i < n && r.err == nil; i++ {
			r.item()
		}
		nd := node{typ: typ, vlen: n}
		if hasAttr {
			r.attrs(&nd)
		}
		return nd

	case altrep:
		r.item() // class (pairlist)
		r.item() // state
		r.item() // attributes
		return node{typ: typ}

	default:
		r.err = errors.New("unsupported SEXP type")
		return node{typ: typ}
	}
}

// attrs reads a node's attribute pairlist, capturing dim / row.names / names.
func (r *reader) attrs(nd *node) {
	for r.err == nil {
		flags := r.i32()
		if int(flags&0xff) != listSxp {
			return // NILVALUE terminates
		}
		if (flags>>9)&1 == 1 {
			r.item() // attrs of this cons (rare)
		}
		tag := ""
		if (flags>>10)&1 == 1 {
			r.item() // tag symbol -> lastSym
			tag = r.lastSym
		}
		switch tag {
		case "dim":
			nd.dim = r.intVectorValue()
		case "row.names":
			nd.rowNames = r.rowNamesValue()
		case "names":
			nd.namesLen = r.strLenValue()
		default:
			r.item() // skip value
		}
	}
}

// intVectorValue reads an INTSXP value and returns its elements.
func (r *reader) intVectorValue() []int {
	flags := r.i32()
	if int(flags&0xff) != intSxp {
		return nil
	}
	n := r.vecLen()
	out := make([]int, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, int(r.i32()))
	}
	if (flags>>9)&1 == 1 {
		var skip node
		r.attrs(&skip)
	}
	return out
}

// rowNamesValue interprets a "row.names" attribute into a row count.
func (r *reader) rowNamesValue() int {
	flags := r.i32()
	typ := int(flags & 0xff)
	switch typ {
	case intSxp:
		n := r.vecLen()
		vals := make([]int, 0, n)
		for i := 0; i < n && r.err == nil; i++ {
			vals = append(vals, int(r.i32()))
		}
		if (flags>>9)&1 == 1 {
			var skip node
			r.attrs(&skip)
		}
		// Compact form c(NA, -nrow) used for default integer row names.
		if len(vals) == 2 && vals[0] == naInt {
			if vals[1] < 0 {
				return -vals[1]
			}
		}
		return len(vals)
	case strSxp:
		n := r.vecLen()
		for i := 0; i < n && r.err == nil; i++ {
			r.item()
		}
		return n
	default:
		return 0
	}
}

// strLenValue reads a STRSXP value and returns its length (skipping contents).
func (r *reader) strLenValue() int {
	flags := r.i32()
	if int(flags&0xff) != strSxp {
		return 0
	}
	n := r.vecLen()
	for i := 0; i < n && r.err == nil; i++ {
		r.item()
	}
	return n
}

func sniffDecompress(data []byte, max int64) []byte {
	switch {
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		if zr, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
			defer zr.Close()
			if out, ok := readBounded(zr, max); ok {
				return out
			}
		}
	case len(data) >= 3 && string(data[:3]) == "BZh":
		if out, ok := readBounded(bzip2.NewReader(bytes.NewReader(data)), max); ok {
			return out
		}
	case len(data) >= 6 && bytes.Equal(data[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		if zr, err := xz.NewReader(bytes.NewReader(data)); err == nil {
			if out, ok := readBounded(zr, max); ok {
				return out
			}
		}
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}):
		if zr, err := zstd.NewReader(bytes.NewReader(data)); err == nil {
			defer zr.Close()
			if out, ok := readBounded(zr, max); ok {
				return out
			}
		}
	}
	return data
}

func readBounded(r io.Reader, max int64) ([]byte, bool) {
	if max <= 0 {
		max = 100 * 1024 * 1024
	}
	out, err := io.ReadAll(io.LimitReader(r, max))
	if err != nil {
		return nil, false
	}
	return out, true
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
