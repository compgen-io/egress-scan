package scan

import (
	"bytes"
	"io"
	"strings"

	"github.com/parquet-go/parquet-go"
)

// scanParquet reads a Parquet file column-wise and scans string (byte-array)
// values plus column names. A structured read is required because Parquet
// dictionary/compression encoding defeats a raw byte scan.
func (s *Scanner) scanParquet(name string, data []byte, res *Result) {
	f, err := parquet.OpenFile(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		s.markErr(name, res, "parquet open: "+err.Error())
		return
	}

	// Column names can themselves be IB-IDs.
	cols := f.Schema().Columns()
	for _, col := range cols {
		colName := strings.Join(col, ".")
		for id := range s.cfg.Matcher.IBIDs(colName) {
			res.record(name, id, "parquet", "structured")
		}
	}
	// Grid area from cheap file metadata (no full scan needed).
	res.addGrid(name, "parquet", int(f.NumRows()), len(cols))

	buf := make([]parquet.Value, 1024)
	for _, rg := range f.RowGroups() {
		for _, chunk := range rg.ColumnChunks() {
			pages := chunk.Pages()
			for {
				page, err := pages.ReadPage()
				if err != nil {
					break // io.EOF or unreadable page
				}
				vr := page.Values()
				for {
					n, rerr := vr.ReadValues(buf)
					for i := 0; i < n; i++ {
						v := buf[i]
						if v.Kind() == parquet.ByteArray || v.Kind() == parquet.FixedLenByteArray {
							text := string(v.ByteArray())
							for id := range s.cfg.Matcher.IBIDs(text) {
								res.record(name, id, "parquet", "structured")
							}
							res.PHIMatches += s.cfg.Matcher.PHICount(text)
						}
					}
					if rerr == io.EOF {
						break
					}
					if rerr != nil {
						break
					}
				}
			}
			pages.Close()
		}
	}
	res.Stats.Scanned++
}
