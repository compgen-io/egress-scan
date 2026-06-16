package scan

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// boundedReadAll reads up to max bytes (+1 to detect overflow). The second
// return is false if the stream exceeded max.
func boundedReadAll(r io.Reader, max int64) ([]byte, bool) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false
	}
	if int64(len(data)) > max {
		return data[:max], false
	}
	return data, true
}

func gunzip(data []byte, max int64) ([]byte, bool) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	return boundedReadAll(zr, max)
}

// decompressExt decompresses a single-file wrapper by extension.
func decompressExt(ext string, data []byte, max int64) ([]byte, bool) {
	switch ext {
	case ".gz":
		return gunzip(data, max)
	case ".bz2":
		return boundedReadAll(bzip2.NewReader(bytes.NewReader(data)), max)
	case ".xz":
		r, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		return boundedReadAll(r, max)
	case ".zst":
		r, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		defer r.Close()
		return boundedReadAll(r, max)
	}
	return nil, false
}

// decompressByMagic strips a known outer compression layer based on leading
// magic bytes, returning the original data unchanged when none is recognised.
// Used for formats (RDS/RData) where compression is implicit, not in the name.
func decompressByMagic(data []byte, max int64) []byte {
	switch {
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b: // gzip
		if dec, ok := gunzip(data, max); ok {
			return dec
		}
	case len(data) >= 3 && string(data[:3]) == "BZh": // bzip2
		if dec, ok := boundedReadAll(bzip2.NewReader(bytes.NewReader(data)), max); ok {
			return dec
		}
	case len(data) >= 6 && bytes.Equal(data[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}): // xz
		if r, err := xz.NewReader(bytes.NewReader(data)); err == nil {
			if dec, ok := boundedReadAll(r, max); ok {
				return dec
			}
		}
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}): // zstd
		if r, err := zstd.NewReader(bytes.NewReader(data)); err == nil {
			defer r.Close()
			if dec, ok := boundedReadAll(r, max); ok {
				return dec
			}
		}
	}
	return data
}

// recurseZip treats a .zip as a container and dispatches every member through
// the normal pipeline so nested PDFs, CSVs, etc. are all scanned.
func (s *Scanner) recurseZip(name string, data []byte, depth int, res *Result) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		s.markErr(name, res, "zip open: "+err.Error())
		return
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || isMacMetadata(f.Name) {
			continue
		}
		member := joinLogical(name, f.Name)
		res.Stats.Entries++
		if int64(f.UncompressedSize64) > s.cfg.MaxBytes {
			res.Stats.SkippedTooLarge++
			res.Unscanned = append(res.Unscanned, Unscanned{
				Path: member, Format: formatFor(member), Reason: "exceeds max-bytes limit",
			})
			continue
		}
		rc, err := f.Open()
		if err != nil {
			s.markErr(member, res, "zip member open: "+err.Error())
			continue
		}
		buf, _ := boundedReadAll(rc, s.cfg.MaxBytes)
		rc.Close()
		s.dispatch(member, buf, depth+1, res)
	}
}
