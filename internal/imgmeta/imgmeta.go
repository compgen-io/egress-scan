// Package imgmeta extracts embedded text metadata (and its size) from images,
// without a third-party dependency. It walks PNG chunks and JPEG APPn/COM
// segments — enough to (a) regex the metadata for leaked IDs and (b) measure how
// much metadata is present, since a bloated metadata block can itself smuggle data.
//
// It is best-effort: TIFF/WebP/GIF/BMP return ok=false (metadata not inspected).
package imgmeta

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"strings"
)

// Result is the extracted metadata for one image.
type Result struct {
	Format string // "png" or "jpeg"
	Bytes  int    // total metadata bytes (sum of metadata chunk/segment sizes)
	Text   string // concatenated textual metadata, best-effort
}

// Extract returns image metadata and ok=true for supported formats.
func Extract(data []byte) (Result, bool) {
	switch {
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}):
		return extractPNG(data), true
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return extractJPEG(data), true
	}
	return Result{}, false
}

// structuralPNG are the chunks that carry image structure/pixels, not metadata.
var structuralPNG = map[string]bool{"IHDR": true, "IDAT": true, "IEND": true, "PLTE": true}

func extractPNG(data []byte) Result {
	res := Result{Format: "png"}
	var sb strings.Builder
	p := 8 // past the signature
	for p+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[p : p+4]))
		typ := string(data[p+4 : p+8])
		dataStart := p + 8
		if length < 0 || dataStart+length+4 > len(data) {
			break // truncated/garbage
		}
		chunk := data[dataStart : dataStart+length]

		if !structuralPNG[typ] {
			res.Bytes += length
			switch typ {
			case "tEXt":
				if i := bytes.IndexByte(chunk, 0); i >= 0 {
					sb.Write(chunk[i+1:])
				} else {
					sb.Write(chunk)
				}
				sb.WriteByte('\n')
			case "zTXt":
				if i := bytes.IndexByte(chunk, 0); i >= 0 && i+1 < len(chunk) {
					if dec, ok := zlibInflate(chunk[i+2:]); ok { // skip keyword\0 + method byte
						sb.Write(dec)
						sb.WriteByte('\n')
					}
				}
			case "iTXt":
				writeITXt(&sb, chunk)
			default: // eXIf, tIME, and other ancillary chunks: regex raw bytes
				sb.Write(chunk)
				sb.WriteByte('\n')
			}
		}

		p = dataStart + length + 4 // + CRC
		if typ == "IEND" {
			break
		}
	}
	res.Text = sb.String()
	return res
}

// writeITXt parses an iTXt chunk: keyword\0 compFlag compMethod langTag\0
// translatedKeyword\0 text. text is zlib-compressed when compFlag==1.
func writeITXt(sb *strings.Builder, chunk []byte) {
	i := bytes.IndexByte(chunk, 0)
	if i < 0 || i+2 >= len(chunk) {
		return
	}
	compFlag := chunk[i+1]
	rest := chunk[i+3:] // past compFlag + compMethod
	// skip langTag\0 and translatedKeyword\0
	for n := 0; n < 2; n++ {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			return
		}
		rest = rest[j+1:]
	}
	if compFlag == 1 {
		if dec, ok := zlibInflate(rest); ok {
			sb.Write(dec)
			sb.WriteByte('\n')
		}
		return
	}
	sb.Write(rest)
	sb.WriteByte('\n')
}

func extractJPEG(data []byte) Result {
	res := Result{Format: "jpeg"}
	var sb strings.Builder
	p := 2 // past SOI (FFD8)
	for p+1 < len(data) {
		if data[p] != 0xff {
			break
		}
		marker := data[p+1]
		// Standalone markers (no length): RSTn, TEM, and FF padding.
		if marker == 0xff {
			p++
			continue
		}
		if (marker >= 0xd0 && marker <= 0xd7) || marker == 0x01 {
			p += 2
			continue
		}
		if marker == 0xd9 || marker == 0xda { // EOI or start of scan (pixel data)
			break
		}
		if p+4 > len(data) {
			break
		}
		length := int(binary.BigEndian.Uint16(data[p+2 : p+4])) // includes the 2 length bytes
		segStart := p + 4
		segLen := length - 2
		if segLen < 0 || segStart+segLen > len(data) {
			break
		}
		// APPn (E0-EF) hold EXIF/XMP/IPTC/ICC; COM (FE) is a comment.
		if (marker >= 0xe0 && marker <= 0xef) || marker == 0xfe {
			res.Bytes += segLen
			sb.Write(data[segStart : segStart+segLen])
			sb.WriteByte('\n')
		}
		p = segStart + segLen
	}
	res.Text = sb.String()
	return res
}

func zlibInflate(b []byte) ([]byte, bool) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, 32<<20))
	if err != nil {
		return nil, false
	}
	return out, true
}
