package scan

import (
	"archive/zip"
	"bytes"
	"strings"
)

// scanOffice handles OOXML (.xlsx/.docx/.pptx) and OpenDocument (.ods/.odt/.odp).
// All are zip containers of XML; IB-IDs appear literally in the XML text, so we
// open the zip and regex the relevant member parts. We avoid a heavyweight
// spreadsheet library and the false-negative risk of scanning compressed bytes.
func (s *Scanner) scanOffice(name string, data []byte, ext string, res *Result) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		// Not a valid zip — treat as opaque and flag for review.
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: formatFor(name), Reason: "office container open failed: " + err.Error(),
		})
		return
	}

	scannedAny := false
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !isOfficeTextPart(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf, _ := boundedReadAll(rc, s.cfg.MaxBytes)
		rc.Close()

		text := string(buf)
		for id := range s.cfg.Matcher.IBIDs(text) {
			res.record(name, id, ext[1:], "structured")
		}
		res.PHIMatches += s.cfg.Matcher.PHICount(text)
		scannedAny = true
	}

	if scannedAny {
		res.Stats.Scanned++
	} else {
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: formatFor(name), Reason: "no scannable XML parts found",
		})
	}
}

// isOfficeTextPart selects the XML parts that carry user content across OOXML
// and OpenDocument, skipping binaries (media, fonts) and relationship plumbing.
func isOfficeTextPart(n string) bool {
	n = strings.ToLower(n)
	if !strings.HasSuffix(n, ".xml") {
		return false
	}
	switch {
	case strings.HasPrefix(n, "xl/"): // xlsx: sharedStrings, sheets, etc.
		return true
	case strings.HasPrefix(n, "word/"): // docx
		return true
	case strings.HasPrefix(n, "ppt/"): // pptx
		return true
	case n == "content.xml" || n == "styles.xml" || n == "meta.xml": // OpenDocument
		return true
	}
	return false
}
