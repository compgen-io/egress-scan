package scan

import (
	"bytes"
	"io"
	"strings"

	"github.com/ledongthuc/pdf"
)

// scanPDF extracts the text layer from a PDF and scans it. Scanned/image-only
// PDFs have no text layer; those are flagged for manual review (or OCR once that
// path is added). Best-effort: unusual font encodings may yield partial text.
func (s *Scanner) scanPDF(name string, data []byte, res *Result) {
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		s.markErr(name, res, "pdf open: "+err.Error())
		return
	}

	var sb strings.Builder
	if tr, err := r.GetPlainText(); err == nil {
		_, _ = io.Copy(&sb, tr) // fall through with whatever was captured
	}
	text := sb.String()

	if strings.TrimSpace(text) == "" {
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: "pdf",
			Reason: "no extractable text layer (possibly scanned/image PDF)",
		})
		return
	}

	for id := range s.cfg.Matcher.IBIDs(text) {
		res.record(name, id, "pdf", "regex")
	}
	res.PHIMatches += s.cfg.Matcher.PHICount(text)
	res.Stats.Scanned++
}
