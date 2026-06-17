package scan

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/ledongthuc/pdf"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

func init() {
	// Don't read/write the user's pdfcpu config dir; keep the tool self-contained.
	pdfmodel.ConfigPath = "disable"
}

// scanPDF extracts the PDF text layer (scanned for IDs) and every embedded image
// (analysed for noise / data-as-pixels). A PDF with neither is flagged.
func (s *Scanner) scanPDF(name string, data []byte, res *Result) {
	textFound := s.scanPDFText(name, data, res)
	imagesFound := s.scanPDFImages(name, data, res)

	if !textFound && !imagesFound {
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: "pdf",
			Reason: "no extractable text layer or images (possibly scanned/image PDF)",
		})
	}
}

func (s *Scanner) scanPDFText(name string, data []byte, res *Result) bool {
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		s.markErr(name, res, "pdf open: "+err.Error())
		return false
	}
	var sb strings.Builder
	if tr, err := r.GetPlainText(); err == nil {
		_, _ = io.Copy(&sb, tr)
	}
	text := sb.String()
	if strings.TrimSpace(text) == "" {
		return false
	}
	for id := range s.cfg.Matcher.IBIDs(text) {
		res.record(name, id, "pdf", "regex")
	}
	res.PHIMatches += s.cfg.Matcher.PHICount(text)
	res.Stats.Scanned++
	return true
}

// scanPDFImages extracts embedded image XObjects via pdfcpu and runs the noise
// analysis on each. Returns whether any image was analysed.
func (s *Scanner) scanPDFImages(name string, data []byte, res *Result) bool {
	conf := pdfmodel.NewDefaultConfiguration()
	conf.ValidationMode = pdfmodel.ValidationRelaxed

	pages, err := pdfapi.ExtractImagesRaw(bytes.NewReader(data), nil, conf)
	if err != nil {
		return false // best effort; text path already covered
	}

	found := false
	idx := 0
	for _, pageImages := range pages {
		for _, img := range pageImages {
			idx++
			buf, err := io.ReadAll(io.LimitReader(img, s.cfg.MaxBytes))
			if err != nil || len(buf) == 0 {
				continue
			}
			label := fmt.Sprintf("%s#image%d", name, idx)
			format := strings.ToLower(img.FileType)
			if format == "" {
				format = "img"
			}
			s.analyzeImage(label, buf, format, "pdf", res)
			found = true
		}
	}
	return found
}
