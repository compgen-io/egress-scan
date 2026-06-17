package scan

import "github.com/compgen-io/egress-scan/internal/imgnoise"

// scanImage analyses every image for noise (data-as-pixels detection) and, when
// OCR is enabled and compiled in, additionally OCRs it for IB-IDs.
func (s *Scanner) scanImage(name string, data []byte, res *Result) {
	s.analyzeImage(name, data, formatFor(name), "file", res)

	if s.cfg.OCR && ocrAvailable() {
		text, err := ocrImage(data)
		if err != nil {
			s.markErr(name, res, "ocr: "+err.Error())
			return
		}
		for id := range s.cfg.Matcher.IBIDs(text) {
			res.record(name, id, formatFor(name), "ocr")
		}
		res.PHIMatches += s.cfg.Matcher.PHICount(text)
	}
}

// analyzeImage decodes image bytes, scores their noise, and records the result.
// source is "file" for standalone images or "pdf" for PDF-embedded ones.
func (s *Scanner) analyzeImage(name string, data []byte, format, source string, res *Result) {
	rep, err := imgnoise.AnalyzeBytes(data)
	if err != nil {
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: format, Reason: "image decode failed: " + err.Error(),
		})
		return
	}
	res.Images = append(res.Images, ImageInfo{
		Path: name, Format: format, Source: source,
		Width: rep.Width, Height: rep.Height,
		Noise: rep.Noise, Entropy: rep.Entropy, Whitespace: rep.Whitespace,
		CompRatio: rep.CompRatio, Flagged: rep.Flagged(),
	})
	res.Stats.Scanned++
}
