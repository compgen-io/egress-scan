package scan

// scanImage runs OCR on an image when the binary was built with the `ocr` tag
// and --ocr is enabled; otherwise the image is flagged for manual review.
func (s *Scanner) scanImage(name string, data []byte, res *Result) {
	if !s.cfg.OCR {
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: formatFor(name), Reason: "image not scanned (OCR disabled)",
		})
		return
	}
	if !ocrAvailable() {
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: formatFor(name),
			Reason: "OCR requested but binary built without OCR support",
		})
		return
	}
	text, err := ocrImage(data)
	if err != nil {
		s.markErr(name, res, "ocr: "+err.Error())
		return
	}
	for id := range s.cfg.Matcher.IBIDs(text) {
		res.record(name, id, formatFor(name), "ocr")
	}
	res.PHIMatches += s.cfg.Matcher.PHICount(text)
	res.Stats.Scanned++
}
