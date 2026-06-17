package scan

import (
	"github.com/compgen-io/egress-scan/internal/imgmeta"
	"github.com/compgen-io/egress-scan/internal/imgnoise"
)

// scanImage analyses a standalone image: noise (data-as-pixels), embedded text
// metadata (IDs + how much metadata), and — when OCR is enabled and compiled in
// — OCR text for IB-IDs.
func (s *Scanner) scanImage(name string, data []byte, res *Result) {
	info, ok := s.noiseInfo(name, data, formatFor(name), "file", res)
	if ok {
		// Embedded text metadata: scan for IDs/PHI and flag bloated metadata.
		if meta, mok := imgmeta.Extract(data); mok {
			for id := range s.cfg.Matcher.IBIDs(meta.Text) {
				res.record(name, id, formatFor(name), "metadata")
			}
			res.PHIMatches += s.cfg.Matcher.PHICount(meta.Text)
			info.MetadataBytes = meta.Bytes
			info.MetadataFlagged = int64(meta.Bytes) > s.cfg.MetadataLimit
		}
		res.Images = append(res.Images, info)
		res.Stats.Scanned++
	}

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

// analyzeImage decodes, scores noise, and records the image. Used for
// PDF-embedded images (no original-file metadata to inspect).
func (s *Scanner) analyzeImage(name string, data []byte, format, source string, res *Result) {
	if info, ok := s.noiseInfo(name, data, format, source, res); ok {
		res.Images = append(res.Images, info)
		res.Stats.Scanned++
	}
}

// noiseInfo decodes image bytes and builds an ImageInfo from the noise analysis.
// On decode failure it records an Unscanned entry and returns ok=false; the
// caller is responsible for appending the returned info.
func (s *Scanner) noiseInfo(name string, data []byte, format, source string, res *Result) (ImageInfo, bool) {
	rep, err := imgnoise.AnalyzeBytes(data)
	if err != nil {
		res.Unscanned = append(res.Unscanned, Unscanned{
			Path: name, Format: format, Reason: "image decode failed: " + err.Error(),
		})
		return ImageInfo{}, false
	}
	return ImageInfo{
		Path: name, Format: format, Source: source,
		Width: rep.Width, Height: rep.Height,
		Noise: rep.Noise, Entropy: rep.Entropy, Whitespace: rep.Whitespace,
		CompRatio: rep.CompRatio, Flagged: rep.Flagged(),
	}, true
}
