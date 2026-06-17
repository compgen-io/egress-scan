package scan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/compgen-io/egress-scan/internal/fixtures"
	"github.com/compgen-io/egress-scan/internal/idmatch"
)

func newScanner(t *testing.T, ocr bool) *Scanner {
	t.Helper()
	m, err := idmatch.New("")
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Matcher: m, OCR: ocr})
}

// TestSampleTarNonOCR scans the shared fixture tar without OCR and proves every
// non-image format was actually parsed (each ID is unique to one file), that the
// OCR-only ID is NOT found, and that the PNG is reported as unscanned.
func TestSampleTarNonOCR(t *testing.T) {
	tarBytes, err := fixtures.BuildTar()
	if err != nil {
		t.Fatal(err)
	}
	res, err := newScanner(t, false).ScanTarReader(bytes.NewReader(tarBytes))
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range fixtures.NonOCRExpected {
		if _, ok := res.EgressIDs[id]; !ok {
			t.Errorf("expected %s to be found; got %v", id, keys(res.EgressIDs))
		}
	}
	if _, ok := res.EgressIDs[fixtures.IDOCROnly]; ok {
		t.Errorf("OCR-only ID %s must NOT be found without OCR", fixtures.IDOCROnly)
	}

	// The PNG is now noise-analysed regardless of OCR (text in it is low-noise).
	if !hasImage(res, "form.png") {
		t.Errorf("expected scans/form.png in image analysis; got %v", res.Images)
	}
	if res.Stats.Errors != 0 {
		t.Errorf("expected 0 scan errors; got %d (%v)", res.Stats.Errors, res.Unscanned)
	}
}

func hasImage(res *Result, pathSub string) bool {
	for _, im := range res.Images {
		if strings.Contains(im.Path, pathSub) {
			return true
		}
	}
	return false
}

// TestSampleTarDataVolumeAndImages checks the grid-area and image-noise dimensions.
func TestSampleTarDataVolumeAndImages(t *testing.T) {
	tarBytes, err := fixtures.BuildTar()
	if err != nil {
		t.Fatal(err)
	}
	res, err := newScanner(t, false).ScanTarReader(bytes.NewReader(tarBytes))
	if err != nil {
		t.Fatal(err)
	}

	// The wide dump CSV alone exceeds the full-risk area.
	if res.TotalArea < fixtures.DumpArea {
		t.Errorf("total area %d should be >= dump area %d", res.TotalArea, fixtures.DumpArea)
	}
	if !hasGrid(res, "dump.csv", fixtures.DumpRows+1, fixtures.DumpCols) {
		t.Errorf("expected dump.csv grid %dx%d; got %v", fixtures.DumpRows+1, fixtures.DumpCols, res.Grids)
	}

	// Exactly the noise image should be flagged; the text PNG should not.
	flagged := map[string]bool{}
	for _, im := range res.Images {
		flagged[im.Path] = im.Flagged
	}
	if !anyPathFlagged(res, fixtures.NoiseImageName) {
		t.Errorf("expected %s flagged as data-as-pixels; images=%v", fixtures.NoiseImageName, res.Images)
	}
	if anyPathFlagged(res, "form.png") {
		t.Errorf("text PNG form.png should not be flagged; images=%v", res.Images)
	}

	// The PDF's embedded noisy image should be extracted (source "pdf") and flagged.
	pdfImage := false
	for _, im := range res.Images {
		if im.Source == "pdf" && im.Flagged {
			pdfImage = true
		}
	}
	if !pdfImage {
		t.Errorf("expected a flagged PDF-embedded image; images=%v", res.Images)
	}
}

func hasGrid(res *Result, pathSub string, rows, cols int) bool {
	for _, g := range res.Grids {
		if strings.Contains(g.Path, pathSub) && g.Rows == rows && g.Cols == cols {
			return true
		}
	}
	return false
}

func anyPathFlagged(res *Result, pathSub string) bool {
	for _, im := range res.Images {
		if strings.Contains(im.Path, pathSub) && im.Flagged {
			return true
		}
	}
	return false
}
