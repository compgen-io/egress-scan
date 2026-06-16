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

	if !hasUnscanned(res, "form.png", "OCR disabled") {
		t.Errorf("expected scans/form.png flagged unscanned (OCR disabled); got %v", res.Unscanned)
	}
	if res.Stats.Errors != 0 {
		t.Errorf("expected 0 scan errors; got %d (%v)", res.Stats.Errors, res.Unscanned)
	}
}

func hasUnscanned(res *Result, pathSub, reasonSub string) bool {
	for _, u := range res.Unscanned {
		if strings.Contains(u.Path, pathSub) && strings.Contains(u.Reason, reasonSub) {
			return true
		}
	}
	return false
}
