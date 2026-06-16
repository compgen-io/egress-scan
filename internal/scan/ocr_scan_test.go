//go:build ocr

package scan

import (
	"bytes"
	"testing"

	"github.com/compgen-io/egress-scan/internal/fixtures"
)

// TestSampleTarOCR (ocr build only) proves the OCR path reads the ID rendered
// into the PNG — an ID that is reachable by no other means. Requires Tesseract
// and tessdata at runtime; run inside the devcontainer via `make test-ocr`.
func TestSampleTarOCR(t *testing.T) {
	tarBytes, err := fixtures.BuildTar()
	if err != nil {
		t.Fatal(err)
	}
	res, err := newScanner(t, true).ScanTarReader(bytes.NewReader(tarBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.EgressIDs[fixtures.IDOCROnly]; !ok {
		t.Errorf("OCR build must find %s rendered in the PNG; got %v", fixtures.IDOCROnly, keys(res.EgressIDs))
	}
}
