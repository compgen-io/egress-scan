//go:build ocr

package scan

import "github.com/otiai10/gosseract/v2"

// OCR build (`-tags ocr`): requires Tesseract + Leptonica installed in the build
// and runtime environment (e.g. `apt-get install tesseract-ocr libtesseract-dev`).
// This trades the pure-Go static binary for real image-text extraction.

func ocrAvailable() bool { return true }

func ocrImage(data []byte) (string, error) {
	client := gosseract.NewClient()
	defer client.Close()
	if err := client.SetImageFromBytes(data); err != nil {
		return "", err
	}
	return client.Text()
}
