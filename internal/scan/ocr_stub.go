//go:build !ocr

package scan

// Default build: no OCR engine compiled in, so the binary stays pure-Go and
// statically linkable with no Tesseract dependency. Build with `-tags ocr` to
// enable the Tesseract-backed implementation in ocr_tesseract.go.

func ocrAvailable() bool { return false }

func ocrImage(_ []byte) (string, error) { return "", nil }
