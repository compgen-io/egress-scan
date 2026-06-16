// Package fixtures builds a self-contained sample egress tar exercising every
// scanner path, plus the matching approved-ID list. It is shared by the tests
// and by the `gen-fixtures` command (so `make fixtures` writes real files to
// testdata/ that you can scan by hand).
//
// Each IB-ID below is unique to one file so a test can prove that file's path
// was actually scanned. IDOCROnly lives only inside a rendered PNG, so it is
// reachable solely via OCR — non-OCR builds must NOT find it.
package fixtures

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"database/sql"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"

	_ "modernc.org/sqlite"
)

// Known IDs placed in the sample tar.
const (
	IDApproved = "IB-1001" // in csv + sqlite; also in the approved list (overlap)
	IDCSV      = "IB-1002" // plain csv
	IDText     = "IB-1003" // nested-dir text file
	IDZip      = "IB-1004" // inside a nested .zip
	IDGz       = "IB-1005" // inside a .csv.gz
	IDSQLite   = "IB-1006" // sqlite cell
	IDDocx     = "IB-1007" // docx content XML
	IDRDS      = "IB-1008" // gzipped .rds (inline string)
	IDRawH5    = "IB-1009" // literal ASCII in an unsupported .h5 binary
	IDOCROnly  = "IB-7788" // ONLY rendered into a PNG; OCR-only
)

// ApprovedIDs is the approved set the sample is compared against.
var ApprovedIDs = []string{IDApproved}

// NonOCRExpected are the IDs a non-OCR scan must find.
var NonOCRExpected = []string{
	IDApproved, IDCSV, IDText, IDZip, IDGz, IDSQLite, IDDocx, IDRDS, IDRawH5,
}

// BuildTar returns the sample tar bytes. The PNG (OCR-only ID) is always
// included; whether its ID is found depends on the scan's OCR setting.
func BuildTar() ([]byte, error) {
	zipBytes, err := makeZip("inner/leak.txt", []byte("patient "+IDZip+" enrolled\n"))
	if err != nil {
		return nil, err
	}
	gzBytes, err := makeGzip([]byte("id\n" + IDGz + "\n"))
	if err != nil {
		return nil, err
	}
	rdsBytes, err := makeGzip([]byte("X\n\x00\x00\x00\x03 subject " + IDRDS + " factor\n"))
	if err != nil {
		return nil, err
	}
	docxBytes, err := makeDocx(IDDocx)
	if err != nil {
		return nil, err
	}
	sqliteBytes, err := makeSQLite()
	if err != nil {
		return nil, err
	}
	pngBytes, err := RenderPNG(IDOCROnly)
	if err != nil {
		return nil, err
	}

	files := []struct {
		name string
		data []byte
	}{
		{"data/sample.csv", []byte("subject,note\np1," + IDApproved + "\np2," + IDCSV + " enrolled\n")},
		{"data/notes/readme.txt", []byte("see patient " + IDText + " for details\n")},
		{"bundle.zip", zipBytes},
		{"data/col.csv.gz", gzBytes},
		{"data/model.rds", rdsBytes},
		{"report.docx", docxBytes},
		{"data/cohort.sqlite", sqliteBytes},
		{"data/matrix.h5", append([]byte("\x89HDF\r\n\x1a\n....."), []byte(IDRawH5+".....")...)},
		{"scans/form.png", pngBytes},
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func makeGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func makeZip(name string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// makeDocx writes a minimal but valid OOXML docx containing the id in its body.
func makeDocx(id string) ([]byte, error) {
	parts := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
		"word/document.xml":   `<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p><w:r><w:t>Report for ` + id + `</w:t></w:r></w:p></w:body></w:document>`,
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range parts {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// makeSQLite builds an in-memory-then-serialised SQLite db with two rows.
func makeSQLite() ([]byte, error) {
	tmp, err := os.CreateTemp("", "fixture-*.sqlite")
	if err != nil {
		return nil, err
	}
	path := tmp.Name()
	tmp.Close()
	defer os.Remove(path)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE subjects(id TEXT, label TEXT)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`INSERT INTO subjects VALUES(?,?),(?,?)`,
		IDApproved, "baseline", IDSQLite, "followup"); err != nil {
		db.Close()
		return nil, err
	}
	db.Close()
	return os.ReadFile(path)
}

// RenderPNG renders text as a clean, antialiased black-on-white PNG that
// Tesseract can read, using the embedded Go TrueType font at a legible size with
// a generous white margin (Tesseract needs the surrounding whitespace).
func RenderPNG(text string) ([]byte, error) {
	const ptSize = 64
	const pad = 24

	ttf, err := opentype.Parse(goregular.TTF)
	if err != nil {
		return nil, err
	}
	face, err := opentype.NewFace(ttf, &opentype.FaceOptions{
		Size: ptSize, DPI: 72, Hinting: font.HintingFull,
	})
	if err != nil {
		return nil, err
	}
	defer face.Close()

	m := face.Metrics()
	d := &font.Drawer{Face: face}
	width := d.MeasureString(text).Ceil()
	ascent, descent := m.Ascent.Ceil(), m.Descent.Ceil()

	img := image.NewRGBA(image.Rect(0, 0, width+2*pad, ascent+descent+2*pad))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	d.Dst = img
	d.Src = image.NewUniform(color.Black)
	d.Dot = fixed.P(pad, pad+ascent)
	d.DrawString(text)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteTestdata materialises the sample tar, the approved list, and the raw PNG
// into dir (created if needed) so they can be scanned manually.
func WriteTestdata(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tarBytes, err := BuildTar()
	if err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/egress-sample.tar", tarBytes, 0o644); err != nil {
		return err
	}
	approved := ""
	for _, id := range ApprovedIDs {
		approved += id + "\n"
	}
	if err := os.WriteFile(dir+"/approved.txt", []byte(approved), 0o644); err != nil {
		return err
	}
	pngBytes, err := RenderPNG(IDOCROnly)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/ocr-sample.png", pngBytes, 0o644); err != nil {
		return err
	}
	return nil
}
