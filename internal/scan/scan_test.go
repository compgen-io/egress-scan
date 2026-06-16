package scan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/compgen-io/egress-scan/internal/idmatch"
)

// buildTar writes the given name->content map into an in-memory tar.
func buildTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}

func scanBytes(t *testing.T, data []byte) *Result {
	t.Helper()
	m, err := idmatch.New("")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Matcher: m})
	res := newResult()
	if err := s.scanTarStream(bytes.NewReader(data), "", res); err != nil {
		t.Fatal(err)
	}
	return res
}

func TestScanFindsIDsAcrossFormats(t *testing.T) {
	tarBytes := buildTar(t, map[string][]byte{
		"a.csv":        []byte("id\nIB-1234\n"),
		"sub/b.txt":    []byte("note about IB_5678 here"), // underscore normalises to dash
		"c.csv.gz":     gzipBytes(t, []byte("x\nIB-9999\n")),
		"d.rds":        gzipBytes(t, []byte("X\n\x00\x00 subject IB-2468 \n")),
		"._a.csv":      []byte("IB-0000"), // AppleDouble: must be skipped
		"data.unknown": []byte("binary\x00prefix IB-7777 trailing"),
	})

	res := scanBytes(t, tarBytes)

	want := []string{"IB-1234", "IB-5678", "IB-9999", "IB-2468", "IB-7777"}
	for _, id := range want {
		if _, ok := res.EgressIDs[id]; !ok {
			t.Errorf("expected to find %s; got %v", id, keys(res.EgressIDs))
		}
	}
	if _, ok := res.EgressIDs["IB-0000"]; ok {
		t.Errorf("AppleDouble file should have been skipped but IB-0000 was found")
	}
}

func TestNestedZipIsRecursed(t *testing.T) {
	// A zip nested inside the tar whose member holds an ID.
	var zbuf bytes.Buffer
	{
		zw := zip.NewWriter(&zbuf)
		w, err := zw.Create("inner/leak.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("contains IB-4321")); err != nil {
			t.Fatal(err)
		}
		zw.Close()
	}
	res := scanBytes(t, buildTar(t, map[string][]byte{"bundle.zip": zbuf.Bytes()}))
	if _, ok := res.EgressIDs["IB-4321"]; !ok {
		t.Errorf("expected IB-4321 from nested zip; got %v", keys(res.EgressIDs))
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
