package imgmeta

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/png"
	"strings"
	"testing"
)

// pngWithText encodes a tiny PNG and inserts a tEXt chunk before IEND.
func pngWithText(t *testing.T, keyword, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()

	data := append(append([]byte(keyword), 0), text...)
	body := append([]byte("tEXt"), data...)
	var lenb, crcb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(data)))
	binary.BigEndian.PutUint32(crcb[:], crc32.ChecksumIEEE(body))

	cut := len(raw) - 12
	out := append([]byte{}, raw[:cut]...)
	out = append(out, lenb[:]...)
	out = append(out, body...)
	out = append(out, crcb[:]...)
	out = append(out, raw[cut:]...)
	return out
}

func TestExtractPNGText(t *testing.T) {
	img := pngWithText(t, "Comment", "patient IB-4242 enrolled")
	res, ok := Extract(img)
	if !ok || res.Format != "png" {
		t.Fatalf("expected png metadata; ok=%v res=%+v", ok, res)
	}
	if !strings.Contains(res.Text, "IB-4242") {
		t.Errorf("metadata text missing the ID; got %q", res.Text)
	}
	if res.Bytes == 0 {
		t.Errorf("expected non-zero metadata bytes")
	}
}

func TestExtractUnsupported(t *testing.T) {
	if _, ok := Extract([]byte("GIF89a....")); ok {
		t.Errorf("GIF should be reported as unsupported metadata")
	}
}
