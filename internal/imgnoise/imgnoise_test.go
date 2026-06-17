package imgnoise

import (
	"image"
	"image/color"
	"testing"
)

// plotLike: white background with a few black axis lines and a sparse curve —
// mostly whitespace, highly compressible.
func plotLike(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.White)
		}
	}
	for y := 0; y < h; y++ { // y-axis
		img.Set(40, y, color.Black)
	}
	for x := 0; x < w; x++ { // x-axis
		img.Set(x, h-40, color.Black)
	}
	for x := 40; x < w; x++ { // a curve
		y := h - 40 - (x-40)*(x-40)/(w/2)
		if y >= 0 && y < h {
			img.Set(x, y, color.RGBA{200, 0, 0, 255})
		}
	}
	return img
}

// noiseLike: a deterministic high-entropy field (data smuggled as pixels).
func noiseLike(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	var s uint32 = 0x12345678
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			s = s*1664525 + 1013904223 // LCG -> pseudo-random
			v := uint8(s >> 24)
			img.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}
	return img
}

func TestNoiseDiscriminatesPlotFromData(t *testing.T) {
	plot := Analyze(plotLike(400, 300))
	noise := Analyze(noiseLike(400, 300))

	t.Logf("plot:  noise=%.3f comp=%.3f ent=%.3f white=%.3f", plot.Noise, plot.CompRatio, plot.Entropy, plot.Whitespace)
	t.Logf("noise: noise=%.3f comp=%.3f ent=%.3f white=%.3f", noise.Noise, noise.CompRatio, noise.Entropy, noise.Whitespace)

	if plot.Flagged() {
		t.Errorf("plot-like image should NOT be flagged (noise=%.3f)", plot.Noise)
	}
	if !noise.Flagged() {
		t.Errorf("noise-like image SHOULD be flagged (noise=%.3f)", noise.Noise)
	}
	if noise.Noise <= plot.Noise {
		t.Errorf("noise score (%.3f) should exceed plot score (%.3f)", noise.Noise, plot.Noise)
	}
}
