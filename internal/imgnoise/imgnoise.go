// Package imgnoise estimates how "noisy" (random) an image is, to flag data that
// has been smuggled out as image pixels. Legitimate egress images are plots:
// mostly whitespace, few colours, smooth/correlated neighbours -> compressible.
// Data-as-pixels is near-random: incompressible, high entropy, full-frame.
package imgnoise

import (
	"bytes"
	"compress/flate"
	"image"
	"math"

	// Decoders registered for image.Decode.
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

// FlagThreshold is the noise score at/above which an image is flagged.
const FlagThreshold = 0.65

// maxSamples caps how many pixels we analyse (stride-sampled) for speed.
const maxSamples = 1 << 20

// Report holds the noise score and its components.
type Report struct {
	Width      int     `json:"width"`
	Height     int     `json:"height"`
	Noise      float64 `json:"noise"`             // 0-1 combined score
	Entropy    float64 `json:"entropy"`           // grayscale Shannon entropy, bits (0-8)
	Whitespace float64 `json:"whitespace"`        // fraction of near-white pixels
	CompRatio  float64 `json:"compression_ratio"` // deflate(pixels)/pixels, ~1 = random
}

// Flagged reports whether the score crosses the threshold.
func (r Report) Flagged() bool { return r.Noise >= FlagThreshold }

// Analyze scores a decoded image.
func Analyze(img image.Image) Report {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	// Stride so we examine at most ~maxSamples pixels.
	stride := 1
	if w*h > maxSamples {
		stride = int(math.Ceil(math.Sqrt(float64(w*h) / float64(maxSamples))))
	}

	var hist [256]int
	var gray []byte
	white := 0
	total := 0
	for y := b.Min.Y; y < b.Max.Y; y += stride {
		for x := b.Min.X; x < b.Max.X; x += stride {
			r, g, bl, _ := img.At(x, y).RGBA() // 16-bit per channel
			// luma, scaled back to 8-bit
			lum := byte((299*(r>>8) + 587*(g>>8) + 114*(bl>>8)) / 1000)
			hist[lum]++
			gray = append(gray, lum)
			if lum >= 235 {
				white++
			}
			total++
		}
	}
	if total == 0 {
		return Report{Width: w, Height: h}
	}

	entropy := shannon(hist[:], total)
	whitespace := float64(white) / float64(total)
	comp := deflateRatio(gray)

	// Compressibility is the strongest signal; entropy backs it up; abundant
	// whitespace (plots) dampens the score.
	raw := 0.6*comp + 0.4*(entropy/8.0)
	noise := raw * (1 - 0.5*whitespace)
	if noise < 0 {
		noise = 0
	} else if noise > 1 {
		noise = 1
	}

	return Report{
		Width: w, Height: h,
		Noise:      round3(noise),
		Entropy:    round3(entropy),
		Whitespace: round3(whitespace),
		CompRatio:  round3(comp),
	}
}

// AnalyzeBytes decodes image bytes and scores them.
func AnalyzeBytes(data []byte) (Report, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return Report{}, err
	}
	return Analyze(img), nil
}

func shannon(hist []int, total int) float64 {
	var e float64
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		e -= p * math.Log2(p)
	}
	return e
}

// deflateRatio returns compressed/original size of the pixel bytes (best-effort;
// returns 1.0 if compression fails). Near 1.0 means incompressible ~ random.
func deflateRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		return 1
	}
	if _, err := zw.Write(data); err != nil {
		return 1
	}
	zw.Close()
	return float64(buf.Len()) / float64(len(data))
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }
