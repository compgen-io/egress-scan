// Command egress-scan inspects an egress tar artifact for leaks of internal
// biobank identifiers (IB-IDs). It runs as a standalone workflow step: point it
// at the tar, optionally give it the approved-ID set, and it emits a JSON report
// with a plain-text recommendation and a 0-100 risk score.
//
// Exit codes: 0 = no novel IB-IDs, 1 = novel IB-IDs found, 2 = fatal error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/compgen-io/egress-scan/internal/approved"
	"github.com/compgen-io/egress-scan/internal/grid"
	"github.com/compgen-io/egress-scan/internal/idmatch"
	"github.com/compgen-io/egress-scan/internal/risk"
	"github.com/compgen-io/egress-scan/internal/scan"
)

// HighRiskThreshold is the per-file total risk above which a file is called out.
const HighRiskThreshold = 30

// Report is the JSON document written to --out (or stdout).
type Report struct {
	Recommendation string           `json:"recommendation"`
	TotalRisk      int              `json:"total_risk"` // tar-level 0-100
	RiskScore      int              `json:"risk_score"` // IB/PHI sub-score (tar)
	RiskLevel      string           `json:"risk_level"`
	Summary        string           `json:"summary"`
	Reasons        []string         `json:"reasons"`
	HighRiskFiles  []FileRisk       `json:"high_risk_files"` // risk > HighRiskThreshold
	FileRisks      []FileRisk       `json:"file_risks"`      // every file with a signal
	IBIDScan       IBIDScan         `json:"ib_id_scan"`
	DataVolume     DataVolume       `json:"data_volume"`
	ImageAnalysis  ImageAnalysis    `json:"image_analysis"`
	Findings       []scan.Finding   `json:"findings"`
	Unscanned      []scan.Unscanned `json:"unscanned"`
	ScanStats      scan.Stats       `json:"scan_stats"`
}

// FileRisk is one file's 0-100 total risk and the per-dimension sub-scores it is
// the max of.
type FileRisk struct {
	Path           string `json:"path"`
	Risk           int    `json:"risk"`             // max of the sub-scores
	IBRisk         int    `json:"ib_risk"`          // novel/overlap IB-IDs in the file
	DataVolumeRisk int    `json:"data_volume_risk"` // grid area/rows
	ImageRisk      int    `json:"image_risk"`       // worst image noise
}

// DataVolume reports grid (table/matrix/data.frame) area and its 0-1 risk: a
// large total area suggests a raw data dump rather than aggregate results.
type DataVolume struct {
	TotalArea int             `json:"total_area"`
	AreaRisk  float64         `json:"area_risk"`
	Grids     []scan.GridInfo `json:"grids"`
}

// ImageAnalysis reports per-image noise scores; flagged images look like data
// encoded as pixels rather than ordinary plots.
type ImageAnalysis struct {
	FlaggedCount int              `json:"flagged_count"`
	Images       []scan.ImageInfo `json:"images"`
}

// IBIDScan mirrors the ib_id_scan block produced by risk_scoring.py.
type IBIDScan struct {
	ApprovedSource     string   `json:"approved_source"`
	ApprovedIBIDCount  int      `json:"approved_ib_id_count"`
	EgressIBIDCount    int      `json:"egress_ib_id_count"`
	OverlapIBIDCount   int      `json:"overlap_ib_id_count"`
	NovelIBIDCount     int      `json:"novel_ib_id_count"`
	NovelIBIDsSample   []string `json:"novel_ib_ids_sample"`
	OverlapIBIDsSample []string `json:"overlap_ib_ids_sample"`
}

func main() {
	var (
		tarPath     = flag.String("tar", "", "path to the egress tar file to scan (required)")
		approvedIDs = flag.String("approved-ids", "", "file of approved IB-IDs to compare against")
		approvedDir = flag.String("approved-dir", "", "directory of approved dataset files to extract IB-IDs from")
		s3Bucket    = flag.String("approved-s3-bucket", os.Getenv("APPROVED_DATASETS_BUCKET"), "approved-datasets S3 bucket (enables S3 scan when set)")
		s3Prefix    = flag.String("approved-s3-prefix", os.Getenv("APPROVED_DATASETS_PREFIX"), "S3 key prefix to scan for approved IB-IDs")
		ibPattern   = flag.String("ib-pattern", idmatch.DefaultIBPattern, "IB-ID regex (overridable like IB_ID_PATTERN)")
		maxBytes    = flag.Int64("max-bytes", 100*1024*1024, "per-file size cap; larger files are flagged not read")
		maxDepth    = flag.Int("max-depth", 12, "maximum nested-archive recursion depth")
		ocr         = flag.Bool("ocr", false, "OCR images for text (requires a binary built with -tags ocr)")
		outPath     = flag.String("out", "", "write JSON report here (default: stdout)")
		pretty      = flag.Bool("pretty", true, "pretty-print JSON output")
	)
	flag.Parse()

	if *tarPath == "" {
		fmt.Fprintln(os.Stderr, "error: --tar is required")
		flag.Usage()
		os.Exit(2)
	}

	matcher, err := idmatch.New(*ibPattern)
	if err != nil {
		fatal("invalid --ib-pattern: %v", err)
	}

	ctx := context.Background()
	opts := approved.Options{
		IDsFile:        *approvedIDs,
		Dir:            *approvedDir,
		S3Bucket:       *s3Bucket,
		S3Prefix:       *s3Prefix,
		MaxObjects:     envInt("IB_SCAN_MAX_APPROVED_OBJECTS", 500),
		MaxObjectBytes: int64(envInt("IB_SCAN_MAX_OBJECT_BYTES", 5*1024*1024)),
	}
	// Build an S3 client only when a bucket is configured and no higher-precedence
	// source (file/dir) is set, so the default path needs no AWS credentials.
	if *s3Bucket != "" && *approvedIDs == "" && *approvedDir == "" {
		cfg, cerr := awsconfig.LoadDefaultConfig(ctx)
		if cerr != nil {
			fatal("loading AWS config: %v", cerr)
		}
		opts.S3 = s3.NewFromConfig(cfg)
	}

	approvedSet, src, err := approved.Load(ctx, matcher, opts)
	if err != nil {
		fatal("loading approved IDs: %v", err)
	}

	scanner := scan.New(scan.Config{
		Matcher: matcher, MaxBytes: *maxBytes, MaxDepth: *maxDepth, OCR: *ocr,
	})
	if scanner.OCRRequestedButUnavailable() {
		fmt.Fprintln(os.Stderr, "warning: --ocr set but this binary was built without OCR support (-tags ocr); images will be flagged unscanned")
	}

	res, err := scanner.ScanTarFile(*tarPath)
	if err != nil {
		fatal("scanning %s: %v", *tarPath, err)
	}

	report := buildReport(res, approvedSet, src)

	out := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fatal("creating --out: %v", err)
		}
		defer f.Close()
		out = f
	}
	enc := json.NewEncoder(out)
	if *pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(report); err != nil {
		fatal("writing report: %v", err)
	}

	// Non-zero exit when the tar total risk exceeds the threshold, so the
	// workflow step can gate.
	if report.TotalRisk > HighRiskThreshold {
		os.Exit(1)
	}
}

func buildReport(res *scan.Result, approvedSet map[string]struct{}, src approved.Source) Report {
	var overlap, novel []string
	for id := range res.EgressIDs {
		if _, ok := approvedSet[id]; ok {
			overlap = append(overlap, id)
		} else {
			novel = append(novel, id)
		}
	}
	sort.Strings(overlap)
	sort.Strings(novel)

	assessment := risk.Assess(risk.Inputs{
		TotalEgressIDs: len(res.EgressIDs),
		OverlapIDs:     len(overlap),
		NovelIDs:       len(novel),
		PHIMatches:     res.PHIMatches,
		UnscannedFiles: len(res.Unscanned),
	})

	findings := res.Findings
	if findings == nil {
		findings = []scan.Finding{}
	}
	unscanned := res.Unscanned
	if unscanned == nil {
		unscanned = []scan.Unscanned{}
	}
	grids := res.Grids
	if grids == nil {
		grids = []scan.GridInfo{}
	}
	images := res.Images
	if images == nil {
		images = []scan.ImageInfo{}
	}

	flaggedImages := 0
	for _, im := range res.Images {
		if im.Flagged {
			flaggedImages++
		}
	}
	maxGridRisk := 0.0
	for _, g := range grids {
		if r := grid.GridRisk(g.Rows, g.Cols); r > maxGridRisk {
			maxGridRisk = r
		}
	}

	// Per-file total risk = max(IB, data-volume, image) sub-scores.
	fileRisks := buildFileRisks(res, approvedSet)
	var highRisk []FileRisk
	maxFile := 0
	for _, fr := range fileRisks {
		if fr.Risk > maxFile {
			maxFile = fr.Risk
		}
		if fr.Risk > HighRiskThreshold {
			highRisk = append(highRisk, fr)
		}
	}
	if highRisk == nil {
		highRisk = []FileRisk{}
	}
	// Tar total = worst file, floored at the tar-wide IB/PHI score so a broad
	// leak still registers even if no single file dominates.
	totalRisk := maxInt(maxFile, assessment.Score)

	return Report{
		Recommendation: recommendation(totalRisk, highRisk),
		TotalRisk:      totalRisk,
		RiskScore:      assessment.Score,
		RiskLevel:      assessment.Level,
		Summary:        assessment.Summary,
		Reasons:        assessment.Reasons,
		HighRiskFiles:  highRisk,
		FileRisks:      fileRisks,
		IBIDScan: IBIDScan{
			ApprovedSource:     src.Kind,
			ApprovedIBIDCount:  len(approvedSet),
			EgressIBIDCount:    len(res.EgressIDs),
			OverlapIBIDCount:   len(overlap),
			NovelIBIDCount:     len(novel),
			NovelIBIDsSample:   sample(novel, 20),
			OverlapIBIDsSample: sample(overlap, 20),
		},
		DataVolume: DataVolume{
			TotalArea: res.TotalArea,
			AreaRisk:  round2(maxGridRisk),
			Grids:     grids,
		},
		ImageAnalysis: ImageAnalysis{
			FlaggedCount: flaggedImages,
			Images:       images,
		},
		Findings:  findings,
		Unscanned: unscanned,
		ScanStats: res.Stats,
	}
}

// buildFileRisks aggregates per-file sub-risks and combines them with max().
func buildFileRisks(res *scan.Result, approvedSet map[string]struct{}) []FileRisk {
	type agg struct {
		ids, novel, overlap int
		seen                map[string]bool
		dataRisk, imgRisk   float64
	}
	files := map[string]*agg{}
	get := func(p string) *agg {
		a := files[p]
		if a == nil {
			a = &agg{seen: map[string]bool{}}
			files[p] = a
		}
		return a
	}

	for _, f := range res.Findings {
		a := get(f.Path)
		if a.seen[f.ID] {
			continue
		}
		a.seen[f.ID] = true
		a.ids++
		if _, ok := approvedSet[f.ID]; ok {
			a.overlap++
		} else {
			a.novel++
		}
	}
	for _, g := range res.Grids {
		a := get(g.Path)
		if r := grid.GridRisk(g.Rows, g.Cols); r > a.dataRisk {
			a.dataRisk = r
		}
	}
	for _, im := range res.Images {
		a := get(ownerFile(im.Path)) // roll PDF-embedded images up to the PDF
		if im.Noise > a.imgRisk {
			a.imgRisk = im.Noise
		}
	}

	out := make([]FileRisk, 0, len(files))
	for path, a := range files {
		ib := risk.Assess(risk.Inputs{TotalEgressIDs: a.ids, OverlapIDs: a.overlap, NovelIDs: a.novel}).Score
		dv := int(math.Round(a.dataRisk * 100))
		img := int(math.Round(a.imgRisk * 100))
		out = append(out, FileRisk{
			Path: path, Risk: maxInt(ib, dv, img),
			IBRisk: ib, DataVolumeRisk: dv, ImageRisk: img,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// ownerFile strips a "#imageN" suffix so PDF-embedded images roll up to their PDF.
func ownerFile(path string) string {
	if i := strings.Index(path, "#"); i >= 0 {
		return path[:i]
	}
	return path
}

// recommendation names the highest-risk files (those over the threshold).
func recommendation(totalRisk int, high []FileRisk) string {
	if len(high) == 0 {
		return fmt.Sprintf("No files exceed the risk threshold (%d/100); tar total risk %d/100. Low risk.", HighRiskThreshold, totalRisk)
	}
	const maxList = 5
	parts := make([]string, 0, maxList)
	for i, fr := range high {
		if i >= maxList {
			parts = append(parts, fmt.Sprintf("and %d more", len(high)-maxList))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", fr.Path, fr.Risk))
	}
	return fmt.Sprintf("Check this file before release — tar total risk %d/100. Highest-risk files: %s. Manual review required.",
		totalRisk, strings.Join(parts, ", "))
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func maxInt(vals ...int) int {
	m := 0
	for _, v := range vals {
		if v > m {
			m = v
		}
	}
	return m
}

func sample(ids []string, n int) []string {
	if len(ids) > n {
		ids = ids[:n]
	}
	if ids == nil {
		return []string{}
	}
	return ids
}

// envInt reads a positive integer from the environment, or returns def.
func envInt(name string, def int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(2)
}
