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

// Report is the JSON document written to --out (or stdout).
type Report struct {
	Recommendation string           `json:"recommendation"`
	RiskScore      int              `json:"risk_score"`
	RiskLevel      string           `json:"risk_level"`
	Summary        string           `json:"summary"`
	Reasons        []string         `json:"reasons"`
	IBIDScan       IBIDScan         `json:"ib_id_scan"`
	DataVolume     DataVolume       `json:"data_volume"`
	ImageAnalysis  ImageAnalysis    `json:"image_analysis"`
	Findings       []scan.Finding   `json:"findings"`
	Unscanned      []scan.Unscanned `json:"unscanned"`
	ScanStats      scan.Stats       `json:"scan_stats"`
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

	// Non-zero exit on a definite concern so the workflow step can gate.
	if report.IBIDScan.NovelIBIDCount > 0 ||
		report.ImageAnalysis.FlaggedCount > 0 ||
		report.DataVolume.AreaRisk >= 1.0 {
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

	areaRisk := grid.Risk(res.TotalArea)
	flaggedImages := 0
	for _, im := range res.Images {
		if im.Flagged {
			flaggedImages++
		}
	}

	return Report{
		Recommendation: recommendation(recSignals{
			novel:         len(novel),
			totalIDs:      len(res.EgressIDs),
			unscanned:     len(res.Unscanned),
			totalArea:     res.TotalArea,
			areaRisk:      areaRisk,
			flaggedImages: flaggedImages,
		}),
		RiskScore: assessment.Score,
		RiskLevel: assessment.Level,
		Summary:   assessment.Summary,
		Reasons:   assessment.Reasons,
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
			AreaRisk:  round2(areaRisk),
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

// recSignals collects the cross-dimension signals that drive the recommendation.
type recSignals struct {
	novel         int
	totalIDs      int
	unscanned     int
	totalArea     int
	areaRisk      float64
	flaggedImages int
}

// recommendation is the plain-text answer, combining the IB-ID, data-volume, and
// image-noise dimensions.
func recommendation(s recSignals) string {
	var concerns []string
	if s.novel > 0 {
		concerns = append(concerns, fmt.Sprintf("%d novel IB-ID(s) not in approved datasets", s.novel))
	}
	if s.areaRisk >= 0.5 {
		concerns = append(concerns, fmt.Sprintf("large data volume (total grid area %d, area-risk %.2f) — likely a data dump rather than aggregate results", s.totalArea, s.areaRisk))
	}
	if s.flaggedImages > 0 {
		concerns = append(concerns, fmt.Sprintf("%d image(s) look like data encoded as pixels", s.flaggedImages))
	}

	if len(concerns) > 0 {
		return "Check this file before release — " + strings.Join(concerns, "; ") + ". Manual review required."
	}
	if s.totalIDs > 0 {
		return fmt.Sprintf("IB-IDs were found but all %d match approved datasets; review recommended before release.", s.totalIDs)
	}
	if s.unscanned > 0 {
		return fmt.Sprintf("No IB-IDs detected in scanned content, but %d file(s) could not be scanned — manual review recommended.", s.unscanned)
	}
	return "No IB-IDs, oversized data grids, or noisy images detected; low risk."
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

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
