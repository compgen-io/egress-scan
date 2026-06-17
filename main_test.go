package main

import (
	"testing"

	"github.com/compgen-io/egress-scan/internal/approved"
	"github.com/compgen-io/egress-scan/internal/scan"
)

func TestBuildReportPerFileRisk(t *testing.T) {
	res := &scan.Result{
		EgressIDs: map[string]struct{}{"IB-1": {}, "IB-2": {}},
		Findings: []scan.Finding{
			{Path: "a.csv", ID: "IB-1", Format: "csv", Via: "regex"}, // novel
			{Path: "a.csv", ID: "IB-2", Format: "csv", Via: "regex"}, // approved
		},
		Grids: []scan.GridInfo{
			{Path: "big.csv", Format: "csv", Rows: 500, Cols: 3, Area: 1500},
		},
		Images: []scan.ImageInfo{
			{Path: "doc.pdf#image1", Format: "png", Source: "pdf", Noise: 0.9, Flagged: true},
		},
	}
	approvedSet := map[string]struct{}{"IB-2": {}}

	rep := buildReport(res, approvedSet, approved.Source{Kind: "ids_file", Count: 1}, DefaultHighRiskThreshold, 10*1024*1024)

	byPath := map[string]FileRisk{}
	for _, fr := range rep.FileRisks {
		byPath[fr.Path] = fr
	}

	// Big table -> data-volume drives it to 100 (500 rows >> RowsFullRisk).
	if got := byPath["big.csv"]; got.Risk != 100 || got.DataVolumeRisk != 100 {
		t.Errorf("big.csv: got %+v, want risk/data 100", got)
	}
	// PDF-embedded image rolls up to doc.pdf at image risk 90.
	if got := byPath["doc.pdf"]; got.Risk != 90 || got.ImageRisk != 90 {
		t.Errorf("doc.pdf: got %+v, want risk/image 90", got)
	}
	// a.csv: 1 novel of 2 IDs -> novel ratio 0.5 -> IB score 35.
	if got := byPath["a.csv"]; got.IBRisk != 35 || got.Risk != 35 {
		t.Errorf("a.csv: got %+v, want ib/risk 35", got)
	}

	if rep.TotalRisk != 100 {
		t.Errorf("total risk = %d, want 100", rep.TotalRisk)
	}
	// big.csv, doc.pdf, a.csv all exceed the threshold of 30.
	if len(rep.HighRiskFiles) != 3 {
		t.Errorf("high-risk files = %d (%v), want 3", len(rep.HighRiskFiles), rep.HighRiskFiles)
	}
	if rep.HighRiskFiles[0].Path != "big.csv" {
		t.Errorf("highest-risk file = %q, want big.csv", rep.HighRiskFiles[0].Path)
	}

	// A higher threshold (80) drops the 35-risk file, keeping big.csv (100) and
	// doc.pdf (90).
	repHi := buildReport(res, approvedSet, approved.Source{Kind: "ids_file", Count: 1}, 80, 10*1024*1024)
	if len(repHi.HighRiskFiles) != 2 {
		t.Errorf("threshold 80: high-risk files = %d (%v), want 2", len(repHi.HighRiskFiles), repHi.HighRiskFiles)
	}
}

func TestBuildReportPickleAutoFlag(t *testing.T) {
	res := &scan.Result{
		EgressIDs: map[string]struct{}{},
		Flagged: []scan.FlaggedFile{
			{Path: "m/model.pkl", Format: "pkl", Risk: AutoFlagRisk, Reason: "python pickle — opaque"},
		},
	}
	rep := buildReport(res, map[string]struct{}{}, approved.Source{Kind: "none"}, DefaultHighRiskThreshold, 10*1024*1024)

	if len(rep.FileRisks) != 1 || rep.FileRisks[0].Risk != AutoFlagRisk {
		t.Fatalf("expected one file at risk %d; got %v", AutoFlagRisk, rep.FileRisks)
	}
	if rep.FileRisks[0].Reason == "" {
		t.Errorf("expected a reason on the auto-flagged pickle; got %+v", rep.FileRisks[0])
	}
	if rep.TotalRisk != AutoFlagRisk {
		t.Errorf("total risk = %d, want %d (pickle present)", rep.TotalRisk, AutoFlagRisk)
	}
	if len(rep.HighRiskFiles) != 1 {
		t.Errorf("pickle should be a high-risk file; got %v", rep.HighRiskFiles)
	}
}

func TestBuildReportLowRisk(t *testing.T) {
	res := &scan.Result{
		EgressIDs: map[string]struct{}{"IB-2": {}},
		Findings:  []scan.Finding{{Path: "a.csv", ID: "IB-2"}},
	}
	rep := buildReport(res, map[string]struct{}{"IB-2": {}}, approved.Source{Kind: "ids_file"}, DefaultHighRiskThreshold, 10*1024*1024)
	if len(rep.HighRiskFiles) != 0 {
		t.Errorf("expected no high-risk files for an all-approved tar; got %v", rep.HighRiskFiles)
	}
	if rep.TotalRisk > DefaultHighRiskThreshold {
		t.Errorf("total risk %d should be <= threshold for all-approved IDs", rep.TotalRisk)
	}
}
