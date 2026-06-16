// Package risk ports the advisory scoring model from risk_scoring.py (_score_risk)
// so the Go tool produces a comparable 0-100 score and LOW/MEDIUM/HIGH level.
package risk

import (
	"fmt"
	"math"
)

// Assessment is the scored outcome plus human-readable context.
type Assessment struct {
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Summary string   `json:"summary"`
	Reasons []string `json:"reasons"`
}

// Inputs collects the signals that drive the score.
type Inputs struct {
	TotalEgressIDs int // distinct IB-IDs found in the tar
	OverlapIDs     int // IB-IDs that also appear in approved datasets
	NovelIDs       int // IB-IDs NOT in approved datasets
	PHIMatches     int // SSN/DOB/phone pattern hits (advisory screening)
	UnscannedFiles int // files that could not be scanned and need manual review
}

// Assess computes the advisory score. Model mirrors risk_scoring.py:
//   - base = round((novel / total) * 70)
//   - +20 when content screening flags PHI patterns
//   - +10 when there are files needing manual review
//   - capped at 100; LOW < 25, MEDIUM 25-59, HIGH >= 60.
func Assess(in Inputs) Assessment {
	var reasons []string
	base := 0.0

	if in.TotalEgressIDs == 0 {
		reasons = append(reasons, "No IB-style IDs detected in scanned tar content.")
	} else {
		novelRatio := float64(in.NovelIDs) / float64(in.TotalEgressIDs)
		base = math.Round(novelRatio * 70)
		reasons = append(reasons, fmt.Sprintf(
			"Detected %d IB-style ID(s); %d not found in approved datasets.",
			in.TotalEgressIDs, in.NovelIDs))
		if in.OverlapIDs > 0 {
			reasons = append(reasons, fmt.Sprintf(
				"%d ID(s) overlap with approved datasets.", in.OverlapIDs))
		}
	}

	if in.PHIMatches > 0 {
		base += 20
		reasons = append(reasons, fmt.Sprintf(
			"Content screening matched %d potential PHI value(s) (SSN/DOB/phone).",
			in.PHIMatches))
	}

	if in.UnscannedFiles > 0 {
		base += 10
		reasons = append(reasons, fmt.Sprintf(
			"%d file(s) could not be scanned and require manual review.",
			in.UnscannedFiles))
	}

	score := int(base)
	if score > 100 {
		score = 100
	}

	level := "LOW"
	switch {
	case score >= 60:
		level = "HIGH"
	case score >= 25:
		level = "MEDIUM"
	}

	return Assessment{
		Score:   score,
		Level:   level,
		Summary: fmt.Sprintf("Advisory PHI risk score %d/100 (%s) based on IB-ID overlap and content screening signals.", score, level),
		Reasons: reasons,
	}
}
