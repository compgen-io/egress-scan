// Package idmatch holds the IB-ID and PHI pattern matchers shared by all scanners.
//
// The IB-ID pattern and normalisation mirror risk_scoring.py so that the Go tool
// produces the same canonical IDs as the existing Python worker.
package idmatch

import (
	"regexp"
	"strings"
)

// DefaultIBPattern matches internal biobank identifiers, e.g. IB1234, IB-1234,
// IB_1234. Mirrors _DEFAULT_IB_ID_PATTERN in risk_scoring.py.
const DefaultIBPattern = `\bIB[_-]?\d+\b`

// Matcher compiles the IB-ID pattern plus the advisory PHI patterns ported from
// worker.py (_PHI_PATTERNS): SSN, slash-SSN, DOB, and phone numbers.
type Matcher struct {
	ib  *regexp.Regexp
	phi []*regexp.Regexp
}

// New compiles a Matcher. An empty pattern falls back to DefaultIBPattern. The
// IB pattern is matched case-insensitively, matching re.IGNORECASE in Python.
func New(ibPattern string) (*Matcher, error) {
	if strings.TrimSpace(ibPattern) == "" {
		ibPattern = DefaultIBPattern
	}
	ib, err := regexp.Compile("(?i)" + ibPattern)
	if err != nil {
		return nil, err
	}
	return &Matcher{
		ib: ib,
		phi: []*regexp.Regexp{
			regexp.MustCompile(`\b\d{3}[\s-]+\d{2}[\s-]+\d{4}\b`),                                            // SSN NNN-NN-NNNN
			regexp.MustCompile(`\b\d{3}/\d{2}/\d{4}\b`),                                                      // SSN NNN/NN/NNNN
			regexp.MustCompile(`\b(?:0[1-9]|1[0-2])[\s./-]+(?:0[1-9]|[12]\d|3[01])[\s./-]+(?:19|20)\d{2}\b`), // DOB MM/DD/YYYY
			regexp.MustCompile(`\b\d{3}[-.\s]+\d{3}[-.\s]+\d{4}\b`),                                          // Phone NNN-NNN-NNNN
		},
	}, nil
}

// Normalize canonicalises a raw ID: trim, upper-case, underscores to dashes.
// Mirrors _normalise_id in risk_scoring.py.
func Normalize(raw string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(raw)), "_", "-")
}

// IBIDs returns the set of normalised IB-IDs found in text.
func (m *Matcher) IBIDs(text string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, hit := range m.ib.FindAllString(text, -1) {
		out[Normalize(hit)] = struct{}{}
	}
	return out
}

// PHICount returns how many PHI-pattern matches appear in text. Advisory only.
func (m *Matcher) PHICount(text string) int {
	n := 0
	for _, p := range m.phi {
		n += len(p.FindAllStringIndex(text, -1))
	}
	return n
}
