// Package approved loads the set of approved IB-IDs that egress IDs are compared
// against. Sources, in order of use: an explicit IDs file, a directory of
// approved dataset files, and the APPROVED_IB_IDS environment variable.
//
// S3 is intentionally left out of the binary: as a separate workflow step, the
// approved dataset is materialised locally (or an ID list is passed in) before
// this tool runs, which keeps the binary dependency-light and offline.
package approved

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/compgen-io/egress-scan/internal/idmatch"
)

// Source describes where approved IDs came from, surfaced in the output.
type Source struct {
	Kind  string // "ids_file", "approved_dir", "env_list", or "none"
	Count int
}

// Load gathers approved IDs from the first configured source. idsFile is a flat
// text file of IDs (any text; IDs are regex-extracted). dir is a directory whose
// files are scanned for IDs. Either or both may be empty.
func Load(m *idmatch.Matcher, idsFile, dir string) (map[string]struct{}, Source, error) {
	ids := make(map[string]struct{})

	if idsFile != "" {
		data, err := os.ReadFile(idsFile)
		if err != nil {
			return nil, Source{}, err
		}
		for id := range m.IBIDs(string(data)) {
			ids[id] = struct{}{}
		}
		// A bare ID list (one per line) may not match the \bIB\d+\b shape if the
		// file lists raw tokens; also fold in normalised non-empty lines.
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for id := range m.IBIDs(line) {
				ids[id] = struct{}{}
			}
		}
		return ids, Source{Kind: "ids_file", Count: len(ids)}, nil
	}

	if dir != "" {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil // best effort; skip unreadable files
			}
			for id := range m.IBIDs(string(data)) {
				ids[id] = struct{}{}
			}
			return nil
		})
		if err != nil {
			return nil, Source{}, err
		}
		return ids, Source{Kind: "approved_dir", Count: len(ids)}, nil
	}

	if raw := strings.TrimSpace(os.Getenv("APPROVED_IB_IDS")); raw != "" {
		for _, tok := range strings.Split(raw, ",") {
			for id := range m.IBIDs(tok) {
				ids[id] = struct{}{}
			}
		}
		return ids, Source{Kind: "env_list", Count: len(ids)}, nil
	}

	return ids, Source{Kind: "none", Count: 0}, nil
}
