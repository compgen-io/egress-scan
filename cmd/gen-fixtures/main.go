// Command gen-fixtures writes the sample egress tar, approved-ID list, and a
// standalone OCR sample PNG into a directory (default ./testdata) so they can be
// scanned by hand. Wired into the Makefile as `make fixtures`.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/compgen-io/egress-scan/internal/fixtures"
)

func main() {
	dir := flag.String("dir", "testdata", "directory to write fixtures into")
	flag.Parse()

	if err := fixtures.WriteTestdata(*dir); err != nil {
		fmt.Fprintf(os.Stderr, "gen-fixtures: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s/egress-sample.tar, %s/approved.txt, %s/ocr-sample.png\n", *dir, *dir, *dir)
}
