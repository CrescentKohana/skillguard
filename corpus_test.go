package skillguard_test

import (
	"os"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/rules"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestOwnBenignCorpusHasZeroFindings exercises every file kind with realistic
// clean content. See testdata/benign/ for the fixtures.
func TestOwnBenignCorpusHasZeroFindings(t *testing.T) {
	res, err := scan.Scan([]string{"testdata/benign"})
	if err != nil {
		t.Fatalf("Scan(testdata/benign): unexpected error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("testdata/benign corpus produced findings, want zero: %+v", res.Findings)
	}
	if res.Suppressed != 0 {
		t.Fatalf("testdata/benign corpus relies on suppression (%d suppressed); the corpus must be clean without it", res.Suppressed)
	}
	if res.Files == 0 {
		t.Fatalf("testdata/benign corpus scanned zero files; the fixture set is missing")
	}
}

// TestRepoExamplesBenignHasZeroFindings covers acceptance criterion 10: the
// distributed examples/benign corpus must produce zero findings.
func TestRepoExamplesBenignHasZeroFindings(t *testing.T) {
	root := "examples/benign"
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("%s must exist per the spec's distribution section: %v", root, err)
	}
	res, err := scan.Scan([]string{root})
	if err != nil {
		t.Fatalf("Scan(%s): unexpected error: %v", root, err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("%s produced findings, want zero: %+v", root, res.Findings)
	}
	if res.Suppressed != 0 {
		t.Fatalf("%s relies on suppression (%d suppressed); it must be clean without it", root, res.Suppressed)
	}
}

// TestRepoExamplesMaliciousCoversEveryRule covers acceptance criterion 10: the
// distributed examples/malicious corpus must contain at least one sample per
// rule ID, for the README demo.
func TestRepoExamplesMaliciousCoversEveryRule(t *testing.T) {
	root := "examples/malicious"
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("%s must exist per the spec's distribution section: %v", root, err)
	}
	res, err := scan.Scan([]string{root})
	if err != nil {
		t.Fatalf("Scan(%s): unexpected error: %v", root, err)
	}

	counts := make(map[string]int)
	for _, f := range res.Findings {
		counts[f.RuleID]++
	}
	for _, r := range rules.All() {
		if counts[r.ID] == 0 {
			t.Errorf("%s has no sample triggering rule %s (%s)", root, r.ID, r.Name)
		}
	}
}
