package scan_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

func TestScanSortsFindingsByPathLineColumnRuleID(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "z", "AGENTS.md"), "rm -rf /\n")
	writeFile(t, filepath.Join(root, "a", "AGENTS.md"), "cat ~/.ssh/id_rsa\nrm -rf /\n")

	res, err := scan.Scan([]string{root})
	if err != nil {
		t.Fatalf("Scan: unexpected error: %v", err)
	}
	if len(res.Findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d: %+v", len(res.Findings), res.Findings)
	}

	for i := 1; i < len(res.Findings); i++ {
		prev, cur := res.Findings[i-1], res.Findings[i]
		if prev.Path > cur.Path {
			t.Fatalf("Findings not sorted by Path: %q appears before %q", prev.Path, cur.Path)
		}
		if prev.Path == cur.Path {
			if prev.Line > cur.Line {
				t.Fatalf("Findings not sorted by Line within %q", prev.Path)
			}
			if prev.Line == cur.Line && prev.Column > cur.Column {
				t.Fatalf("Findings not sorted by Column within %q line %d", prev.Path, prev.Line)
			}
			if prev.Line == cur.Line && prev.Column == cur.Column && prev.RuleID > cur.RuleID {
				t.Fatalf("Findings not sorted by RuleID within %q:%d:%d", prev.Path, prev.Line, prev.Column)
			}
		}
	}
}

func TestScanFilesCount(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "SKILL.md"), "harmless content\n")
	writeFile(t, filepath.Join(root, "AGENTS.md"), "harmless content\n")
	writeFile(t, filepath.Join(root, "README.md"), "not classified, must not count\n")

	res, err := scan.Scan([]string{root})
	if err != nil {
		t.Fatalf("Scan: unexpected error: %v", err)
	}
	if res.Files != 2 {
		t.Fatalf("Result.Files = %d, want 2 (only classified files are scanned)", res.Files)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected zero findings for harmless content, got %+v", res.Findings)
	}
}

func TestScanSkipsOversizeFilesWithoutFindingOrError(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "AGENTS.md")

	const limit = 5 * 1024 * 1024
	payload := strings.Repeat("A", limit+1) + "AKIA" + strings.Repeat("A1B2", 4)
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := scan.Scan([]string{root})
	if err != nil {
		t.Fatalf("Scan: unexpected error for oversize file: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("oversize file must be skipped with no finding, got %+v", res.Findings)
	}
}

func TestScanNonexistentRootIsError(t *testing.T) {
	root := t.TempDir()
	if _, err := scan.Scan([]string{filepath.Join(root, "missing")}); err == nil {
		t.Fatalf("Scan: expected error for nonexistent root, got nil")
	}
}

func TestScanMultipleRootsAggregated(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	writeFile(t, filepath.Join(rootA, "AGENTS.md"), "harmless\n")
	writeFile(t, filepath.Join(rootB, "SKILL.md"), "harmless\n")

	res, err := scan.Scan([]string{rootA, rootB})
	if err != nil {
		t.Fatalf("Scan: unexpected error: %v", err)
	}
	if res.Files != 2 {
		t.Fatalf("Result.Files = %d, want 2 across both roots", res.Files)
	}
}

func TestScanResultPathsAreForwardSlash(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "sub", "AGENTS.md"), "rm -rf /\n")

	res, err := scan.Scan([]string{root})
	if err != nil {
		t.Fatalf("Scan: unexpected error: %v", err)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Path, `\`) {
			t.Fatalf("Finding.Path must use forward slashes, got %q", f.Path)
		}
	}
}

func TestScanSortDeterminismWithSort(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "b", "AGENTS.md"), "")
	writeFile(t, filepath.Join(root, "AGENTS.md"), "")
	writeFile(t, filepath.Join(root, "sub", "AGENTS.md"), "")

	targets, err := scan.Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	paths := make([]string, len(targets))
	for i, tg := range targets {
		paths[i] = tg.Path
	}
	cp := append([]string(nil), paths...)
	sort.Strings(cp)
	for i := range paths {
		if paths[i] != cp[i] {
			t.Fatalf("Discover result order %v is not sorted, want %v", paths, cp)
		}
	}
}
