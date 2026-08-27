package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/cli"
	"github.com/CrescentKohana/skillguard/internal/finding"
)

func run(args ...string) (stdout, stderr string, code int) {
	var out, errOut bytes.Buffer
	code = cli.Run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// severityFixture returns a temp root directory containing exactly one
// classified file that produces exactly one finding at the given severity.
func severityFixture(t *testing.T, sev finding.Severity) string {
	t.Helper()
	root := t.TempDir()
	switch sev {
	case finding.SeverityLow:
		writeFile(t, filepath.Join(root, ".mcp.json"), `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
      "autoApprove": ["readFile", "listFiles"]
    }
  }
}`)
	case finding.SeverityMedium:
		writeFile(t, filepath.Join(root, ".mcp.json"), `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "left-pad"]
    }
  }
}`)
	case finding.SeverityHigh:
		writeFile(t, filepath.Join(root, "AGENTS.md"), "a\u200Bb\n")
	case finding.SeverityCritical:
		secret := "AKIA" + strings.Repeat("A1B2", 4)
		writeFile(t, filepath.Join(root, "AGENTS.md"), "token="+secret+"\n")
	default:
		t.Fatalf("severityFixture: unsupported severity %v", sev)
	}
	return root
}

func severityRank(sev finding.Severity) int { return int(sev) }

func TestRunScanExitCodeMatrixByFailOn(t *testing.T) {
	failOns := []string{"info", "low", "medium", "high", "critical", "none"}
	tiers := []finding.Severity{
		finding.SeverityLow, finding.SeverityMedium, finding.SeverityHigh, finding.SeverityCritical,
	}

	for _, tier := range tiers {
		root := severityFixture(t, tier)
		for _, failOn := range failOns {
			t.Run(tier.String()+"_failOn_"+failOn, func(t *testing.T) {
				_, stderr, code := run("scan", "--format", "json", "--fail-on", failOn, root)

				wantCode := 0
				if failOn != "none" {
					threshold, err := finding.ParseSeverity(failOn)
					if err != nil {
						t.Fatalf("test setup: ParseSeverity(%q): %v", failOn, err)
					}
					if severityRank(tier) >= severityRank(threshold) {
						wantCode = 1
					}
				}
				if code != wantCode {
					t.Fatalf("finding severity=%s fail-on=%s: exit code = %d, want %d; stderr=%q", tier, failOn, code, wantCode, stderr)
				}
			})
		}
	}
}

func TestRunScanJSONFormat(t *testing.T) {
	root := severityFixture(t, finding.SeverityHigh)
	stdout, stderr, code := run("scan", "--format", "json", root)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (default fail-on is medium, high >= medium); stderr=%q", code, stderr)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v; stdout=%q", err, stdout)
	}
	if doc["tool"] != "skillguard" {
		t.Errorf(`doc["tool"] = %v, want "skillguard"`, doc["tool"])
	}
}

func TestRunScanTextFormatDefault(t *testing.T) {
	root := severityFixture(t, finding.SeverityHigh)
	stdout, _, _ := run("scan", root)
	if !strings.Contains(stdout, "SG001") {
		t.Fatalf("default text output does not mention SG001: %q", stdout)
	}
}

func TestRunScanOutputFlagWritesFile(t *testing.T) {
	root := severityFixture(t, finding.SeverityHigh)
	outFile := filepath.Join(t.TempDir(), "report.json")

	stdout, stderr, code := run("scan", "--format", "json", "--output", outFile, root)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, stderr)
	}

	data, err := os.ReadFile(outFile) //nolint:gosec // G304: outFile is a path this test created under t.TempDir(), not external input
	if err != nil {
		t.Fatalf("--output file was not created: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("--output file is not valid JSON: %v; content=%q", err, data)
	}
	if doc["tool"] != "skillguard" {
		t.Errorf(`doc["tool"] = %v, want "skillguard"`, doc["tool"])
	}

	if strings.TrimSpace(stdout) != "" {
		t.Errorf("stdout should be empty when --output redirects the report to a file, got %q", stdout)
	}

	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("Stat(%q): %v", outFile, err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("--output file mode = %o, want 0644", perm)
	}
}

func TestRunScanOutputFlagReplacesExistingFile(t *testing.T) {
	root := severityFixture(t, finding.SeverityHigh)
	outFile := filepath.Join(t.TempDir(), "report.json")
	writeFile(t, outFile, "stale content that must be fully replaced, not appended")

	_, stderr, code := run("scan", "--format", "json", "--output", outFile, root)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, stderr)
	}
	data, err := os.ReadFile(outFile) //nolint:gosec // G304: outFile is a path this test created under t.TempDir(), not external input
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "stale content") {
		t.Fatalf("--output must replace the file's prior content, got %q", data)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("replaced file is not valid JSON: %v", err)
	}
}

func TestRunScanDefaultPathIsCurrentDirectory(t *testing.T) {
	root := severityFixture(t, finding.SeverityHigh)
	t.Chdir(root)

	stdout, stderr, code := run("scan", "--format", "json")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "SG001") {
		t.Fatalf("scanning the default path \".\" did not find the fixture's SG001 finding: %q", stdout)
	}
}

func TestRunScanNonexistentPathIsExit2(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, stderr, code := run("scan", missing)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 for a nonexistent path; stderr=%q", code, stderr)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Fatalf("expected an error message on stderr for a nonexistent path")
	}
}

func TestRunScanInvalidFailOnIsExit2(t *testing.T) {
	root := severityFixture(t, finding.SeverityHigh)
	_, stderr, code := run("scan", "--fail-on", "catastrophic", root)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 for an invalid --fail-on value; stderr=%q", code, stderr)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Fatalf("expected an error message on stderr for an invalid --fail-on value")
	}
}

func TestRunUnknownCommandIsExit2(t *testing.T) {
	_, stderr, code := run("frobnicate")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 for an unknown command; stderr=%q", code, stderr)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Fatalf("expected an error message on stderr for an unknown command")
	}
}

func TestRunUnknownFlagIsExit2(t *testing.T) {
	root := severityFixture(t, finding.SeverityHigh)
	_, stderr, code := run("scan", "--does-not-exist", root)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 for an unknown flag; stderr=%q", code, stderr)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Fatalf("expected an error message on stderr for an unknown flag")
	}
}

func TestRunRulesTextFormat(t *testing.T) {
	stdout, stderr, code := run("rules")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	for _, want := range []string{"SG001", "SG060", "high", "critical"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("rules output does not contain %q: %q", want, stdout)
		}
	}
}

func TestRunRulesJSONFormat(t *testing.T) {
	stdout, stderr, code := run("rules", "--format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	var docs []map[string]any
	if err := json.Unmarshal([]byte(stdout), &docs); err != nil {
		t.Fatalf("rules --format json output is not a JSON array: %v; stdout=%q", err, stdout)
	}
	if len(docs) != 11 {
		t.Fatalf("len(rules json) = %d, want 11", len(docs))
	}
}

func TestRunVersion(t *testing.T) {
	stdout, stderr, code := run("version")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, cli.Version) {
		t.Fatalf("version output %q does not contain cli.Version %q", stdout, cli.Version)
	}
}

func TestRunHelp(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := run(args...)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
			}
			for _, want := range []string{"scan", "rules", "version"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("help output does not mention command %q: %q", want, stdout)
				}
			}
		})
	}
}
