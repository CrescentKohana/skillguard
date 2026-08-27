package scan_test

import (
	"testing"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

func TestSG002EachCodePoint(t *testing.T) {
	cases := []struct {
		name string
		r    rune
	}{
		{"U+202A LRE", '\u202A'},
		{"U+202B RLE", '\u202B'},
		{"U+202C PDF", '\u202C'},
		{"U+202D LRO", '\u202D'},
		{"U+202E RLO", '\u202E'},
		{"U+2066 LRI", '\u2066'},
		{"U+2067 RLI", '\u2067'},
		{"U+2068 FSI", '\u2068'},
		{"U+2069 PDI", '\u2069'},
		{"U+200E LRM", '\u200E'},
		{"U+200F RLM", '\u200F'},
		{"U+061C ALM", '\u061C'},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := "visible" + string(tc.r) + "text"
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
			f := findRule(t, findings, "SG002")
			if f.Severity != finding.SeverityHigh {
				t.Errorf("SG002 default severity: got %v, want high", f.Severity)
			}
			if f.Line != 1 {
				t.Errorf("SG002 Line = %d, want 1", f.Line)
			}
		})
	}
}

func TestSG002OneFindingPerLine(t *testing.T) {
	line := "a\u202Ab\u2066c"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	if n := countRule(findings, "SG002"); n != 1 {
		t.Fatalf("expected exactly one SG002 finding per line, got %d: %+v", n, findings)
	}
}

func TestSG002DoesNotFireOnPlainText(t *testing.T) {
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte("just plain ascii text\n"))
	if hasRule(findings, "SG002") {
		t.Fatalf("SG002 must not fire on plain ASCII text; findings=%+v", findings)
	}
}
