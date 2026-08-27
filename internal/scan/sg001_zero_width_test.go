package scan_test

import (
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

func TestSG001EachCodePoint(t *testing.T) {
	cases := []struct {
		name string
		r    rune
	}{
		{"U+200B zero-width-space", '\u200B'},
		{"U+200C zero-width-non-joiner", '\u200C'},
		{"U+200D zero-width-joiner (not emoji)", '\u200D'},
		{"U+2060 word-joiner", '\u2060'},
		{"U+2061 function-application", '\u2061'},
		{"U+2062 invisible-times", '\u2062'},
		{"U+2063 invisible-separator", '\u2063'},
		{"U+2064 invisible-plus", '\u2064'},
		{"U+00AD soft-hyphen", '\u00AD'},
		{"U+180E mongolian-vowel-separator", '\u180E'},
		{"U+3164 hangul-filler", '\u3164'},
		{"U+115F hangul-choseong-filler", '\u115F'},
		{"U+1160 hangul-jungseong-filler", '\u1160'},
		{"U+FFA0 halfwidth-hangul-filler", '\uFFA0'},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := "visible" + string(tc.r) + "text"
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
			if !hasRule(findings, "SG001") {
				t.Fatalf("rune %U: SG001 did not fire for line %q; findings=%+v", tc.r, line, findings)
			}
		})
	}
}

func TestSG001MidFileBOMReported(t *testing.T) {
	content := "line one\nline two" + "\uFEFF" + " more\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	f := findRule(t, findings, "SG001")
	if f.Line != 2 {
		t.Fatalf("mid-file U+FEFF: Line = %d, want 2", f.Line)
	}
}

func TestSG001LeadingBOMIgnored(t *testing.T) {
	content := "\uFEFF" + "clean first line\nclean second line\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	if hasRule(findings, "SG001") {
		t.Fatalf("leading BOM must be ignored, got findings=%+v", findings)
	}
}

func TestSG001EmojiZWJExceptionNotReported(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"man-zwj-woman", "\U0001F468\u200D\U0001F469"},
		{"heart-fe0f-zwj-fire", "\u2764\uFE0F\u200D\U0001F525"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(tc.line+"\n"))
			if hasRule(findings, "SG001") {
				t.Fatalf("emoji ZWJ sequence %q must not trigger SG001; findings=%+v", tc.line, findings)
			}
		})
	}
}

func TestSG001ZWJBetweenNonPictographicIsReported(t *testing.T) {
	line := "a\u200Db"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	if !hasRule(findings, "SG001") {
		t.Fatalf("ZWJ between plain letters must still trigger SG001; findings=%+v", findings)
	}
}

func TestSG001ColumnIsRuneBasedAfterMultibyteChars(t *testing.T) {
	content := "first line is plain\n" + "h\u00E9llo\u200Bworld\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	f := findRule(t, findings, "SG001")
	if f.Line != 2 {
		t.Fatalf("Line = %d, want 2", f.Line)
	}
	if f.Column != 6 {
		t.Fatalf("Column = %d, want 6 (rune index of U+200B after h-\u00e9-l-l-o)", f.Column)
	}
}

func TestSG001OneFindingPerLineWithCount(t *testing.T) {
	line := "a\u200Bb\u200Bc\u200Cd"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	if n := countRule(findings, "SG001"); n != 1 {
		t.Fatalf("expected exactly one SG001 finding per line, got %d: %+v", n, findings)
	}
	f := findRule(t, findings, "SG001")
	if !strings.Contains(f.Message, "3") {
		t.Errorf("message %q does not mention the total occurrence count 3", f.Message)
	}
	if !strings.Contains(f.Message, "U+200B") || !strings.Contains(f.Message, "U+200C") {
		t.Errorf("message %q does not list both distinct code points U+200B and U+200C", f.Message)
	}
	if f.Column != 2 {
		t.Fatalf("Column = %d, want 2 (first occurrence)", f.Column)
	}
}
