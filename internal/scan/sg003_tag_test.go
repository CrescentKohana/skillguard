package scan_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

func TestSG003DecodesHiddenASCIIText(t *testing.T) {
	hidden := "rm -rf /"
	line := "Click here" + encodeTag(hidden) + " to install"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	f := findRule(t, findings, "SG003")
	want := `hidden text: "` + hidden + `"`
	if !strings.Contains(f.Message, want) {
		t.Fatalf("message %q does not contain %q", f.Message, want)
	}
}

func TestSG003DecodedTextTruncatedTo200Chars(t *testing.T) {
	hidden := strings.Repeat("A", 250)
	line := "payload" + encodeTag(hidden)
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	f := findRule(t, findings, "SG003")

	want200 := strings.Repeat("A", 200)
	want201 := strings.Repeat("A", 201)
	if !strings.Contains(f.Message, want200) {
		t.Fatalf("message does not contain the 200-char truncated decoded text: %q", f.Message)
	}
	if strings.Contains(f.Message, want201) {
		t.Fatalf("message contains more than 200 decoded characters, want truncation: %q", f.Message)
	}
}

func TestSG003VariationSelectorsFireWithoutDecoding(t *testing.T) {
	// U+E0100-U+E01EF are variation selectors 17-256; they do not fall in the
	// U+E0020-U+E007E decode range but must still be reported as smuggled content.
	cases := []rune{0xE0100, 0xE0150, 0xE01EF}
	for _, r := range cases {
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			line := "visible" + string(r) + "text"
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
			if !hasRule(findings, "SG003") {
				t.Fatalf("variation selector %U must trigger SG003; findings=%+v", r, findings)
			}
		})
	}
}

func TestSG003TagBlockBoundaryCharactersFire(t *testing.T) {
	cases := []rune{0xE0000, 0xE007F}
	for _, r := range cases {
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			line := "visible" + string(r) + "text"
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
			if !hasRule(findings, "SG003") {
				t.Fatalf("tag character %U must trigger SG003; findings=%+v", r, findings)
			}
		})
	}
}

func TestSG003NotSuppressibleBySameLineComment(t *testing.T) {
	line := "x" + encodeTag("evil") + " <!-- skillguard-ignore SG003 -->"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	if !hasRule(findings, "SG003") {
		t.Fatalf("SG003 must never be suppressible, even with a matching ignore comment; findings=%+v", findings)
	}
}

func TestSG003NotSuppressibleByPrecedingLine(t *testing.T) {
	content := "<!-- skillguard-ignore SG003 -->\nx" + encodeTag("evil") + "\n"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
	if !hasRule(findings, "SG003") {
		t.Fatalf("SG003 must never be suppressible from the preceding line either; findings=%+v", findings)
	}
}

func TestSG003MustNotFire(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"plain-text", "This is an entirely ordinary sentence about the build."},
		{"ordinary-emoji", "Great job \U0001F44D today, team!"},
		{"ordinary-emoji-with-variation-selector-16", "Nice \u2764\uFE0F work on this PR"},
		{"cjk-japanese", "これは日本語のテキストです。"},
		{"cjk-chinese", "这是一个普通的中文句子。"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(tc.line+"\n"))
			if hasRule(findings, "SG003") {
				t.Fatalf("line %q must not trigger SG003; findings=%+v", tc.line, findings)
			}
		})
	}
}
