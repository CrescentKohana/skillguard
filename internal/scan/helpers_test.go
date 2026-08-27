package scan_test

import (
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

func hasRule(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func findRule(t *testing.T, fs []finding.Finding, id string) finding.Finding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == id {
			return f
		}
	}
	t.Fatalf("no finding with RuleID %s among %+v", id, fs)
	return finding.Finding{}
}

func countRule(fs []finding.Finding, id string) int {
	n := 0
	for _, f := range fs {
		if f.RuleID == id {
			n++
		}
	}
	return n
}

// encodeTag renders s (printable ASCII, 0x20-0x7E) as Unicode Tag characters
// (U+E0020-U+E007E), the smuggling encoding SG003 must decode.
func encodeTag(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteRune(0xE0000 + r)
	}
	return b.String()
}
