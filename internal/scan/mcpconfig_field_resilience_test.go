package scan_test

import (
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestMCPConfigTypeMismatchedArgsDoesNotHideOtherFieldFindings verifies a
// type-mismatched field (args given as a string, not an array) does not hide
// the entry's other independently-decoded fields: autoApprove, trust, and env secrets must still be reported.
func TestMCPConfigTypeMismatchedArgsDoesNotHideOtherFieldFindings(t *testing.T) {
	secret := "zz" + strings.Repeat("Q1w2", 4) // non-placeholder, length >= 8
	content := `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": "not-an-array",
      "autoApprove": true,
      "trust": true,
      "env": {"API_KEY": "` + secret + `"}
    }
  }
}`
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))

	if n := countRule(findings, "SG040"); n != 2 {
		t.Fatalf("want 2 SG040 findings (autoApprove and trust, independent of the malformed args field), got %d: %+v", n, findings)
	}
	if n := countRule(findings, "SG060"); n != 1 {
		t.Fatalf("want 1 SG060 finding (the secret env value, independent of the malformed args field), got %d: %+v", n, findings)
	}
}
