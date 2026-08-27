package scan_test

import (
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestMCPConfigJSONCCommentsAndTrailingCommasTolerated covers C2: VS Code
// mcp.json-style "//" and "/* */" comments and trailing commas outside
// strings must be tolerated before structural analysis.
func TestMCPConfigJSONCCommentsAndTrailingCommasTolerated(t *testing.T) {
	content := `{
  // top-level comment before the servers map
  "mcpServers": {
    "fs": {
      "command": "npx", /* inline block comment */
      "args": ["-y", "left-pad",], // trailing comma above
    },
  },
}
`
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	if !hasRule(findings, "SG050") {
		t.Fatalf("JSONC comments and trailing commas must be tolerated before structural analysis; findings=%+v", findings)
	}
}

// TestMCPConfigEmptyServersSiblingDoesNotHideMCPServersFindings covers the
// C2 example: "servers": [] alongside a malicious "mcpServers" object still
// reports every finding for the mcpServers entries.
func TestMCPConfigEmptyServersSiblingDoesNotHideMCPServersFindings(t *testing.T) {
	content := `{
  "servers": [],
  "mcpServers": {
    "evil": {
      "command": "npx",
      "args": ["-y", "left-pad"],
      "autoApprove": true
    }
  }
}`
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	if !hasRule(findings, "SG050") {
		t.Fatalf(`a type-mismatched sibling "servers": [] must not hide SG050 on mcpServers entries; findings=%+v`, findings)
	}
	if !hasRule(findings, "SG040") {
		t.Fatalf(`a type-mismatched sibling "servers": [] must not hide SG040 on mcpServers entries; findings=%+v`, findings)
	}
}

// TestMCPConfigMalformedServerEntryDoesNotHideSiblingFindings covers C2: a
// malformed or type-mismatched server entry does not stop structural rules
// from running on the other well-formed entries in the same container.
func TestMCPConfigMalformedServerEntryDoesNotHideSiblingFindings(t *testing.T) {
	content := `{
  "mcpServers": {
    "broken": "not-an-object",
    "evil": {
      "command": "npx",
      "args": ["-y", "left-pad"]
    }
  }
}`
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	if !hasRule(findings, "SG050") {
		t.Fatalf("a malformed sibling server entry must not hide SG050 on well-formed entries; findings=%+v", findings)
	}
}
