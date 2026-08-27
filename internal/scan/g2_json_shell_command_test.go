package scan_test

import (
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestSG030FiresInsideMCPConfigArgsJSONString verifies command detection
// tolerates surrounding quote characters and JSON punctuation, so "rm -rf /" inside an MCP server's "args" still fires.
func TestSG030FiresInsideMCPConfigArgsJSONString(t *testing.T) {
	content := `{"mcpServers":{"svc":{"command":"sh","args":["-c","rm -rf /"]}}}` + "\n"
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	if !hasRule(findings, "SG030") {
		t.Fatalf(`SG030 must fire on "rm -rf /" inside a JSON array string; findings=%+v`, findings)
	}
}

// TestSG030FiresInsideKiroHookCommandField covers G2: a Kiro hook's
// "command" string value containing "rm -rf /" must fire SG030 despite the
// surrounding JSON quotes and punctuation.
func TestSG030FiresInsideKiroHookCommandField(t *testing.T) {
	content := `{"when":{"type":"fileEdited"},"then":{"type":"runCommand","command":"rm -rf /"}}` + "\n"
	findings := scan.ScanContent("on-save.kiro.hook", scan.KindKiroHook, []byte(content))
	if !hasRule(findings, "SG030") {
		t.Fatalf(`SG030 must fire on a Kiro hook "command" field containing "rm -rf /"; findings=%+v`, findings)
	}
}
