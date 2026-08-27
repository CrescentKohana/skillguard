package cli_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRunScanWarningsDoNotAffectExitCode covers C2: Scan.Warnings are not
// findings, so an unparsable MCP config that triggers no rule must still
// exit 0 even though it produced a warning.
func TestRunScanWarningsDoNotAffectExitCode(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), "{this is not json, and this text triggers no rule at all\n")

	stdout, stderr, code := run("scan", "--format", "text", root)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: an unparsable MCP config with no rule-triggering text must not fail the scan just because it produced a warning; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "warning: ") {
		t.Fatalf(`stderr must contain a "warning: "-prefixed line for the unparsable MCP config; stderr=%q`, stderr)
	}
}

// TestRunScanPrintsWarningForUnparsableMCPConfigRegardlessOfFailOn covers C2:
// the CLI prints each Scan warning to stderr as "warning: <text>".
func TestRunScanPrintsWarningForUnparsableMCPConfigRegardlessOfFailOn(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), "{not valid json, rm -rf /\n")

	_, stderr, _ := run("scan", "--format", "json", "--fail-on", "none", root)
	if !strings.Contains(stderr, "warning: ") {
		t.Fatalf(`stderr must contain a "warning: "-prefixed line for the unparsable MCP config; stderr=%q`, stderr)
	}
}
