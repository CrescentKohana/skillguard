package scan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestScanRecordsWarningForUnparsableMCPConfigAndStillRunsTextRules covers
// C2: when an MCP-classified file cannot be parsed at all, text rules still
// run and Scan records a warning naming the file and the reason.
func TestScanRecordsWarningForUnparsableMCPConfigAndStillRunsTextRules(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".mcp.json")
	content := "{not valid json at all, rm -rf / \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := scan.Scan([]string{root})
	if err != nil {
		t.Fatalf("Scan: unexpected error for an unparsable MCP config: %v", err)
	}
	if !hasRule(res.Findings, "SG030") {
		t.Fatalf("text rules must still run on an unparsable MCP config; findings=%+v", res.Findings)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("Scan must record a warning for an unparsable MCP config; Result=%+v", res)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, ".mcp.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Result.Warnings must name the unparsable file; got %v", res.Warnings)
	}
}

// TestScanContentSignatureUnchangedForUnparsableMCPConfig documents that
// ScanContent's signature does not change for C2: it stays pure (no
// warnings return value) and still runs text rules on malformed JSON.
func TestScanContentSignatureUnchangedForUnparsableMCPConfig(t *testing.T) {
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte("{not valid json, rm -rf /\n"))
	if !hasRule(findings, "SG030") {
		t.Fatalf("ScanContent must still run text rules on malformed JSON; findings=%+v", findings)
	}
}

// TestScanWarnsNamingServerAndFieldForTypeMismatchedField covers E3: each
// field that could not be decoded independently adds a Result.Warnings
// entry naming the file, the server (container.name), and the field.
func TestScanWarnsNamingServerAndFieldForTypeMismatchedField(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".mcp.json")
	content := `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": "not-an-array",
      "autoApprove": true
    }
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := scan.Scan([]string{root})
	if err != nil {
		t.Fatalf("Scan: unexpected error: %v", err)
	}

	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, ".mcp.json") && strings.Contains(w, "mcpServers.fs") && strings.Contains(w, "args") {
			found = true
		}
	}
	if !found {
		t.Fatalf(`Result.Warnings must name the file, "mcpServers.fs", and the "args" field for a type-mismatched field; got %v`, res.Warnings)
	}
}
