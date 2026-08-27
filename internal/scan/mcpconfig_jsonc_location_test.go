package scan_test

import (
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestSG050PackageLocationIgnoresCommentMention covers E4: locating a
// package spec searches the JSONC-stripped content, so a comment mentioning
// the package name before the real occurrence never wins the location.
func TestSG050PackageLocationIgnoresCommentMention(t *testing.T) {
	content := "{\n" +
		`  "mcpServers": {` + "\n" +
		`    "fs": {` + "\n" +
		`      "command": "npx",` + "\n" +
		`      // package reference: left-pad` + "\n" +
		`      "args": ["-y", "left-pad"]` + "\n" +
		`    }` + "\n" +
		`  }` + "\n" +
		"}\n"
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	f := findRule(t, findings, "SG050")
	if f.Line != 6 {
		t.Fatalf("SG050 location must be the real args line (6), not the comment mentioning the package name on line 5; got line %d; findings=%+v", f.Line, findings)
	}
}

// TestSG060KeyLocationIgnoresCommentMention covers E4: locating a secret env
// key searches the JSONC-stripped content, so a comment mentioning the
// quoted key before the real occurrence never wins the location.
func TestSG060KeyLocationIgnoresCommentMention(t *testing.T) {
	secret := "zz" + strings.Repeat("R2s3", 4) // non-placeholder, length >= 8
	content := "{\n" +
		`  "mcpServers": {` + "\n" +
		`    "fs": {` + "\n" +
		`      "command": "node",` + "\n" +
		`      "args": ["server.js"],` + "\n" +
		`      // "API_KEY" is read from the environment here` + "\n" +
		`      "env": {"API_KEY": "` + secret + `"}` + "\n" +
		`    }` + "\n" +
		`  }` + "\n" +
		"}\n"
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	f := findRule(t, findings, "SG060")
	if f.Line != 7 {
		t.Fatalf(`SG060 location must be the real "env" line (7), not the comment mentioning "API_KEY" on line 6; got line %d; findings=%+v`, f.Line, findings)
	}
}
