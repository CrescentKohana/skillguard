package scan_test

import (
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestG4SlashStarSlashIsNotACompleteCommentAndStaysOpenUntilNextClose verifies
// "/*/" does not reuse its own "*" as a closing "*/": a fake "mcpServers.evil"
// entry inside the resulting comment must not be analysed, while a server after the real close still is.
func TestG4SlashStarSlashIsNotACompleteCommentAndStaysOpenUntilNextClose(t *testing.T) {
	content := "{\n" +
		`  /*/ noise claiming to define "mcpServers": {"evil": {"command":"npx","args":["-y","left-pad"]}} , */` + "\n" +
		`  "mcpServers": {` + "\n" +
		`    "real": {"command": "npx", "args": ["-y", "left-pad"]}` + "\n" +
		`  }` + "\n" +
		"}\n"
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))

	if n := countRule(findings, "SG050"); n != 1 {
		t.Fatalf(`G4: "/*/" must stay open until the next "*/", so only "real" (defined after the genuine close) is analysed and "evil" (inside the still-open comment) is not; want exactly 1 SG050 finding, got %d: %+v`, n, findings)
	}
	msg := findRule(t, findings, "SG050").Message
	if strings.Contains(msg, "evil") {
		t.Errorf(`SG050 finding must not name "evil" (it sits inside the still-open comment); got message %q`, msg)
	}
	if !strings.Contains(msg, "real") {
		t.Errorf(`SG050 finding must name "real"; got message %q`, msg)
	}
}

// TestG4DoubleStarSlashIsACompleteComment covers G4's companion example:
// "/**/" is itself a complete, empty comment.
func TestG4DoubleStarSlashIsACompleteComment(t *testing.T) {
	content := `{/**/"mcpServers":{"real":{"command":"npx","args":["-y","left-pad"]}}}`
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))

	if n := countRule(findings, "SG050"); n != 1 {
		t.Fatalf(`G4: "/**/" must be a complete, empty comment; want exactly 1 SG050 finding for "real", got %d: %+v`, n, findings)
	}
}
