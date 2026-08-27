package scan_test

import (
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestMCPConfigSameNamedServerInBothContainersAreTwoServers verifies servers
// are keyed by (container, name): a server named "fs" in both "mcpServers" and
// "servers" is two distinct servers, both analysed and reported, never merged or overwritten.
func TestMCPConfigSameNamedServerInBothContainersAreTwoServers(t *testing.T) {
	secret := "zz" + strings.Repeat("Ab1c", 4) // non-placeholder, length >= 8
	content := `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "left-pad"],
      "autoApprove": true,
      "env": {"API_KEY": "` + secret + `"}
    }
  },
  "servers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "left-pad@1.0.0"],
      "trust": true
    }
  }
}`
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))

	if n := countRule(findings, "SG050"); n != 1 {
		t.Fatalf(`want exactly 1 SG050 finding (only mcpServers.fs's "left-pad" is unpinned; servers.fs's "left-pad@1.0.0" is pinned), got %d: %+v`, n, findings)
	}
	if msg := findRule(t, findings, "SG050").Message; !strings.Contains(msg, `"mcpServers.fs"`) {
		t.Errorf(`SG050 message must name the container: want to contain %q, got %q`, `"mcpServers.fs"`, msg)
	}

	if n := countRule(findings, "SG040"); n != 2 {
		t.Fatalf("want exactly 2 SG040 findings (one for mcpServers.fs's autoApprove, one for servers.fs's trust), got %d: %+v", n, findings)
	}
	var sawMCPServers, sawServers bool
	for _, f := range findings {
		if f.RuleID != "SG040" {
			continue
		}
		// Quotes are required: unquoted "servers.fs" is also a substring of
		// "mcpServers.fs", which would match both findings regardless of container.
		if strings.Contains(f.Message, `"mcpServers.fs"`) {
			sawMCPServers = true
		}
		if strings.Contains(f.Message, `"servers.fs"`) {
			sawServers = true
		}
	}
	if !sawMCPServers {
		t.Errorf(`no SG040 message names "mcpServers.fs"; findings=%+v`, findings)
	}
	if !sawServers {
		t.Errorf(`no SG040 message names "servers.fs"; findings=%+v`, findings)
	}

	if n := countRule(findings, "SG060"); n != 1 {
		t.Fatalf("want exactly 1 SG060 finding (mcpServers.fs's secret env value), got %d: %+v", n, findings)
	}
	if msg := findRule(t, findings, "SG060").Message; !strings.Contains(msg, `"mcpServers.fs"`) {
		t.Errorf(`SG060 message must name the container: want to contain %q, got %q`, `"mcpServers.fs"`, msg)
	}
}
