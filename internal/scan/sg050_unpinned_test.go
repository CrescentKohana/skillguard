package scan_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

func mcpServerConfig(serverName, command string, args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	return fmt.Sprintf(`{
  "mcpServers": {
    %q: {
      "command": %q,
      "args": [%s]
    }
  }
}`, serverName, command, strings.Join(quoted, ", "))
}

func TestSG050NpxFamily(t *testing.T) {
	cases := []struct {
		name     string
		command  string
		args     []string
		unpinned bool
	}{
		{"npx-unpinned-no-version", "npx", []string{"-y", "left-pad"}, true},
		{"npx-pinned-exact", "npx", []string{"-y", "left-pad@1.3.0"}, false},
		{"npx-at-latest", "npx", []string{"-y", "left-pad@latest"}, true},
		{"npx-at-next", "npx", []string{"-y", "left-pad@next"}, true},
		{"npx-caret-range", "npx", []string{"-y", "left-pad@^1.0.0"}, true},
		{"npx-tilde-range", "npx", []string{"-y", "left-pad@~1.0.0"}, true},
		{"npx-wildcard-range", "npx", []string{"-y", "left-pad@*"}, true},
		{"npx-scoped-unpinned", "npx", []string{"-y", "@scope/name"}, true},
		{"npx-scoped-pinned", "npx", []string{"-y", "@scope/name@2.0.0"}, false},
		{"npx-package-flag-pinned", "npx", []string{"-y", "-p", "cowsay@1.5.0", "cowsay"}, false},
		{"npx-package-flag-unpinned", "npx", []string{"-y", "-p", "cowsay", "cowsay"}, true},
		{"npx-prerelease-pin", "npx", []string{"-y", "left-pad@1.0.0-beta.1"}, false},
		{"npx-build-metadata-pin", "npx", []string{"-y", "left-pad@1.0.0+build5"}, false},
		{"bunx-unpinned", "bunx", []string{"cowsay@latest"}, true},
		{"bunx-pinned", "bunx", []string{"cowsay@1.5.0"}, false},
		{"pnpm-dlx-unpinned", "pnpm", []string{"dlx", "cowsay"}, true},
		{"pnpm-dlx-pinned", "pnpm", []string{"dlx", "cowsay@1.5.0"}, false},
		{"yarn-dlx-unpinned", "yarn", []string{"dlx", "cowsay"}, true},
		{"yarn-dlx-pinned", "yarn", []string{"dlx", "cowsay@1.5.0"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := mcpServerConfig("svc", tc.command, tc.args)
			findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
			got := hasRule(findings, "SG050")
			if got != tc.unpinned {
				t.Fatalf("command=%q args=%v: SG050 fired=%v, want %v; findings=%+v", tc.command, tc.args, got, tc.unpinned, findings)
			}
		})
	}
}

func TestSG050UvxPipxUvToolFamily(t *testing.T) {
	cases := []struct {
		name     string
		command  string
		args     []string
		unpinned bool
	}{
		{"uvx-double-equals-pinned", "uvx", []string{"ruff==0.4.4"}, false},
		{"uvx-at-pinned", "uvx", []string{"ruff@0.4.4"}, false},
		{"uvx-unpinned", "uvx", []string{"ruff"}, true},
		{"pipx-run-pinned", "pipx", []string{"run", "black==24.1.0"}, false},
		{"pipx-run-unpinned", "pipx", []string{"run", "black"}, true},
		{"uv-tool-run-pinned", "uv", []string{"tool", "run", "ruff==0.4.4"}, false},
		{"uv-tool-run-unpinned", "uv", []string{"tool", "run", "ruff"}, true},
		{"uvx-from-flag-pinned", "uvx", []string{"--from", "black==24.1.0", "black"}, false},
		{"uvx-from-flag-unpinned", "uvx", []string{"--from", "black", "black"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := mcpServerConfig("svc", tc.command, tc.args)
			findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
			got := hasRule(findings, "SG050")
			if got != tc.unpinned {
				t.Fatalf("command=%q args=%v: SG050 fired=%v, want %v; findings=%+v", tc.command, tc.args, got, tc.unpinned, findings)
			}
		})
	}
}

func TestSG050DockerSeverity(t *testing.T) {
	cases := []struct {
		name  string
		image string
		fires bool
		want  finding.Severity
	}{
		{"no-tag", "myimage", true, finding.SeverityMedium},
		{"latest-tag", "myimage:latest", true, finding.SeverityMedium},
		{"versioned-tag", "myimage:1.2.3", true, finding.SeverityLow},
		{"digest-pinned", "myimage@sha256:" + strings.Repeat("ab", 32), false, finding.SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := mcpServerConfig("svc", "docker", []string{"run", tc.image})
			findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
			got := hasRule(findings, "SG050")
			if got != tc.fires {
				t.Fatalf("image %q: SG050 fired=%v, want %v; findings=%+v", tc.image, got, tc.fires, findings)
			}
			if tc.fires {
				f := findRule(t, findings, "SG050")
				if f.Severity != tc.want {
					t.Fatalf("image %q: severity=%v, want %v", tc.image, f.Severity, tc.want)
				}
			}
		})
	}
}

func TestSG050MessageNamesServerAndPackageSpec(t *testing.T) {
	content := mcpServerConfig("filesystem-server", "npx", []string{"-y", "left-pad"})
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	f := findRule(t, findings, "SG050")
	if !strings.Contains(f.Message, "filesystem-server") {
		t.Errorf("message %q does not name the server filesystem-server", f.Message)
	}
	if !strings.Contains(f.Message, "left-pad") {
		t.Errorf("message %q does not name the package spec left-pad", f.Message)
	}
}

func TestSG050OneFindingPerOffendingServer(t *testing.T) {
	content := `{
  "mcpServers": {
    "unpinned-one": {"command": "npx", "args": ["-y", "left-pad"]},
    "pinned": {"command": "npx", "args": ["-y", "left-pad@1.3.0"]},
    "unpinned-two": {"command": "uvx", "args": ["ruff"]}
  }
}`
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	if n := countRule(findings, "SG050"); n != 2 {
		t.Fatalf("expected exactly 2 SG050 findings (one per offending server), got %d: %+v", n, findings)
	}
}
