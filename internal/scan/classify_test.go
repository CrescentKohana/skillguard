package scan_test

import (
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

func TestClassifyPositive(t *testing.T) {
	cases := []struct {
		name string
		path string
		want scan.FileKind
	}{
		{"skill-plain", "SKILL.md", scan.KindSkill},
		{"skill-lowercase", "skill.md", scan.KindSkill},
		{"skill-mixedcase", "Skill.MD", scan.KindSkill},
		{"skill-nested", "foo/bar/SKILL.md", scan.KindSkill},
		{"skill-windows-path", `C:\Users\foo\skills\SKILL.md`, scan.KindSkill},
		{"agents-plain", "AGENTS.md", scan.KindAgents},
		{"agents-lowercase", "agents.md", scan.KindAgents},
		{"agents-nested", "repo/AGENTS.md", scan.KindAgents},
		{"kiro-steering", ".kiro/steering/style.md", scan.KindKiroSteering},
		{"kiro-steering-nested-root", "project/.kiro/steering/style.md", scan.KindKiroSteering},
		{"kiro-hook", ".kiro/hooks/on-save.kiro.hook", scan.KindKiroHook},
		{"kiro-hook-nested-root", "project/.kiro/hooks/on-save.kiro.hook", scan.KindKiroHook},
		{"mcp-dotmcp", ".mcp.json", scan.KindMCPConfig},
		{"mcp-plain", "mcp.json", scan.KindMCPConfig},
		{"mcp-config-underscore", "mcp_config.json", scan.KindMCPConfig},
		{"claude-desktop", "claude_desktop_config.json", scan.KindMCPConfig},
		{"mcp-nested", "config/.mcp.json", scan.KindMCPConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, ok := scan.Classify(tc.path)
			if !ok {
				t.Fatalf("Classify(%q): ok = false, want true with kind %v", tc.path, tc.want)
			}
			if kind != tc.want {
				t.Fatalf("Classify(%q) = %v, want %v", tc.path, kind, tc.want)
			}
		})
	}
}

func TestClassifyNegative(t *testing.T) {
	cases := []string{
		"README.md",
		"main.go",
		"notes.txt",
		"steering.md",
		"hooks/on-save.kiro.hook",
		"something.json",
		"package.json",
		"skill.md.bak",
		"AGENTS.markdown",
		"",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			if kind, ok := scan.Classify(path); ok {
				t.Fatalf("Classify(%q): ok = true, kind = %v, want ok = false", path, kind)
			}
		})
	}
}
