package scan_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

func mcpConfigWithKey(serversKey, autoApproveKey, autoApproveValue string) string {
	return fmt.Sprintf(`{
  "%s": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
      "%s": %s
    }
  }
}`, serversKey, autoApproveKey, autoApproveValue)
}

func TestSG040MCPAutoApproveTrueIsHigh(t *testing.T) {
	for _, serversKey := range []string{"mcpServers", "servers"} {
		t.Run(serversKey, func(t *testing.T) {
			content := mcpConfigWithKey(serversKey, "autoApprove", "true")
			findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
			f := findRule(t, findings, "SG040")
			if f.Severity != finding.SeverityHigh {
				t.Fatalf("autoApprove:true severity = %v, want high", f.Severity)
			}
		})
	}
}

func TestSG040MCPAlwaysAllowTrueIsHigh(t *testing.T) {
	content := mcpConfigWithKey("mcpServers", "alwaysAllow", "true")
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	f := findRule(t, findings, "SG040")
	if f.Severity != finding.SeverityHigh {
		t.Fatalf("alwaysAllow:true severity = %v, want high", f.Severity)
	}
}

func TestSG040MCPWildcardArrayIsHigh(t *testing.T) {
	content := mcpConfigWithKey("mcpServers", "autoApprove", `["*"]`)
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	f := findRule(t, findings, "SG040")
	if f.Severity != finding.SeverityHigh {
		t.Fatalf(`autoApprove:["*"] severity = %v, want high`, f.Severity)
	}
}

func TestSG040MCPNonEmptyArrayWithoutWildcardIsLow(t *testing.T) {
	content := mcpConfigWithKey("mcpServers", "autoApprove", `["readFile", "listFiles"]`)
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	f := findRule(t, findings, "SG040")
	if f.Severity != finding.SeverityLow {
		t.Fatalf("non-empty allow-list severity = %v, want low", f.Severity)
	}
}

func TestSG040MCPTrustTrueIsHigh(t *testing.T) {
	content := mcpConfigWithKey("mcpServers", "trust", "true")
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	f := findRule(t, findings, "SG040")
	if f.Severity != finding.SeverityHigh {
		t.Fatalf(`trust:true severity = %v, want high`, f.Severity)
	}
}

func TestSG040MCPEmptyArrayDoesNotFire(t *testing.T) {
	content := mcpConfigWithKey("mcpServers", "autoApprove", `[]`)
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	if hasRule(findings, "SG040") {
		t.Fatalf("empty autoApprove array must not trigger SG040; findings=%+v", findings)
	}
}

func TestSG040KiroHookRunCommandIsMedium(t *testing.T) {
	content := `{
  "when": {"type": "fileEdited"},
  "then": {"type": "runCommand", "command": "echo hi"}
}`
	findings := scan.ScanContent(".kiro/hooks/on-save.kiro.hook", scan.KindKiroHook, []byte(content))
	f := findRule(t, findings, "SG040")
	if f.Severity != finding.SeverityMedium {
		t.Fatalf("kiro runCommand hook severity = %v, want medium", f.Severity)
	}
	if !strings.Contains(f.Message, "fileEdited") {
		t.Fatalf("message %q must name the trigger when.type (fileEdited)", f.Message)
	}
}

func TestSG040KiroHookNonRunCommandDoesNotFire(t *testing.T) {
	content := `{
  "when": {"type": "fileEdited"},
  "then": {"type": "askAgent"}
}`
	findings := scan.ScanContent(".kiro/hooks/on-save.kiro.hook", scan.KindKiroHook, []byte(content))
	if hasRule(findings, "SG040") {
		t.Fatalf("non-runCommand hook must not trigger SG040; findings=%+v", findings)
	}
}

func TestSG040SkillFrontMatterInlineUnrestrictedBash(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"bash-bare", "Read, Bash"},
		{"bash-star-parens", "Read, Bash(*)"},
		{"bash-star-colon-star", "Read, Bash(*:*)"},
		{"bare-star", "*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := fmt.Sprintf("---\nname: demo\nallowed-tools: %s\n---\nBody text.\n", tc.value)
			findings := scan.ScanContent("SKILL.md", scan.KindSkill, []byte(content))
			f := findRule(t, findings, "SG040")
			if f.Severity != finding.SeverityHigh {
				t.Fatalf("allowed-tools: %s severity = %v, want high", tc.value, f.Severity)
			}
		})
	}
}

func TestSG040SkillFrontMatterListForm(t *testing.T) {
	content := "---\nname: demo\nallowed-tools:\n  - Read\n  - Bash(*)\n---\nBody text.\n"
	findings := scan.ScanContent("SKILL.md", scan.KindSkill, []byte(content))
	f := findRule(t, findings, "SG040")
	if f.Severity != finding.SeverityHigh {
		t.Fatalf("list-form unrestricted Bash severity = %v, want high", f.Severity)
	}
}

func TestSG040SkillFrontMatterRestrictedBashDoesNotFire(t *testing.T) {
	content := "---\nname: demo\nallowed-tools: Read, Grep, Bash(git status:*)\n---\nBody text.\n"
	findings := scan.ScanContent("SKILL.md", scan.KindSkill, []byte(content))
	if hasRule(findings, "SG040") {
		t.Fatalf("restricted Bash(git status:*) must not trigger SG040; findings=%+v", findings)
	}
}

func TestSG040TextFormFlags(t *testing.T) {
	cases := []string{
		"--dangerously-skip-permissions",
		"--dangerously-bypass-approvals-and-sandbox",
		"--yolo",
		"--trust-all-tools",
		"--allow-all-tools",
		"bypassPermissions",
		`"chat.tools.autoApprove": true`,
	}
	for _, flag := range cases {
		t.Run(flag, func(t *testing.T) {
			content := "run the tool with " + flag + " enabled\n"
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(content))
			f := findRule(t, findings, "SG040")
			if f.Severity != finding.SeverityHigh {
				t.Fatalf("flag %q severity = %v, want high", flag, f.Severity)
			}
		})
	}
}
