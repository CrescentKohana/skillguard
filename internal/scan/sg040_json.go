package scan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

// classifyApproval maps an autoApprove/alwaysAllow value to a severity.
// ok is false when the value grants no extra permission (absent, false, or empty array).
func classifyApproval(v any) (finding.Severity, bool) {
	switch val := v.(type) {
	case bool:
		if val {
			return finding.SeverityHigh, true
		}
	case []any:
		if len(val) == 0 {
			return 0, false
		}
		for _, item := range val {
			if s, ok := item.(string); ok && s == "*" {
				return finding.SeverityHigh, true
			}
		}
		return finding.SeverityLow, true
	}
	return 0, false
}

// sg040MCPJSON flags MCP servers with auto-approval or trust enabled.
func sg040MCPJSON(doc document, stripped string, servers map[serverKey]mcpServerConfig, idx map[serverKey]serverSpan, sc *snippetCache) []finding.Finding {
	var out []finding.Finding
	for _, key := range sortedServerKeys(servers) {
		s := servers[key]
		start, end, hasBlock := serverBlockFor(idx, key)

		report := func(field string, sev finding.Severity, msg string) {
			line, col := 1, 1
			if hasBlock {
				line, col = locateKeyInBlock(doc, stripped, start, end, field)
			}
			out = append(out, finding.Finding{
				RuleID: "SG040", Severity: sev, Line: line, Column: col,
				Message: msg, Snippet: sc.at(line),
			})
		}

		if sev, flagged := classifyApproval(s.AutoApprove); flagged {
			report("autoApprove", sev, fmt.Sprintf("MCP server %q has excessive permission via %q", key, "autoApprove"))
		}
		if sev, flagged := classifyApproval(s.AlwaysAllow); flagged {
			report("alwaysAllow", sev, fmt.Sprintf("MCP server %q has excessive permission via %q", key, "alwaysAllow"))
		}
		if trust, isBool := s.Trust.(bool); isBool && trust {
			report("trust", finding.SeverityHigh, fmt.Sprintf("MCP server %q has trust enabled", key))
		}
	}
	return out
}

type kiroHookFile struct {
	When struct {
		Type string `json:"type"`
	} `json:"when"`
	Then struct {
		Type string `json:"type"`
	} `json:"then"`
}

// sg040HookJSON flags Kiro hooks that run a shell command on any trigger.
func sg040HookJSON(doc document, sc *snippetCache) []finding.Finding {
	var hook kiroHookFile
	if err := json.Unmarshal([]byte(doc.content), &hook); err != nil {
		return nil
	}
	if hook.Then.Type != "runCommand" {
		return nil
	}
	line, col := 1, 1
	if idx := strings.Index(doc.content, `"runCommand"`); idx != -1 {
		line, col = doc.locate(idx)
	}
	return []finding.Finding{{
		RuleID: "SG040", Severity: finding.SeverityMedium, Line: line, Column: col,
		Message: fmt.Sprintf("kiro hook runs a command when %q fires", hook.When.Type),
		Snippet: sc.at(line),
	}}
}

// parseAllowedToolsValue splits an inline allowed-tools value into its
// tokens, accepting a plain comma list, a YAML flow sequence ("[a, b]"), and
// single- or double-quoted items in either form.
func parseAllowedToolsValue(rest string) []string {
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
		rest = rest[1 : len(rest)-1]
	}
	if rest == "" {
		return nil
	}
	parts := strings.Split(rest, ",")
	tokens := make([]string, 0, len(parts))
	for _, p := range parts {
		tokens = append(tokens, unquote(strings.TrimSpace(p)))
	}
	return tokens
}

func isUnrestrictedBashToken(tok string) bool {
	switch tok {
	case "Bash", "Bash(*)", "Bash(*:*)", "*":
		return true
	}
	return false
}

// sg040FrontMatter flags a SKILL.md allowed-tools entry that grants
// unrestricted Bash access, in either the inline or YAML-list form.
func sg040FrontMatter(doc document, sc *snippetCache) []finding.Finding {
	if len(doc.lines) == 0 || strings.TrimSpace(doc.lines[0]) != "---" {
		return nil
	}
	closeIdx := -1
	for i := 1; i < len(doc.lines); i++ {
		if strings.TrimSpace(doc.lines[i]) == "---" {
			closeIdx = i
			break
		}
	}
	if closeIdx == -1 {
		return nil
	}
	front := doc.lines[1:closeIdx]

	var out []finding.Finding
	for i, l := range front {
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(trimmed, "allowed-tools:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "allowed-tools:"))
		var tokens []string
		if rest != "" {
			tokens = parseAllowedToolsValue(rest)
		} else {
			for j := i + 1; j < len(front); j++ {
				item := strings.TrimSpace(front[j])
				if !strings.HasPrefix(item, "- ") {
					break
				}
				tokens = append(tokens, unquote(strings.TrimSpace(strings.TrimPrefix(item, "- "))))
			}
		}
		for _, tok := range tokens {
			if !isUnrestrictedBashToken(tok) {
				continue
			}
			lineNum := i + 2
			lineText := doc.lineAt(lineNum)
			col := 1
			if idx := strings.Index(lineText, "allowed-tools"); idx != -1 {
				col = len([]rune(lineText[:idx])) + 1
			}
			out = append(out, finding.Finding{
				RuleID: "SG040", Severity: finding.SeverityHigh, Line: lineNum, Column: col,
				Message: fmt.Sprintf("allowed-tools grants unrestricted shell access via %q", tok),
				Snippet: sc.at(lineNum),
			})
			break
		}
	}
	return out
}
