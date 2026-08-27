// Package rules holds the fixed catalogue of SkillGuard detection rules:
// their IDs, names, default severities, and OWASP/ATLAS mappings.
package rules

import (
	"sort"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

// Rule describes one detection rule.
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    finding.Severity
	// OWASP holds OWASP Top 10 for LLM Applications 2025 IDs, e.g. "LLM01:2025".
	OWASP []string
	// ATLAS holds MITRE ATLAS technique IDs, e.g. "AML.T0051".
	ATLAS []string
}

var table = []Rule{
	{
		ID:          "SG001",
		Name:        "invisible-unicode-zero-width",
		Description: "Zero-width and other invisible Unicode characters that can hide instructions from a human reviewer.",
		Severity:    finding.SeverityHigh,
		OWASP:       []string{"LLM01:2025"},
		ATLAS:       []string{"AML.T0068"},
	},
	{
		ID:          "SG002",
		Name:        "invisible-unicode-bidi",
		Description: "Bidirectional-control Unicode characters that can reorder displayed text to disguise content.",
		Severity:    finding.SeverityHigh,
		OWASP:       []string{"LLM01:2025"},
		ATLAS:       []string{"AML.T0068"},
	},
	{
		ID:          "SG003",
		Name:        "invisible-unicode-tag",
		Description: "Unicode Tag or variation-selector characters smuggling hidden ASCII instructions.",
		Severity:    finding.SeverityCritical,
		OWASP:       []string{"LLM01:2025"},
		ATLAS:       []string{"AML.T0068", "AML.T0051"},
	},
	{
		ID:          "SG010",
		Name:        "prompt-injection-phrase",
		Description: "English or Japanese phrasing that attempts to override or bypass prior instructions.",
		Severity:    finding.SeverityHigh,
		OWASP:       []string{"LLM01:2025"},
		ATLAS:       []string{"AML.T0051"},
	},
	{
		ID:          "SG020",
		Name:        "data-exfiltration",
		Description: "Commands or URLs that send data to a remote or known out-of-band host.",
		Severity:    finding.SeverityHigh,
		OWASP:       []string{"LLM02:2025"},
		ATLAS:       []string{"AML.T0025"},
	},
	{
		ID:          "SG021",
		Name:        "markdown-image-exfiltration",
		Description: "Markdown or HTML images whose URL encodes a data placeholder, used to exfiltrate data on render.",
		Severity:    finding.SeverityHigh,
		OWASP:       []string{"LLM02:2025"},
		ATLAS:       []string{"AML.T0086"},
	},
	{
		ID:          "SG030",
		Name:        "dangerous-shell-command",
		Description: "Shell commands that download-and-execute, wipe a filesystem, or otherwise cause irreversible damage.",
		Severity:    finding.SeverityHigh,
		OWASP:       []string{"LLM06:2025"},
		ATLAS:       []string{"AML.T0050"},
	},
	{
		ID:          "SG031",
		Name:        "sensitive-file-access",
		Description: "References to credential files and locations such as SSH keys, cloud credentials, or shadow files.",
		Severity:    finding.SeverityHigh,
		OWASP:       []string{"LLM02:2025"},
		ATLAS:       []string{"AML.T0055"},
	},
	{
		ID:          "SG040",
		Name:        "excessive-permission",
		Description: "Configuration or flags that grant an agent unrestricted or auto-approved tool access.",
		Severity:    finding.SeverityHigh,
		OWASP:       []string{"LLM06:2025"},
		ATLAS:       []string{"AML.T0053"},
	},
	{
		ID:          "SG050",
		Name:        "unpinned-mcp-package",
		Description: "MCP server packages run without a pinned version or content digest.",
		Severity:    finding.SeverityMedium,
		OWASP:       []string{"LLM03:2025"},
		ATLAS:       []string{"AML.T0010"},
	},
	{
		ID:          "SG060",
		Name:        "hardcoded-secret",
		Description: "API keys, tokens, or other credentials hardcoded in a skill or configuration file.",
		Severity:    finding.SeverityCritical,
		OWASP:       []string{"LLM02:2025"},
		ATLAS:       []string{"AML.T0083"},
	},
}

// clone copies r so callers cannot mutate the shared catalogue through its slices.
func (r Rule) clone() Rule {
	r.OWASP = append([]string(nil), r.OWASP...)
	r.ATLAS = append([]string(nil), r.ATLAS...)
	return r
}

// All returns every rule, sorted by ID.
func All() []Rule {
	out := make([]Rule, len(table))
	for i, r := range table {
		out[i] = r.clone()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Lookup finds a rule by ID.
func Lookup(id string) (Rule, bool) {
	for _, r := range table {
		if r.ID == id {
			return r.clone(), true
		}
	}
	return Rule{}, false
}
