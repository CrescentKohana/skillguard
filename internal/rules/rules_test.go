package rules_test

import (
	"regexp"
	"sort"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/rules"
)

var owaspPattern = regexp.MustCompile(`^LLM(0[1-9]|10):2025$`)
var atlasPattern = regexp.MustCompile(`^AML\.T\d{4}(\.\d{3})?$`)

var wantTable = []struct {
	id       string
	name     string
	severity finding.Severity
}{
	{"SG001", "invisible-unicode-zero-width", finding.SeverityHigh},
	{"SG002", "invisible-unicode-bidi", finding.SeverityHigh},
	{"SG003", "invisible-unicode-tag", finding.SeverityCritical},
	{"SG010", "prompt-injection-phrase", finding.SeverityHigh},
	{"SG020", "data-exfiltration", finding.SeverityHigh},
	{"SG021", "markdown-image-exfiltration", finding.SeverityHigh},
	{"SG030", "dangerous-shell-command", finding.SeverityHigh},
	{"SG031", "sensitive-file-access", finding.SeverityHigh},
	{"SG040", "excessive-permission", finding.SeverityHigh},
	{"SG050", "unpinned-mcp-package", finding.SeverityMedium},
	{"SG060", "hardcoded-secret", finding.SeverityCritical},
}

func TestAllCount(t *testing.T) {
	all := rules.All()
	if len(all) != len(wantTable) {
		t.Fatalf("All() returned %d rules, want %d", len(all), len(wantTable))
	}
}

func TestAllSortedByID(t *testing.T) {
	all := rules.All()
	ids := make([]string, len(all))
	for i, r := range all {
		ids[i] = r.ID
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("All() not sorted by ID: %v", ids)
	}
}

func TestAllFixedTable(t *testing.T) {
	all := rules.All()
	byID := make(map[string]rules.Rule, len(all))
	for _, r := range all {
		byID[r.ID] = r
	}
	for _, tc := range wantTable {
		t.Run(tc.id, func(t *testing.T) {
			r, ok := byID[tc.id]
			if !ok {
				t.Fatalf("All() missing rule %s", tc.id)
			}
			if r.Name != tc.name {
				t.Errorf("rule %s: Name = %q, want %q", tc.id, r.Name, tc.name)
			}
			if r.Severity != tc.severity {
				t.Errorf("rule %s: Severity = %v, want %v", tc.id, r.Severity, tc.severity)
			}
			if r.Description == "" {
				t.Errorf("rule %s: Description is empty", tc.id)
			}
		})
	}
}

func TestAllOWASPIDsWellFormed(t *testing.T) {
	for _, r := range rules.All() {
		t.Run(r.ID, func(t *testing.T) {
			if len(r.OWASP) == 0 {
				t.Fatalf("rule %s has no OWASP mapping", r.ID)
			}
			for _, id := range r.OWASP {
				if !owaspPattern.MatchString(id) {
					t.Errorf("rule %s: OWASP id %q does not match LLMxx:2025", r.ID, id)
				}
			}
		})
	}
}

func TestAllATLASIDsWellFormed(t *testing.T) {
	for _, r := range rules.All() {
		t.Run(r.ID, func(t *testing.T) {
			if len(r.ATLAS) == 0 {
				t.Fatalf("rule %s has no ATLAS mapping", r.ID)
			}
			for _, id := range r.ATLAS {
				if !atlasPattern.MatchString(id) {
					t.Errorf("rule %s: ATLAS id %q does not match AML.T\\d{4}(\\.\\d{3})?", r.ID, id)
				}
			}
		})
	}
}

func TestLookupKnown(t *testing.T) {
	for _, tc := range wantTable {
		t.Run(tc.id, func(t *testing.T) {
			r, ok := rules.Lookup(tc.id)
			if !ok {
				t.Fatalf("Lookup(%q): ok = false, want true", tc.id)
			}
			if r.ID != tc.id || r.Name != tc.name || r.Severity != tc.severity {
				t.Fatalf("Lookup(%q) = %+v, want ID/Name/Severity matching %+v", tc.id, r, tc)
			}
		})
	}
}

func TestLookupUnknown(t *testing.T) {
	for _, id := range []string{"SG000", "SG999", "sg001", "", "SG0001"} {
		t.Run(id, func(t *testing.T) {
			if _, ok := rules.Lookup(id); ok {
				t.Fatalf("Lookup(%q): ok = true, want false", id)
			}
		})
	}
}
