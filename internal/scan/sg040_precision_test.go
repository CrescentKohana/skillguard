package scan_test

import (
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestSG040FrontMatterFlowSequenceAndQuotedForms covers every C4 example for
// the SKILL.md front-matter form: the YAML flow-sequence form and quoted
// items must be recognized, both for unrestricted and for restricted Bash.
func TestSG040FrontMatterFlowSequenceAndQuotedForms(t *testing.T) {
	cases := []struct {
		name    string
		content string
		fires   bool
	}{
		{
			"flow-sequence-bash-fires",
			"---\nname: demo\nallowed-tools: [Read, Bash]\n---\nBody.\n",
			true,
		},
		{
			"list-form-quoted-bash-fires",
			"---\nname: demo\nallowed-tools:\n  - Read\n  - \"Bash\"\n---\nBody.\n",
			true,
		},
		{
			"flat-quoted-bash-star-fires",
			"---\nname: demo\nallowed-tools: 'Bash(*)'\n---\nBody.\n",
			true,
		},
		{
			"flow-sequence-restricted-bash-does-not-fire",
			"---\nname: demo\nallowed-tools: [Read, \"Bash(git status:*)\"]\n---\nBody.\n",
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scan.ScanContent("SKILL.md", scan.KindSkill, []byte(tc.content))
			got := hasRule(findings, "SG040")
			if got != tc.fires {
				t.Fatalf("content %q: SG040 fired=%v, want %v; findings=%+v", tc.content, got, tc.fires, findings)
			}
		})
	}
}
