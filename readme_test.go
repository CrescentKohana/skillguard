package skillguard_test

import (
	"os"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/rules"
)

// TestREADMEMapsEveryRuleToOWASPAndATLAS covers acceptance criterion 11: the
// README must map every rule to its OWASP LLM Top 10 2025 and MITRE ATLAS IDs.
func TestREADMEMapsEveryRuleToOWASPAndATLAS(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("README.md must exist at the repo root: %v", err)
	}
	content := string(data)

	for _, r := range rules.All() {
		if !strings.Contains(content, r.ID) {
			t.Errorf("README.md does not mention rule %s", r.ID)
		}
		foundOWASP := false
		for _, id := range r.OWASP {
			if strings.Contains(content, id) {
				foundOWASP = true
			}
		}
		if !foundOWASP {
			t.Errorf("README.md does not mention any OWASP mapping for %s (%v)", r.ID, r.OWASP)
		}
		foundATLAS := false
		for _, id := range r.ATLAS {
			if strings.Contains(content, id) {
				foundATLAS = true
			}
		}
		if !foundATLAS {
			t.Errorf("README.md does not mention any ATLAS mapping for %s (%v)", r.ID, r.ATLAS)
		}
	}
}

func TestREADMEMentionsInstallExitCodesAndSuppression(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("README.md must exist at the repo root: %v", err)
	}
	content := string(data)

	for _, want := range []string{
		"go install github.com/CrescentKohana/skillguard/cmd/skillguard@latest",
		"skillguard-ignore",
		"synthetic",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("README.md does not mention %q", want)
		}
	}
}

// actionPlaceholderSHA is the literal placeholder E6 requires in the
// README's uses: line, replacing a fake all-zero SHA: this supersedes C6's
// literal-40-hex-commit-SHA requirement.
const actionPlaceholderSHA = "CrescentKohana/skillguard@<full-40-character-commit-sha>"

// TestREADMEActionSnippetUsesPlaceholderCommitSHAWithPinNote verifies the
// action snippet's `uses:` line names the placeholder SHA, with a pin note
// scoped to the lines around that snippet rather than anywhere in the document.
func TestREADMEActionSnippetUsesPlaceholderCommitSHAWithPinNote(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("README.md must exist at the repo root: %v", err)
	}
	lines := strings.Split(string(data), "\n")

	usesIdx := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "- uses: CrescentKohana/skillguard@") {
			usesIdx = i
			break
		}
	}
	if usesIdx == -1 {
		t.Fatalf(`README.md does not contain a "- uses: CrescentKohana/skillguard@..." GitHub Action snippet line`)
	}
	usesLine := strings.TrimSpace(lines[usesIdx])
	if !strings.Contains(usesLine, actionPlaceholderSHA) {
		t.Errorf("README.md's Action snippet uses: line must contain the placeholder %q (E6 supersedes the literal-40-hex-SHA requirement); got %q", actionPlaceholderSHA, usesLine)
	}

	start := usesIdx - 2
	if start < 0 {
		start = 0
	}
	end := usesIdx + 3
	if end > len(lines) {
		end = len(lines)
	}
	window := strings.ToLower(strings.Join(lines[start:end], "\n"))
	if !strings.Contains(window, "pin") {
		t.Errorf("README.md must include a note telling users to pin the action, near its uses: line; window=%q", window)
	}
}

// TestREADMEActionSnippetHasCallerPermissionsForSARIFUpload covers C6: the
// README includes the caller-side permissions: block SARIF upload needs.
func TestREADMEActionSnippetHasCallerPermissionsForSARIFUpload(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("README.md must exist at the repo root: %v", err)
	}
	content := string(data)
	for _, want := range []string{"permissions:", "contents: read", "security-events: write"} {
		if !strings.Contains(content, want) {
			t.Errorf("README.md does not contain %q (needed for the caller-side permissions block for SARIF upload)", want)
		}
	}
}
