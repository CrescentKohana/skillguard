package scan

import (
	"fmt"
	"regexp"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

// secretPattern pairs a \b-bounded detection regex with an explicit,
// hand-written boundary-free masking variant, so masking still catches a
// secret glued to adjacent filler, e.g. inside SG003's hidden text (G1.1.a).
type secretPattern struct {
	re       *regexp.Regexp
	maskRe   *regexp.Regexp
	provider string
}

// secretPatterns are checked in order; Anthropic is checked before OpenAI
// because an Anthropic key also satisfies the looser OpenAI alphabet.
var secretPatterns = []secretPattern{
	{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), regexp.MustCompile(`(AKIA|ASIA)[0-9A-Z]{16}`), "AWS access key"},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`), "GitHub token"},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`), regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`), "GitHub fine-grained PAT"},
	{regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`), "Anthropic API key"},
	{regexp.MustCompile(`\bsk-(proj-)?[A-Za-z0-9_-]{20,}`), regexp.MustCompile(`sk-(proj-)?[A-Za-z0-9_-]{20,}`), "OpenAI API key"},
	{regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}`), "Slack token"},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "Google API key"},
	{regexp.MustCompile(`\b[rs]k_live_[0-9A-Za-z]{20,}`), regexp.MustCompile(`[rs]k_live_[0-9A-Za-z]{20,}`), "Stripe live key"},
	{regexp.MustCompile(`-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----`), regexp.MustCompile(`-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----`), "PEM private key"},
}

// matchSecretPattern builds its message with the raw secret text; scan.go
// masks every finding's message (and buildSnippet masks every snippet)
// before either reaches output.
func matchSecretPattern(line string) (lineMatch, bool) {
	for _, sp := range secretPatterns {
		loc := sp.re.FindStringIndex(line)
		if loc == nil {
			continue
		}
		secret := line[loc[0]:loc[1]]
		return lineMatch{
			offset:   loc[0],
			severity: finding.SeverityCritical,
			message:  fmt.Sprintf("hardcoded %s detected: %s", sp.provider, secret),
		}, true
	}
	return lineMatch{}, false
}

func sg060Pattern(doc document, sc *snippetCache) []finding.Finding {
	return scanLines(doc, sc, "SG060", []lineMatcher{matchSecretPattern})
}
