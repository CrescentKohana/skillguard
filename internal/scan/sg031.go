package scan

import (
	"fmt"
	"strings"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

var sensitiveFilePatterns = []string{
	"~/.ssh/", "$HOME/.ssh", "${HOME}/.ssh", "id_rsa", "id_ed25519", "id_ecdsa",
	".aws/credentials", ".config/gh/hosts.yml", ".netrc", ".docker/config.json",
	".kube/config", ".git-credentials", ".npmrc", ".pypirc", "/etc/shadow",
	"Library/Keychains",
}

func matchSensitiveFileAccess(line string) (lineMatch, bool) {
	best := -1
	matched := ""
	for _, p := range sensitiveFilePatterns {
		if idx := strings.Index(line, p); idx != -1 && (best == -1 || idx < best) {
			best, matched = idx, p
		}
	}
	if best == -1 {
		return lineMatch{}, false
	}
	return lineMatch{offset: best, severity: finding.SeverityHigh,
		message: fmt.Sprintf("reference to a sensitive credential location: %s", matched)}, true
}

func sg031(doc document, sc *snippetCache) []finding.Finding {
	return scanLines(doc, sc, "SG031", []lineMatcher{matchSensitiveFileAccess})
}
