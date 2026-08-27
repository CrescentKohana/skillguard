package scan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

var sg040TextLiterals = []string{
	"--dangerously-skip-permissions",
	"--dangerously-bypass-approvals-and-sandbox",
	"--yolo",
	"--trust-all-tools",
	"--allow-all-tools",
	"bypassPermissions",
}

var sg040ChatAutoApproveRe = regexp.MustCompile(`"chat\.tools\.autoApprove"\s*:\s*true`)

func matchExcessivePermissionText(line string) (lineMatch, bool) {
	best := -1
	msg := ""
	for _, lit := range sg040TextLiterals {
		if idx := strings.Index(line, lit); idx != -1 && (best == -1 || idx < best) {
			best, msg = idx, fmt.Sprintf("excessive-permission flag detected: %s", lit)
		}
	}
	if loc := sg040ChatAutoApproveRe.FindStringIndex(line); loc != nil && (best == -1 || loc[0] < best) {
		best, msg = loc[0], `excessive-permission setting detected: "chat.tools.autoApprove": true`
	}
	if best == -1 {
		return lineMatch{}, false
	}
	return lineMatch{offset: best, severity: finding.SeverityHigh, message: msg}, true
}

func sg040Text(doc document, sc *snippetCache) []finding.Finding {
	return scanLines(doc, sc, "SG040", []lineMatcher{matchExcessivePermissionText})
}
