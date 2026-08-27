package scan

import (
	"fmt"
	"regexp"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

var (
	mdImageRe = regexp.MustCompile(`!\[[^\]]*\]\((https?://[^)\s]+)\)`)
	htmlImgRe = regexp.MustCompile(`(?i)<img\b[^>]*\bsrc=["']?(https?://[^"'>\s]+)`)
	// placeholderRe matches the data-placeholder markers listed in the spec:
	// {{...}}, {...}, ${...}, $NAME, <...>, %7B/%7b, [...].
	placeholderRe = regexp.MustCompile(`\{\{[^}]*\}\}|\$\{[^}]*\}|\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]*>|%7[Bb]|\[[^\]]*\]`)
)

// matchMarkdownImageExfil checks every Markdown image and every <img> on the
// line (not just the first), reporting the earliest one with a URL that
// contains a data placeholder.
func matchMarkdownImageExfil(line string) (lineMatch, bool) {
	best := -1
	var msg string
	check := func(re *regexp.Regexp, label string) {
		for _, loc := range re.FindAllStringSubmatchIndex(line, -1) {
			u := line[loc[2]:loc[3]]
			if !placeholderRe.MatchString(u) {
				continue
			}
			if best == -1 || loc[0] < best {
				best = loc[0]
				msg = fmt.Sprintf("%s contains a data placeholder: %s", label, u)
			}
		}
	}
	check(mdImageRe, "markdown image URL")
	check(htmlImgRe, "HTML image src")
	if best == -1 {
		return lineMatch{}, false
	}
	return lineMatch{offset: best, severity: finding.SeverityHigh, message: msg}, true
}

func sg021(doc document, sc *snippetCache) []finding.Finding {
	return scanLines(doc, sc, "SG021", []lineMatcher{matchMarkdownImageExfil})
}
