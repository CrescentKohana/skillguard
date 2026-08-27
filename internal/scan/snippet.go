package scan

import (
	"fmt"
	"strings"
)

const maxSnippetRunes = 200

// buildSnippet masks the whole line before trimming and truncating to maxSnippetRunes, so a
// secret straddling the cut is still masked; a mask marker is never split.
func buildSnippet(line string, spans []span) string {
	masked := spliceMask(line, spans)
	trimmed := strings.TrimSpace(masked)
	return renderInvisible(truncateKeepingMaskIntact(trimmed, maxSnippetRunes))
}

// renderInvisible spells invisible and bidi characters as <U+XXXX> so output never carries them raw.
func renderInvisible(s string) string {
	var b strings.Builder
	for _, r := range s {
		if isInvisible(r) {
			fmt.Fprintf(&b, "<U+%04X>", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// snippetCache memoizes the masked, truncated snippet per line: several
// rules can report findings on the same line, and masking must run at most
// once per line regardless of how many findings reference it (G1).
type snippetCache struct {
	doc        document
	extra      map[int][]span
	spans      map[int][]span
	cache      map[int]string
	secretSets map[int]map[string]bool
}

// newSnippetCache builds a cache over doc; extra supplies, per 1-based
// line, the structurally-detected secret spans (G1.1.b) already rebased to
// that line's own byte offsets. extra may be nil for non-MCP documents.
func newSnippetCache(doc document, extra map[int][]span) *snippetCache {
	return &snippetCache{doc: doc, extra: extra, spans: map[int][]span{}, cache: map[int]string{}, secretSets: map[int]map[string]bool{}}
}

// lineSpans memoizes the merged secret spans of line n; detection is the costly step and both
// the snippet and the message fragment set need it.
func (c *snippetCache) lineSpans(n int) []span {
	if s, ok := c.spans[n]; ok {
		return s
	}
	s := collectLineSecretSpans(c.doc.lineAt(n), c.extra[n])
	c.spans[n] = s
	return s
}

func (c *snippetCache) at(line int) string {
	if s, ok := c.cache[line]; ok {
		return s
	}
	s := buildSnippet(c.doc.lineAt(line), c.lineSpans(line))
	c.cache[line] = s
	return s
}

// knownSecretWindows returns, memoized per line, the fragment set of every
// secret detected directly on line n, so a different finding's message
// quoting one of those fragments by coincidence can still be masked.
func (c *snippetCache) knownSecretWindows(line int) map[string]bool {
	if s, ok := c.secretSets[line]; ok {
		return s
	}
	lineText := c.doc.lineAt(line)
	s := knownSubstringSet(lineText, c.lineSpans(line))
	c.secretSets[line] = s
	return s
}

// maskPrefixRunes is how many leading runes of a secret output may disclose.
const maskPrefixRunes = 4

// knownSubstringWindow is the shortest secret fragment that may not appear in output: one rune
// more than maskSecret discloses.
const knownSubstringWindow = maskPrefixRunes + 1

// maskSecret keeps at most the first maskPrefixRunes runes of a secret and masks the rest.
func maskSecret(secret string) string {
	runes := []rune(secret)
	n := maskPrefixRunes
	if len(runes) < n {
		n = len(runes)
	}
	return string(runes[:n]) + "****"
}

// truncateKeepingMaskIntact slices masked to at most max runes, extending the
// cut past any run of literal `*` so a maskSecret marker is never left
// half-visible by landing the truncation inside its trailing asterisks.
func truncateKeepingMaskIntact(masked string, max int) string {
	runes := []rune(masked)
	if len(runes) <= max {
		return masked
	}
	cut := max
	for cut < len(runes) && runes[cut] == '*' {
		cut++
	}
	return string(runes[:cut])
}

// unquote strips one layer of surrounding single or double quotes, used to
// read the same value from a quoted shell or YAML token as from a bare one.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
