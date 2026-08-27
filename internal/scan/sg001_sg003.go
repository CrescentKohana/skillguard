package scan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

// countInvisibleOnLine scans runes for pred, skipping any index where skip
// (if non-nil) returns true. It returns the rune index of the first match,
// the total match count, and the distinct code points found, sorted ascending.
func countInvisibleOnLine(runes []rune, pred func(rune) bool, skip func([]rune, int) bool) (first, total int, codepoints []rune) {
	first = -1
	seen := map[rune]bool{}
	for idx, r := range runes {
		if !pred(r) {
			continue
		}
		if skip != nil && skip(runes, idx) {
			continue
		}
		if first == -1 {
			first = idx
		}
		total++
		if !seen[r] {
			seen[r] = true
			codepoints = append(codepoints, r)
		}
	}
	sort.Slice(codepoints, func(a, b int) bool { return codepoints[a] < codepoints[b] })
	return first, total, codepoints
}

func formatCodepointMessage(noun string, total int, codepoints []rune) string {
	word := noun + "s"
	if total == 1 {
		word = noun
	}
	parts := make([]string, len(codepoints))
	for i, r := range codepoints {
		parts[i] = fmt.Sprintf("U+%04X", r)
	}
	return fmt.Sprintf("%d %s (%s)", total, word, strings.Join(parts, ", "))
}

// sg001 detects zero-width and other invisible characters, excluding emoji ZWJ sequences.
func sg001(doc document, sc *snippetCache) []finding.Finding {
	var out []finding.Finding
	for i, line := range doc.lines {
		runes := []rune(line)
		first, total, cps := countInvisibleOnLine(runes, isZeroWidth, func(rs []rune, idx int) bool {
			return rs[idx] == 0x200D && isEmojiZWJException(rs, idx)
		})
		if total == 0 {
			continue
		}
		out = append(out, finding.Finding{
			RuleID:   "SG001",
			Severity: finding.SeverityHigh,
			Line:     i + 1,
			Column:   first + 1,
			Message:  formatCodepointMessage("zero-width character", total, cps),
			Snippet:  sc.at(i + 1),
		})
	}
	return out
}

// sg002 detects bidirectional-control characters.
func sg002(doc document, sc *snippetCache) []finding.Finding {
	var out []finding.Finding
	for i, line := range doc.lines {
		runes := []rune(line)
		first, total, cps := countInvisibleOnLine(runes, isBidi, nil)
		if total == 0 {
			continue
		}
		out = append(out, finding.Finding{
			RuleID:   "SG002",
			Severity: finding.SeverityHigh,
			Line:     i + 1,
			Column:   first + 1,
			Message:  formatCodepointMessage("bidirectional-control character", total, cps),
			Snippet:  sc.at(i + 1),
		})
	}
	return out
}

const maxDecodedTagRunes = 200

// decodeTagText decodes the ASCII text hidden in Unicode Tag characters
// (U+E0020-U+E007E) on line, used both for SG003 messages and to find
// secret-pattern matches hidden inside smuggled text.
func decodeTagText(line string) string {
	var b strings.Builder
	for _, r := range line {
		if r >= 0xE0020 && r <= 0xE007E {
			b.WriteRune(r - 0xE0000)
		}
	}
	return b.String()
}

// sg003 detects Unicode Tag block and variation-selector characters, hidden
// ASCII text from tag characters in U+E0020-U+E007E, decoded and masked in
// full before the message's 200-character truncation (G1).
func sg003(doc document, sc *snippetCache) []finding.Finding {
	var out []finding.Finding
	for i, line := range doc.lines {
		runes := []rune(line)
		first := -1
		total := 0
		for idx, r := range runes {
			if !isTagOrVariationSelector(r) {
				continue
			}
			if first == -1 {
				first = idx
			}
			total++
		}
		if total == 0 {
			continue
		}
		text := truncateKeepingMaskIntact(maskText(decodeTagText(line), nil), maxDecodedTagRunes)
		var msg string
		if text != "" {
			msg = "Unicode tag/variation-selector smuggling detected; hidden text: \"" + text + "\""
		} else {
			msg = fmt.Sprintf("Unicode tag/variation-selector smuggling detected (%d code points)", total)
		}
		out = append(out, finding.Finding{
			RuleID:   "SG003",
			Severity: finding.SeverityCritical,
			Line:     i + 1,
			Column:   first + 1,
			Message:  msg,
			Snippet:  sc.at(i + 1),
		})
	}
	return out
}
