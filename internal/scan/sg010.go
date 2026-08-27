package scan

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

// sg010Patterns match English prompt-injection phrase families on a
// normalized line: full-width folded, invisible characters removed,
// lower-cased, and whitespace runs collapsed to a single space.
var sg010Patterns = []*regexp.Regexp{
	regexp.MustCompile(`\bignore\b.{0,40}\b(previous|prior|above|preceding)\b.{0,20}\b(instructions?|rules?|guidelines?)\b`),
	regexp.MustCompile(`\bdisregard\b.{0,40}\b(previous|prior|above|your)\b.{0,30}\b(guidelines?|instructions?|rules?)\b`),
	regexp.MustCompile(`\bforget\b.{0,60}\b(instructions?|you were told|rules?)\b`),
	regexp.MustCompile(`\byou are now\b.{0,25}\b(developer mode|dan)\b`),
	regexp.MustCompile(`\b(do not|don't|without)\b.{0,30}\b(tell|mention|inform|telling|notify|notifying)\b.{0,20}\b(the user|users?)\b`),
	regexp.MustCompile(`\b(reveal|print|show|display)\b.{0,20}\b(your |the )?system prompt\b`),
	regexp.MustCompile(`\brepeat\b.{0,20}\babove\b.{0,20}\bverbatim\b`),
	regexp.MustCompile(`\bnew system instructions\b`),
	regexp.MustCompile(`\bsystem override\b`),
	regexp.MustCompile(`\boverride\b.{0,20}\bsafety instructions\b`),
}

// sg010Literals are exact substrings checked case-insensitively against the
// normalized line: chat-template role tokens and Japanese injection phrases.
var sg010Literals = []string{
	"<|im_start|>system",
	"<|system|>",
	"[inst]",
	"<<sys>>",
	"以前の指示を無視して",
	"これまでの指示をすべて無視",
	"上記の指示を無視",
	"ユーザーには伝えないで",
	"ユーザーに知らせずに",
	"システムプロンプトを表示して",
}

// foldFullWidth maps full-width ASCII and the ideographic space to their
// ASCII equivalents, defeating full-width obfuscation of English phrases.
func foldFullWidth(r rune) rune {
	switch {
	case r >= 0xFF01 && r <= 0xFF5E:
		return r - 0xFF01 + 0x21
	case r == 0x3000:
		return ' '
	default:
		return r
	}
}

// normalizeLine builds the folded/lower-cased/whitespace-collapsed line used
// for SG010 matching, along with a mapping from each rune of the normalized
// string back to its original rune index in line.
func normalizeLine(line string) (normalized string, mapping []int) {
	runes := []rune(line)
	var out []rune
	prevSpace := false
	for idx, r := range runes {
		if isInvisible(r) {
			continue
		}
		folded := unicode.ToLower(foldFullWidth(r))
		if folded == ' ' || unicode.IsSpace(folded) {
			if prevSpace {
				continue
			}
			prevSpace = true
			folded = ' '
		} else {
			prevSpace = false
		}
		out = append(out, folded)
		mapping = append(mapping, idx)
	}
	return string(out), mapping
}

// originalExcerpt returns the original-line text behind normalized runes [from, to), so the
// message quotes the line as written and secret masking (case-sensitive) still applies.
func originalExcerpt(line string, mapping []int, from, to int) string {
	if from >= to || to > len(mapping) {
		return ""
	}
	runes := []rune(line)
	return string(runes[mapping[from] : mapping[to-1]+1])
}

// sg010 detects English and Japanese prompt-injection phrasing.
func sg010(doc document, sc *snippetCache) []finding.Finding {
	var out []finding.Finding
	for i, line := range doc.lines {
		norm, mapping := normalizeLine(line)
		if norm == "" {
			continue
		}
		bestStart, bestEnd := -1, -1
		consider := func(start, end int) {
			if bestStart == -1 || start < bestStart {
				bestStart, bestEnd = start, end
			}
		}
		for _, re := range sg010Patterns {
			if loc := re.FindStringIndex(norm); loc != nil {
				consider(loc[0], loc[1])
			}
		}
		lowerNorm := norm // already lower-cased by normalizeLine
		for _, lit := range sg010Literals {
			if idx := strings.Index(lowerNorm, lit); idx != -1 {
				consider(idx, idx+len(lit))
			}
		}
		if bestStart == -1 {
			continue
		}
		runeIdx := utf8.RuneCountInString(norm[:bestStart])
		origIdx := 0
		switch {
		case runeIdx < len(mapping):
			origIdx = mapping[runeIdx]
		case len(mapping) > 0:
			origIdx = mapping[len(mapping)-1]
		}
		excerpt := renderInvisible(truncateRunes(originalExcerpt(line, mapping, runeIdx, utf8.RuneCountInString(norm[:bestEnd])), maxSnippetRunes))
		out = append(out, finding.Finding{
			RuleID:   "SG010",
			Severity: finding.SeverityHigh,
			Line:     i + 1,
			Column:   origIdx + 1,
			Message:  fmt.Sprintf("prompt-injection phrase detected: %q", excerpt),
			Snippet:  sc.at(i + 1),
		})
	}
	return out
}
