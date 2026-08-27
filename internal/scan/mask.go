package scan

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// span is a half-open byte range marked for redaction within some text.
type span struct{ start, end int }

// mergeSpans sorts spans by start and unions any that overlap or touch, so
// a single left-to-right splice never lets one match destroy or extend
// another (G1).
func mergeSpans(spans []span) []span {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})
	out := make([]span, 0, len(spans))
	cur := spans[0]
	for _, s := range spans[1:] {
		if s.start > cur.end {
			out = append(out, cur)
			cur = s
			continue
		}
		if s.end > cur.end {
			cur.end = s.end
		}
	}
	return append(out, cur)
}

// spliceMask merges spans, clamps them to text and replaces each with maskSecret of its
// contents in one left-to-right pass; clamping never drops a partly in-range secret.
func spliceMask(text string, spans []span) string {
	spans = mergeSpans(spans)
	if len(spans) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, s := range spans {
		s.start = max(s.start, 0)
		s.end = min(s.end, len(text))
		if s.start >= s.end {
			continue
		}
		b.WriteString(text[last:s.start])
		b.WriteString(maskSecret(text[s.start:s.end]))
		last = s.end
	}
	b.WriteString(text[last:])
	return b.String()
}

// collectPatternSpans returns the byte spans of every SG060 provider
// pattern match in text, using each pattern's boundary-free masking variant
// so a secret directly adjoining other text is caught as a whole span (G1.1.a).
func collectPatternSpans(text string) []span {
	var out []span
	for _, sp := range secretPatterns {
		for _, loc := range sp.maskRe.FindAllStringIndex(text, -1) {
			out = append(out, span{loc[0], loc[1]})
		}
	}
	return out
}

// kvValueRe matches, anchored after a key, optional block comments, `:` or `=`, and a quoted
// value (group 1, quotes included). `//` comments are excluded: they run to end of line, so no
// value can follow them, and allowing them let a URL swallow a later credential pair.
var kvValueRe = regexp.MustCompile(`^\s*(?:/\*[^*]*\*+(?:[^/*][^*]*\*+)*/\s*)*[:=]\s*(?:/\*[^*]*\*+(?:[^/*][^*]*\*+)*/\s*)*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')`)

// maxMaskExemptPlaceholderRunes limits the placeholder exemption for masking: a long value that
// merely contains a word like "xxxx" is still masked, since over-masking is harmless.
const maxMaskExemptPlaceholderRunes = 64

// maxQuotedKeyTailBytes bounds how far past a credential word a quoted key's closing quote is
// searched for ("my key name"), keeping the scan linear in the line length.
const maxQuotedKeyTailBytes = 64

func isKeyByte(b byte) bool {
	return b == '_' || b == '.' || b == '-' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// maskExempt reports whether a key/value literal is too short, or a short placeholder, to mask.
func maskExempt(val string) bool {
	n := utf8.RuneCountInString(val)
	return n < 8 || (n <= maxMaskExemptPlaceholderRunes && isPlaceholderValue(val))
}

// collectKVFallbackSpans returns the byte spans of quoted values whose key contains a
// credential word (secretKeyRe). It anchors on each credential word, so no earlier text on the
// line can swallow the pair, and skips words inside an already-consumed key run to stay linear.
func collectKVFallbackSpans(text string) []span {
	var out []span
	runEnd := 0
	for _, w := range secretKeyRe.FindAllStringIndex(text, -1) {
		if w[0] < runEnd {
			continue
		}
		keyEnd := w[1]
		for keyEnd < len(text) && isKeyByte(text[keyEnd]) {
			keyEnd++
		}
		runEnd = keyEnd
		for _, candidate := range keyEndCandidates(text, keyEnd) {
			m := kvValueRe.FindStringSubmatchIndex(text[candidate:])
			if m == nil {
				continue
			}
			valStart, valEnd := candidate+m[2]+1, candidate+m[3]-1
			if !maskExempt(text[valStart:valEnd]) {
				out = append(out, span{valStart, valEnd})
			}
			break
		}
	}
	return out
}

// keyEndCandidates returns where a key ending at runEnd may close: right there, after a closing
// quote, or after the closing quote of a quoted key with more words ("my key name").
func keyEndCandidates(text string, runEnd int) []int {
	candidates := []int{runEnd}
	if runEnd < len(text) && (text[runEnd] == '"' || text[runEnd] == '\'') {
		return append(candidates, runEnd+1)
	}
	limit := min(runEnd+maxQuotedKeyTailBytes, len(text))
	if q := strings.IndexAny(text[runEnd:limit], `"'`); q > 0 {
		candidates = append(candidates, runEnd+q+1)
	}
	return candidates
}

// maskText masks every SG060 pattern match and credential-shaped key/value
// literal in text, plus any caller-supplied spans in text's own byte
// coordinates (structurally-detected secrets, G1.1.b), in one splice (G1).
func maskText(text string, extra []span) string {
	spans := collectPatternSpans(text)
	spans = append(spans, collectKVFallbackSpans(text)...)
	spans = append(spans, extra...)
	return spliceMask(text, spans)
}

// collectLineSecretSpans returns the merged redaction spans found directly
// in lineText (patterns, kv-fallback, and the caller's structural spans),
// the same detection buildSnippet uses.
func collectLineSecretSpans(lineText string, structural []span) []span {
	spans := collectPatternSpans(lineText)
	spans = append(spans, collectKVFallbackSpans(lineText)...)
	spans = append(spans, structural...)
	return mergeSpans(spans)
}

// knownSubstringSet returns every knownSubstringWindow-rune window of the spans' text in
// lineText; keys are substrings of lineText, so building the set copies no text.
func knownSubstringSet(lineText string, spans []span) map[string]bool {
	set := map[string]bool{}
	var starts []int
	for _, sp := range spans {
		starts = starts[:0]
		for pos := range lineText[sp.start:sp.end] {
			starts = append(starts, sp.start+pos)
		}
		starts = append(starts, sp.end)
		for i := 0; i+knownSubstringWindow < len(starts); i++ {
			set[lineText[starts[i]:starts[i+knownSubstringWindow]]] = true
		}
	}
	return set
}

// collectKnownSubstringSpans returns the byte spans in text of every
// knownSubstringWindow-rune run that also appears in known.
func collectKnownSubstringSpans(text string, known map[string]bool) []span {
	if len(known) == 0 {
		return nil
	}
	runes := []rune(text)
	if len(runes) < knownSubstringWindow {
		return nil
	}
	offsets := make([]int, len(runes)+1)
	off := 0
	for i, r := range runes {
		offsets[i] = off
		off += utf8.RuneLen(r)
	}
	offsets[len(runes)] = off

	var spans []span
	for i := 0; i+knownSubstringWindow <= len(runes); i++ {
		if known[string(runes[i:i+knownSubstringWindow])] {
			spans = append(spans, span{offsets[i], offsets[i+knownSubstringWindow]})
		}
	}
	return spans
}

// maskMessage masks message like maskText, plus any run coincidentally
// matching a window of a secret found elsewhere on the same line (known),
// so a fixed literal (e.g. a flag name) can't leak a fragment of one (G1).
func maskMessage(message string, known map[string]bool) string {
	spans := collectPatternSpans(message)
	spans = append(spans, collectKVFallbackSpans(message)...)
	spans = append(spans, collectKnownSubstringSpans(message, known)...)
	return spliceMask(message, spans)
}
