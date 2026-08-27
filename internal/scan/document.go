package scan

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// document is a parsed file ready for rule evaluation: BOM-stripped content,
// its lines (trailing \r removed, per the line/column spec), and a byte-offset
// index used to map JSON key/value text back to a line and column.
type document struct {
	content    string
	lines      []string
	lineStarts []int
	// asciiLine[i] is true when lines[i] has no multi-byte UTF-8 sequence, so
	// locate() can use the byte offset directly instead of re-counting runes
	// from the line start on every call (costly for a huge, minified line).
	asciiLine []bool
}

func newDocument(raw []byte) document {
	content := string(raw)
	content = strings.TrimPrefix(content, "\uFEFF")

	rawLines := strings.Split(content, "\n")
	lines := make([]string, len(rawLines))
	starts := make([]int, len(rawLines))
	ascii := make([]bool, len(rawLines))
	offset := 0
	for i, rl := range rawLines {
		starts[i] = offset
		lines[i] = strings.TrimSuffix(rl, "\r")
		ascii[i] = isASCII(lines[i])
		offset += len(rl) + 1
	}
	return document{content: content, lines: lines, lineStarts: starts, asciiLine: ascii}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// locate maps a byte offset within doc.content to a 1-based (line, column) pair.
func (d document) locate(byteOffset int) (line, col int) {
	idx := sort.Search(len(d.lineStarts), func(i int) bool { return d.lineStarts[i] > byteOffset }) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(d.lines) {
		idx = len(d.lines) - 1
	}
	rel := byteOffset - d.lineStarts[idx]
	if rel < 0 {
		rel = 0
	}
	lineText := d.lines[idx]
	if rel > len(lineText) {
		rel = len(lineText)
	}
	if d.asciiLine[idx] {
		return idx + 1, rel + 1
	}
	return idx + 1, utf8.RuneCountInString(lineText[:rel]) + 1
}

// lineAt returns the 1-based line n, or "" if out of range.
func (d document) lineAt(n int) string {
	if n < 1 || n > len(d.lines) {
		return ""
	}
	return d.lines[n-1]
}
