// Package scan discovers AI-agent skill and configuration files and runs
// SkillGuard's detection rules over their content.
package scan

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

const maxScannableFileSize = 5 * 1024 * 1024 // 5 MiB

// neverSuppressible holds the rule IDs that inline suppression can never silence.
var neverSuppressible = map[string]bool{"SG001": true, "SG002": true, "SG003": true}

// Result is the outcome of a Scan.
type Result struct {
	// Findings is sorted stably by Path, Line, Column, RuleID, Message (G3).
	Findings   []finding.Finding
	Suppressed int
	Files      int
	// Warnings names, per unparseable file (e.g. an MCP config that isn't
	// valid JSON(C)), the file and the reason; never affects the exit code.
	Warnings []string
}

// findingLess is a total order over findings: Path, Line, Column, RuleID,
// then Message, matching G3's required sort key.
func findingLess(a, b finding.Finding) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.Column != b.Column {
		return a.Column < b.Column
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	return a.Message < b.Message
}

// ScanContent runs every applicable rule over one file's bytes. Pure: no
// filesystem access. Findings are sorted stably by Line, Column, RuleID,
// Message; suppressed findings are removed.
func ScanContent(path string, kind FileKind, content []byte) []finding.Finding {
	out, _, _ := scanContent(path, kind, content)
	return out
}

func scanContent(path string, kind FileKind, content []byte) (out []finding.Finding, suppressedCount int, warnings []string) {
	doc := newDocument(content)
	suppressions := buildSuppressions(doc.lines)

	var mcpServers map[serverKey]mcpServerConfig
	var mcpIndex map[serverKey]serverSpan
	var stripped string
	structuralSpans := map[int][]span{}
	if kind == KindMCPConfig {
		stripped = stripJSONC(doc.content)
		servers, fieldWarnings, err := parseMCPConfig(path, stripped)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: cannot parse MCP config: %v", path, err))
		} else {
			mcpServers = servers
			var secretSpans []span
			mcpIndex, secretSpans = buildMCPStructuralIndex(stripped)
			structuralSpans = groupSpansByLine(doc, secretSpans)
			warnings = append(warnings, fieldWarnings...)
		}
	}
	sc := newSnippetCache(doc, structuralSpans)

	var raw []finding.Finding
	raw = append(raw, sg001(doc, sc)...)
	raw = append(raw, sg002(doc, sc)...)
	raw = append(raw, sg003(doc, sc)...)
	raw = append(raw, sg010(doc, sc)...)
	raw = append(raw, sg020(doc, sc)...)
	raw = append(raw, sg021(doc, sc)...)
	raw = append(raw, sg030(doc, sc)...)
	raw = append(raw, sg031(doc, sc)...)
	raw = append(raw, sg040Text(doc, sc)...)
	raw = append(raw, sg060Pattern(doc, sc)...)

	switch kind {
	case KindMCPConfig:
		if mcpServers != nil {
			raw = append(raw, sg040MCPJSON(doc, stripped, mcpServers, mcpIndex, sc)...)
			raw = append(raw, sg050(doc, stripped, mcpServers, mcpIndex, sc)...)
			raw = appendUnlessRuleOnLine(raw, sg030MCPCommand(doc, stripped, mcpServers, mcpIndex, sc))
			raw = append(raw, sg060JSONEnv(doc, stripped, mcpServers, mcpIndex, sc)...)
		}
	case KindKiroHook:
		raw = append(raw, sg040HookJSON(doc, sc)...)
	case KindSkill:
		raw = append(raw, sg040FrontMatter(doc, sc)...)
	}

	// Snippets are masked at construction; messages are masked here, also
	// against any fragment shared with a secret elsewhere on that line (G1).
	for i := range raw {
		raw[i].Message = maskMessage(raw[i].Message, sc.knownSecretWindows(raw[i].Line))
	}

	for i := range raw {
		raw[i].Path = path
		f := raw[i]
		if !neverSuppressible[f.RuleID] && suppressions[f.Line][f.RuleID] {
			suppressedCount++
			continue
		}
		out = append(out, f)
	}

	sort.SliceStable(out, func(i, j int) bool { return findingLess(out[i], out[j]) })

	for i := range warnings {
		warnings[i] = maskText(warnings[i], nil)
	}
	return out, suppressedCount, warnings
}

// groupSpansByLine maps each absolute byte span in doc's content to the
// 1-based line it falls on, rebased to that line's own byte offset so
// buildSnippet can apply it directly to the line's text.
func groupSpansByLine(doc document, spans []span) map[int][]span {
	out := map[int][]span{}
	for _, s := range spans {
		line, _ := doc.locate(s.start)
		base := doc.lineStarts[line-1]
		out[line] = append(out[line], span{s.start - base, s.end - base})
	}
	return out
}

// readBounded opens path once and reads at most maxScannableFileSize+1
// bytes from that handle, so size-checking and reading never race against a
// file changing between a separate stat and read; tooLarge means over limit.
func readBounded(path string) (content []byte, tooLarge bool, err error) {
	f, err := os.Open(path) //nolint:gosec // G304: path comes from Discover, which only returns regular files it found itself
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.Size() > maxScannableFileSize {
		return nil, true, nil
	}

	data, err := io.ReadAll(io.LimitReader(f, maxScannableFileSize+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxScannableFileSize {
		return nil, true, nil
	}
	return data, false, nil
}

// Scan discovers files under roots, reads them, and runs ScanContent over
// each. Files larger than 5 MiB are skipped with no finding, not an error.
func Scan(roots []string) (Result, error) {
	targets, err := Discover(roots)
	if err != nil {
		return Result{}, err
	}

	var res Result
	for _, t := range targets {
		content, tooLarge, err := readBounded(t.Path)
		if err != nil {
			return Result{}, err
		}
		if tooLarge {
			continue
		}
		res.Files++
		findings, suppressed, warnings := scanContent(t.Path, t.Kind, content)
		res.Findings = append(res.Findings, findings...)
		res.Suppressed += suppressed
		res.Warnings = append(res.Warnings, warnings...)
	}

	sort.SliceStable(res.Findings, func(i, j int) bool { return findingLess(res.Findings[i], res.Findings[j]) })
	return res, nil
}

// appendUnlessRuleOnLine merges extra into raw keeping at most one finding per rule per line;
// on a collision the lower column wins, since the first match on a line gives the column.
func appendUnlessRuleOnLine(raw, extra []finding.Finding) []finding.Finding {
	type ruleLine struct {
		rule string
		line int
	}
	at := map[ruleLine]int{}
	for i, f := range raw {
		at[ruleLine{f.RuleID, f.Line}] = i
	}
	for _, f := range extra {
		k := ruleLine{f.RuleID, f.Line}
		if i, ok := at[k]; ok {
			if f.Column < raw[i].Column {
				raw[i] = f
			}
			continue
		}
		at[k] = len(raw)
		raw = append(raw, f)
	}
	return raw
}
