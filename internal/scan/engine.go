package scan

import (
	"unicode/utf8"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

// lineMatch is a candidate hit on one line. offset is the byte offset of the
// match within the (already \r-trimmed) line, used to compute the reported
// column and to pick the earliest match when several matchers fire.
type lineMatch struct {
	offset   int
	severity finding.Severity
	message  string
}

type lineMatcher func(line string) (lineMatch, bool)

// scanLines runs every matcher over every line and keeps, per rule per line,
// only the match with the smallest offset (the "first match on the line").
func scanLines(doc document, sc *snippetCache, ruleID string, matchers []lineMatcher) []finding.Finding {
	var out []finding.Finding
	for i, line := range doc.lines {
		found := false
		var best lineMatch
		for _, m := range matchers {
			lm, ok := m(line)
			if !ok {
				continue
			}
			if !found || lm.offset < best.offset {
				best = lm
				found = true
			}
		}
		if !found {
			continue
		}
		out = append(out, finding.Finding{
			RuleID:   ruleID,
			Severity: best.severity,
			Line:     i + 1,
			Column:   utf8.RuneCountInString(line[:best.offset]) + 1,
			Message:  best.message,
			Snippet:  sc.at(i + 1),
		})
	}
	return out
}
