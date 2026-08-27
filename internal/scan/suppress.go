package scan

import "regexp"

var (
	suppressKeywordRe = regexp.MustCompile(`skillguard-ignore`)
	suppressIDRe      = regexp.MustCompile(`\bSG\d{3}\b`)
)

// extractSuppressIDs returns the rule IDs named after "skillguard-ignore" on line.
func extractSuppressIDs(line string) []string {
	loc := suppressKeywordRe.FindStringIndex(line)
	if loc == nil {
		return nil
	}
	return suppressIDRe.FindAllString(line[loc[1]:], -1)
}

// buildSuppressions maps each 1-based line number to the set of rule IDs
// suppressed on it: a "skillguard-ignore" comment suppresses on its own line
// and on the next line.
func buildSuppressions(lines []string) map[int]map[string]bool {
	out := map[int]map[string]bool{}
	add := func(lineNum int, ids []string) {
		if out[lineNum] == nil {
			out[lineNum] = map[string]bool{}
		}
		for _, id := range ids {
			out[lineNum][id] = true
		}
	}
	for i, line := range lines {
		ids := extractSuppressIDs(line)
		if len(ids) == 0 {
			continue
		}
		lineNum := i + 1
		add(lineNum, ids)
		add(lineNum+1, ids)
	}
	return out
}
