package scan

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

var (
	downloadPipeRe    = regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|ksh|python3?|perl|ruby|node|iex|invoke-expression)\b`)
	procSubDownloadRe = regexp.MustCompile(`(?i)\b(bash|sh|source)\s+<\(\s*(curl|wget)\b`)
	evalDownloadRe    = regexp.MustCompile(`(?i)\beval\s+"?\$\(\s*(curl|wget)\b`)
	shCDownloadRe     = regexp.MustCompile(`(?i)\b(sh|bash)\s+-c\s+"\$\(\s*(curl|wget)\b`)
	base64PipeShellRe = regexp.MustCompile(`(?i)\bbase64\b[^|\n]*(-d\b|--decode\b|-D\b)[^|\n]*\|\s*(sh|bash|zsh)\b`)
	chmod777NumRe     = regexp.MustCompile(`\bchmod\b[^\n]*\b777\b`)
	chmodSetuidRe     = regexp.MustCompile(`\bchmod\b[^\n]*(u\+s\b|(^|\s)\+s(\s|$))`)
	// mkfsTokenRe matches an mkfs/mkfs.<fs> invocation token; matchMkfs then
	// requires a /dev/ or $-prefixed argument before any shell separator.
	mkfsTokenRe = regexp.MustCompile(`\bmkfs(\.[a-zA-Z0-9]+)?\b`)
	// rmCommandRe matches a standalone "rm" token (group 1), also when glued to JSON punctuation.
	rmCommandRe = regexp.MustCompile(`(?:^|[\s"'\[\],])(rm)(?:[\s"'\[\],]|$)`)
	// rmArgsEndRe marks where an rm command's arguments end: a shell separator or the close of
	// the JSON string holding the command.
	rmArgsEndRe = regexp.MustCompile(`[;|&]|"\s*[,\]}:]`)
	ddOfDiskRe  = regexp.MustCompile(`\bdd\b[^\n]*\bof=/dev/(sd[a-z]+|nvme\d+n\d+|disk\d*)\b`)
	forkBombRe  = regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`)
)

// dangerousRmTargets are the rm targets the spec calls catastrophic.
var dangerousRmTargets = map[string]bool{
	"/": true, "/*": true, "~": true, "~/": true, "~/*": true,
	"$HOME": true, "${HOME}": true, ".": true, "..": true, "*": true,
}

func matchDownloadPipeToInterpreter(line string) (lineMatch, bool) {
	if loc := downloadPipeRe.FindStringIndex(line); loc != nil {
		return lineMatch{offset: loc[0], severity: finding.SeverityHigh, message: "download piped directly into an interpreter"}, true
	}
	return lineMatch{}, false
}

func matchProcessSubstitutionDownload(line string) (lineMatch, bool) {
	for _, re := range []*regexp.Regexp{procSubDownloadRe, evalDownloadRe, shCDownloadRe} {
		if loc := re.FindStringIndex(line); loc != nil {
			return lineMatch{offset: loc[0], severity: finding.SeverityHigh, message: "process substitution or eval of a remote download"}, true
		}
	}
	return lineMatch{}, false
}

func matchBase64PipeToShell(line string) (lineMatch, bool) {
	if loc := base64PipeShellRe.FindStringIndex(line); loc != nil {
		return lineMatch{offset: loc[0], severity: finding.SeverityHigh, message: "base64-decoded data piped into a shell"}, true
	}
	return lineMatch{}, false
}

// isShellTokenSep reports whether r separates shell command tokens: either
// whitespace or JSON/array punctuation that can glue a bare word to
// adjacent syntax without a space (quotes, brackets, commas) (G2).
func isShellTokenSep(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	switch r {
	case '"', '\'', '[', ']', ',':
		return true
	}
	return false
}

// shellTokens splits line into command-like tokens so a command embedded in
// a JSON string or array (e.g. "args":["-c","rm -rf /"]) still tokenizes to
// its bare shell words (G2).
func shellTokens(line string) []string {
	return strings.FieldsFunc(line, isShellTokenSep)
}

func matchDangerousRm(line string) (lineMatch, bool) {
	for _, loc := range rmCommandRe.FindAllStringSubmatchIndex(line, -1) {
		args := line[loc[3]:]
		if end := rmArgsEndRe.FindStringIndex(args); end != nil {
			args = args[:end[0]]
		}
		if target, ok := catastrophicRmTarget(shellTokens(args)); ok {
			return lineMatch{offset: loc[2], severity: finding.SeverityHigh,
				message: fmt.Sprintf("rm -rf against a catastrophic target %q", target)}, true
		}
	}
	return lineMatch{}, false
}

func catastrophicRmTarget(args []string) (string, bool) {
	hasRecursive, hasForce := false, false
	target := ""
	for _, t := range args {
		t = strings.Trim(t, `\`)
		switch t {
		case "-rf", "-fr":
			hasRecursive, hasForce = true, true
		case "-r", "--recursive":
			hasRecursive = true
		case "-f", "--force":
			hasForce = true
		}
		if dangerousRmTargets[t] {
			target = t
		}
	}
	return target, hasRecursive && hasForce && target != ""
}

func matchChmodDangerous(line string) (lineMatch, bool) {
	best := -1
	if loc := chmod777NumRe.FindStringIndex(line); loc != nil {
		best = loc[0]
	}
	if loc := chmodSetuidRe.FindStringIndex(line); loc != nil && (best == -1 || loc[0] < best) {
		best = loc[0]
	}
	if best == -1 {
		return lineMatch{}, false
	}
	return lineMatch{offset: best, severity: finding.SeverityMedium, message: "chmod grants world-writable or setuid permissions"}, true
}

// matchMkfs reports the offset of an mkfs/mkfs.<fs> token that is followed,
// before any shell separator (`;`, `|`, `&`, end of line), by an argument
// token starting with `/dev/` or `$`; a bare mention of the word is not enough.
func matchMkfs(line string) (int, bool) {
	for _, loc := range mkfsTokenRe.FindAllStringIndex(line, -1) {
		rest := line[loc[1]:]
		if sepIdx := strings.IndexAny(rest, ";|&"); sepIdx != -1 {
			rest = rest[:sepIdx]
		}
		for _, tok := range shellTokens(rest) {
			if strings.HasPrefix(tok, "/dev/") || strings.HasPrefix(tok, "$") {
				return loc[0], true
			}
		}
	}
	return 0, false
}

func matchMkfsDdForkbomb(line string) (lineMatch, bool) {
	if offset, ok := matchMkfs(line); ok {
		return lineMatch{offset: offset, severity: finding.SeverityHigh, message: "filesystem-formatting command"}, true
	}
	if loc := ddOfDiskRe.FindStringIndex(line); loc != nil {
		return lineMatch{offset: loc[0], severity: finding.SeverityHigh, message: "dd writes directly to a disk device"}, true
	}
	if loc := forkBombRe.FindStringIndex(line); loc != nil {
		return lineMatch{offset: loc[0], severity: finding.SeverityHigh, message: "shell fork bomb"}, true
	}
	return lineMatch{}, false
}

func sg030(doc document, sc *snippetCache) []finding.Finding {
	return scanLines(doc, sc, "SG030", []lineMatcher{
		matchDownloadPipeToInterpreter,
		matchProcessSubstitutionDownload,
		matchBase64PipeToShell,
		matchDangerousRm,
		matchChmodDangerous,
		matchMkfsDdForkbomb,
	})
}

// sg030MCPCommand runs the rm check over each MCP server's command and args joined as one
// command line, catching the split form {"command":"rm","args":["-rf","/"]}.
func sg030MCPCommand(doc document, stripped string, servers map[serverKey]mcpServerConfig, idx map[serverKey]serverSpan, sc *snippetCache) []finding.Finding {
	var out []finding.Finding
	for _, key := range sortedServerKeys(servers) {
		s := servers[key]
		if s.Command == "" {
			continue
		}
		m, ok := matchDangerousRm(strings.Join(append([]string{s.Command}, s.Args...), " "))
		if !ok {
			continue
		}
		line, col := 1, 1
		if start, end, hasBlock := serverBlockFor(idx, key); hasBlock {
			line, col = locateKeyInBlock(doc, stripped, start, end, "command")
		}
		out = append(out, finding.Finding{
			RuleID: "SG030", Severity: m.severity, Line: line, Column: col,
			Message: fmt.Sprintf("MCP server %q: %s", key, m.message),
			Snippet: sc.at(line),
		})
	}
	return out
}
