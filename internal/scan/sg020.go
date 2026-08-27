package scan

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

var (
	curlWordRe           = regexp.MustCompile(`\bcurl\b`)
	wgetWordRe           = regexp.MustCompile(`\bwget\b`)
	curlUploadLongFlagRe = regexp.MustCompile(`(^|\s)(--data|--data-raw|--data-binary|--data-urlencode|--form|--upload-file)(=|\s|@|$)`)
	// curlUploadShortFlagRe matches a short-option cluster (e.g. "-sd",
	// "-sSF") containing one of curl's data-upload flags (d, F, T), whether
	// its value is a separate argument or attached directly ("-d@file").
	curlUploadShortFlagRe = regexp.MustCompile(`(^|\s)-[A-Za-z]*[dFT][A-Za-z]*(=|@|\s|$)`)
	wgetPostFlagRe        = regexp.MustCompile(`(^|\s)(--post-data|--post-file|--body-data)(=|\s|$)`)
	shellExpansionRe      = regexp.MustCompile("\\$\\{[^}]+\\}|\\$\\([^)]*\\)|\\$[A-Za-z_][A-Za-z0-9_]*|`[^`]*`")
	pipeToNetToolRe       = regexp.MustCompile(`\|\s*(nc|ncat|netcat|curl)\b`)
	psWebCmdRe            = regexp.MustCompile(`(?i)\b(invoke-webrequest|invoke-restmethod|iwr|irm)\b`)
	psBodyOrPostRe        = regexp.MustCompile(`(?i)-body\b|-method\s+post\b`)
	httpURLRe             = regexp.MustCompile(`https?://[^\s'"<>)]+`)
	// sg020URLTokenRe captures a URL up to the next whitespace, wider than
	// httpURLRe, so a process-substitution construct like "$(whoami)" inside
	// the URL keeps its closing parenthesis for the inside-URL check below.
	sg020URLTokenRe = regexp.MustCompile(`https?://\S+`)
)

// oobHosts are known out-of-band / request-capture hosts used to confirm
// blind exfiltration.
var oobHosts = []string{
	"webhook.site", "requestbin.com", "requestbin.net", "pipedream.net",
	"ngrok.io", "ngrok-free.app", "ngrok.app", "burpcollaborator.net",
	"oastify.com", "interact.sh", "oast.pro", "oast.fun", "beeceptor.com",
	"hookbin.com", "canarytokens.com",
}

func firstNonLocalHTTPHost(line string) (string, bool) {
	for _, m := range httpURLRe.FindAllString(line, -1) {
		u, err := url.Parse(m)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
			continue
		}
		return host, true
	}
	return "", false
}

func matchCurlUpload(line string) (lineMatch, bool) {
	if !curlWordRe.MatchString(line) {
		return lineMatch{}, false
	}
	loc := curlUploadLongFlagRe.FindStringIndex(line)
	if shortLoc := curlUploadShortFlagRe.FindStringIndex(line); shortLoc != nil && (loc == nil || shortLoc[0] < loc[0]) {
		loc = shortLoc
	}
	if loc == nil {
		return lineMatch{}, false
	}
	host, ok := firstNonLocalHTTPHost(line)
	if !ok {
		return lineMatch{}, false
	}
	return lineMatch{offset: loc[0], severity: finding.SeverityHigh,
		message: fmt.Sprintf("curl uploads data to a non-local host %q", host)}, true
}

func matchWgetPost(line string) (lineMatch, bool) {
	if !wgetWordRe.MatchString(line) {
		return lineMatch{}, false
	}
	loc := wgetPostFlagRe.FindStringIndex(line)
	if loc == nil {
		return lineMatch{}, false
	}
	return lineMatch{offset: loc[0], severity: finding.SeverityHigh, message: "wget sends a POST body"}, true
}

// matchShellExpansionURL fires only when the shell-expansion construct sits
// inside the URL itself, not elsewhere on the line (e.g. an unrelated "-o
// $HOME/..." output-file argument).
func matchShellExpansionURL(line string) (lineMatch, bool) {
	if !curlWordRe.MatchString(line) && !wgetWordRe.MatchString(line) {
		return lineMatch{}, false
	}
	for _, loc := range sg020URLTokenRe.FindAllStringIndex(line, -1) {
		urlText := line[loc[0]:loc[1]]
		if m := shellExpansionRe.FindStringIndex(urlText); m != nil {
			return lineMatch{offset: loc[0] + m[0], severity: finding.SeverityHigh,
				message: "curl/wget URL contains a shell expansion"}, true
		}
	}
	return lineMatch{}, false
}

func matchPipeToNetTool(line string) (lineMatch, bool) {
	if loc := pipeToNetToolRe.FindStringIndex(line); loc != nil {
		return lineMatch{offset: loc[0], severity: finding.SeverityHigh, message: "output piped to a network tool"}, true
	}
	if idx := strings.Index(line, "/dev/tcp/"); idx != -1 {
		return lineMatch{offset: idx, severity: finding.SeverityHigh, message: "redirection to /dev/tcp/"}, true
	}
	return lineMatch{}, false
}

func matchPowerShellExfil(line string) (lineMatch, bool) {
	loc := psWebCmdRe.FindStringIndex(line)
	if loc == nil || !psBodyOrPostRe.MatchString(line) {
		return lineMatch{}, false
	}
	return lineMatch{offset: loc[0], severity: finding.SeverityHigh, message: "PowerShell web request sends a body"}, true
}

// oobHostMatch reports whether host is, or is a subdomain of, one of the
// known out-of-band hosts.
func oobHostMatch(host string) (string, bool) {
	for _, h := range oobHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return h, true
		}
	}
	return "", false
}

// matchOOBHost checks every URL's host on the line (not a raw substring of
// the line, which would also match prose mentioning a host name with no URL).
func matchOOBHost(line string) (lineMatch, bool) {
	for _, loc := range httpURLRe.FindAllStringIndex(line, -1) {
		u, err := url.Parse(line[loc[0]:loc[1]])
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if h, ok := oobHostMatch(host); ok {
			return lineMatch{offset: loc[0], severity: finding.SeverityHigh,
				message: fmt.Sprintf("references a known out-of-band host %q", h)}, true
		}
	}
	return lineMatch{}, false
}

func sg020(doc document, sc *snippetCache) []finding.Finding {
	return scanLines(doc, sc, "SG020", []lineMatcher{
		matchCurlUpload,
		matchWgetPost,
		matchShellExpansionURL,
		matchPipeToNetTool,
		matchPowerShellExfil,
		matchOOBHost,
	})
}
