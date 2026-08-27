package scan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

var exactSemverRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// extractPackageSpec returns the first non-flag argument, treating -p/--package
// as taking the following argument as the spec, per the npx/uvx conventions.
func extractPackageSpec(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-y", "--yes":
			continue
		case "-p", "--package":
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// splitAtVersion splits "name@version", handling a scoped "@scope/name@version".
func splitAtVersion(spec string) (name, version string) {
	searchFrom := 0
	if strings.HasPrefix(spec, "@") {
		searchFrom = 1
	}
	idx := strings.LastIndex(spec[searchFrom:], "@")
	if idx == -1 {
		return spec, ""
	}
	idx += searchFrom
	return spec[:idx], spec[idx+1:]
}

func npmStyleUnpinned(args []string) (spec string, sev finding.Severity, flagged bool) {
	spec = extractPackageSpec(args)
	if spec == "" {
		return "", 0, false
	}
	_, version := splitAtVersion(spec)
	if version != "" && exactSemverRe.MatchString(version) {
		return spec, 0, false
	}
	return spec, finding.SeverityMedium, true
}

func pipStyleUnpinned(args []string) (spec string, sev finding.Severity, flagged bool) {
	for i, a := range args {
		if a == "--from" && i+1 < len(args) {
			spec = args[i+1]
			break
		}
	}
	if spec == "" {
		spec = extractPackageSpec(args)
	}
	if spec == "" {
		return "", 0, false
	}
	var version string
	if idx := strings.Index(spec, "=="); idx != -1 {
		version = spec[idx+2:]
	} else {
		_, version = splitAtVersion(spec)
	}
	if version != "" && exactSemverRe.MatchString(version) {
		return spec, 0, false
	}
	return spec, finding.SeverityMedium, true
}

func dockerUnpinned(args []string) (image string, sev finding.Severity, flagged bool) {
	image = extractPackageSpec(args)
	if image == "" {
		return "", 0, false
	}
	if strings.Contains(image, "@sha256:") {
		return image, 0, false
	}
	last := image
	if idx := strings.LastIndex(image, "/"); idx != -1 {
		last = image[idx+1:]
	}
	if idx := strings.LastIndex(last, ":"); idx != -1 {
		tag := last[idx+1:]
		if tag != "latest" && tag != "" {
			return image, finding.SeverityLow, true
		}
	}
	return image, finding.SeverityMedium, true
}

// unpinnedSpec identifies the package/image spec for a server's runner
// command and reports whether it is unpinned, and at what severity.
func unpinnedSpec(command string, args []string) (spec string, sev finding.Severity, flagged bool) {
	switch command {
	case "npx", "bunx":
		return npmStyleUnpinned(args)
	case "pnpm":
		if len(args) > 0 && args[0] == "dlx" {
			return npmStyleUnpinned(args[1:])
		}
	case "yarn":
		if len(args) > 0 && args[0] == "dlx" {
			return npmStyleUnpinned(args[1:])
		}
	case "uvx":
		return pipStyleUnpinned(args)
	case "pipx":
		if len(args) > 0 && args[0] == "run" {
			return pipStyleUnpinned(args[1:])
		}
	case "uv":
		if len(args) > 1 && args[0] == "tool" && args[1] == "run" {
			return pipStyleUnpinned(args[2:])
		}
	case "docker":
		if len(args) > 0 && args[0] == "run" {
			return dockerUnpinned(args[1:])
		}
	}
	return "", 0, false
}

func sg050(doc document, stripped string, servers map[serverKey]mcpServerConfig, idx map[serverKey]serverSpan, sc *snippetCache) []finding.Finding {
	var out []finding.Finding
	for _, key := range sortedServerKeys(servers) {
		s := servers[key]
		if s.Command == "" || len(s.Args) == 0 {
			continue
		}
		spec, sev, flagged := unpinnedSpec(s.Command, s.Args)
		if !flagged {
			continue
		}
		line, col := 1, 1
		if start, end, hasBlock := serverBlockFor(idx, key); hasBlock {
			if specIdx := strings.Index(stripped[start:end], spec); specIdx != -1 {
				line, col = doc.locate(start + specIdx)
			}
		}
		out = append(out, finding.Finding{
			RuleID: "SG050", Severity: sev, Line: line, Column: col,
			Message: fmt.Sprintf("MCP server %q uses unpinned package %q", key, spec),
			Snippet: sc.at(line),
		})
	}
	return out
}
