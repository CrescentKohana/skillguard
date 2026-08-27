package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileKind identifies which family of detection rules apply to a file.
type FileKind string

const (
	KindSkill        FileKind = "skill"
	KindAgents       FileKind = "agents"
	KindKiroSteering FileKind = "kiro-steering"
	KindKiroHook     FileKind = "kiro-hook"
	KindMCPConfig    FileKind = "mcp-config"
	KindGeneric      FileKind = "generic"
)

// Target is a file selected for scanning.
type Target struct {
	Path string
	Kind FileKind
}

var mcpConfigBasenames = map[string]bool{
	".mcp.json":                  true,
	"mcp.json":                   true,
	"mcp_config.json":            true,
	"claude_desktop_config.json": true,
}

// Classify reports the kind of a path by basename and directory. ok is false
// for a path that matches none of the recognised kinds.
func Classify(path string) (FileKind, bool) {
	// filepath.ToSlash is a no-op off Windows; Classify must accept
	// Windows-style paths regardless of the host OS.
	slashPath := strings.ReplaceAll(path, "\\", "/")
	base := slashPath
	if idx := strings.LastIndex(slashPath, "/"); idx != -1 {
		base = slashPath[idx+1:]
	}

	switch strings.ToLower(base) {
	case "skill.md":
		return KindSkill, true
	case "agents.md":
		return KindAgents, true
	}
	if mcpConfigBasenames[base] {
		return KindMCPConfig, true
	}
	if strings.HasSuffix(base, ".kiro.hook") && underDir(slashPath, ".kiro/hooks") {
		return KindKiroHook, true
	}
	if strings.HasSuffix(base, ".md") && underDir(slashPath, ".kiro/steering") {
		return KindKiroSteering, true
	}
	return "", false
}

// underDir reports whether slashPath has dir as an ancestor directory.
func underDir(slashPath, dir string) bool {
	marker := "/" + dir + "/"
	return strings.Contains("/"+slashPath, marker)
}

var skippedDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
}

// Discover walks each root, skipping .git, node_modules, and vendor, and
// returns only classified files (KindGeneric for a file root that Classify
// can't place); a non-regular, non-directory root is an error; result sorted by Path.
func Discover(roots []string) ([]Target, error) {
	seen := map[string]bool{}
	var out []Target

	add := func(path string, kind FileKind) {
		p := filepath.ToSlash(path)
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, Target{Path: p, Kind: kind})
	}

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("%s: not a regular file", root)
			}
			kind, ok := Classify(root)
			if !ok {
				kind = KindGeneric
			}
			add(root, kind)
			continue
		}

		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != root && skippedDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			kind, ok := Classify(path)
			if !ok {
				return nil
			}
			add(path, kind)
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
