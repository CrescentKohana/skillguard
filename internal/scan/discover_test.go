package scan_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func TestDiscoverWalksAndClassifies(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "SKILL.md"), "# skill\n")
	writeFile(t, filepath.Join(root, "AGENTS.md"), "# agents\n")
	writeFile(t, filepath.Join(root, ".kiro", "steering", "style.md"), "# style\n")
	writeFile(t, filepath.Join(root, ".kiro", "hooks", "on-save.kiro.hook"), "{}\n")
	writeFile(t, filepath.Join(root, ".mcp.json"), "{}\n")
	writeFile(t, filepath.Join(root, "README.md"), "# not classified\n")

	writeFile(t, filepath.Join(root, ".git", "SKILL.md"), "# must be skipped\n")
	writeFile(t, filepath.Join(root, "node_modules", "pkg", "mcp.json"), "{}\n")
	writeFile(t, filepath.Join(root, "vendor", "lib", "AGENTS.md"), "# must be skipped\n")

	targets, err := scan.Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover(%q): unexpected error: %v", root, err)
	}

	wantPaths := map[string]scan.FileKind{
		filepath.ToSlash(filepath.Join(root, "SKILL.md")):                      scan.KindSkill,
		filepath.ToSlash(filepath.Join(root, "AGENTS.md")):                     scan.KindAgents,
		filepath.ToSlash(filepath.Join(root, ".kiro/steering/style.md")):       scan.KindKiroSteering,
		filepath.ToSlash(filepath.Join(root, ".kiro/hooks/on-save.kiro.hook")): scan.KindKiroHook,
		filepath.ToSlash(filepath.Join(root, ".mcp.json")):                     scan.KindMCPConfig,
	}

	if len(targets) != len(wantPaths) {
		t.Fatalf("Discover returned %d targets, want %d; got %+v", len(targets), len(wantPaths), targets)
	}
	for _, target := range targets {
		want, ok := wantPaths[target.Path]
		if !ok {
			t.Errorf("unexpected target returned by Discover: %+v (README.md, .git, node_modules, vendor must not appear)", target)
			continue
		}
		if target.Kind != want {
			t.Errorf("Discover target %s: Kind = %v, want %v", target.Path, target.Kind, want)
		}
	}
}

func TestDiscoverSortedByPath(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "z", "AGENTS.md"), "# z\n")
	writeFile(t, filepath.Join(root, "a", "AGENTS.md"), "# a\n")
	writeFile(t, filepath.Join(root, "m", "SKILL.md"), "# m\n")

	targets, err := scan.Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: unexpected error: %v", err)
	}

	paths := make([]string, len(targets))
	for i, target := range targets {
		paths[i] = target.Path
	}
	if !sort.StringsAreSorted(paths) {
		t.Fatalf("Discover result not sorted by Path: %v", paths)
	}
}

func TestDiscoverDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "SKILL.md"), "# outside\n")

	linkDir := filepath.Join(root, "linked-dir")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Fatalf("os.Symlink(dir): %v", err)
	}

	realFile := filepath.Join(root, "AGENTS.md")
	writeFile(t, realFile, "# real\n")
	linkFile := filepath.Join(root, "SKILL.md")
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Fatalf("os.Symlink(file): %v", err)
	}

	targets, err := scan.Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: unexpected error: %v", err)
	}

	wantReal := filepath.ToSlash(realFile)
	found := false
	for _, target := range targets {
		if target.Path == filepath.ToSlash(linkFile) {
			t.Errorf("Discover followed/returned the symlinked file %s", target.Path)
		}
		if target.Path == filepath.ToSlash(filepath.Join(outside, "SKILL.md")) {
			t.Errorf("Discover walked into the symlinked directory: %+v", target)
		}
		if target.Path == wantReal {
			found = true
		}
	}
	if !found {
		t.Fatalf("Discover did not return the real AGENTS.md file: %+v", targets)
	}
}

func TestDiscoverExplicitFileRoot(t *testing.T) {
	root := t.TempDir()
	skillPath := filepath.Join(root, "SKILL.md")
	writeFile(t, skillPath, "# skill\n")
	genericPath := filepath.Join(root, "notes.txt")
	writeFile(t, genericPath, "unclassified\n")

	targets, err := scan.Discover([]string{skillPath, genericPath})
	if err != nil {
		t.Fatalf("Discover: unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("Discover(explicit files) returned %d targets, want 2: %+v", len(targets), targets)
	}

	byPath := make(map[string]scan.FileKind, len(targets))
	for _, target := range targets {
		byPath[target.Path] = target.Kind
	}
	if kind, ok := byPath[filepath.ToSlash(skillPath)]; !ok || kind != scan.KindSkill {
		t.Errorf("explicit SKILL.md root: kind = %v, ok = %v, want KindSkill/true", kind, ok)
	}
	if kind, ok := byPath[filepath.ToSlash(genericPath)]; !ok || kind != scan.KindGeneric {
		t.Errorf("explicit unclassified root: kind = %v, ok = %v, want KindGeneric/true", kind, ok)
	}
}

func TestDiscoverNonexistentRootIsError(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "does-not-exist")
	if _, err := scan.Discover([]string{missing}); err == nil {
		t.Fatalf("Discover(%q): expected error for nonexistent root, got nil", missing)
	}
}
