package scan_test

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestDiscoverExplicitFIFORootIsError covers C5: Discover accepts only
// regular files; an explicit root that is a FIFO is an error.
func TestDiscoverExplicitFIFORootIsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFOs via syscall.Mkfifo are not available on Windows")
	}
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "a-fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo(%q): %v", fifoPath, err)
	}

	if _, err := scan.Discover([]string{fifoPath}); err == nil {
		t.Fatalf("Discover(%q): expected an error for an explicit FIFO root, got nil", fifoPath)
	}
}

// TestDiscoverSkipsFIFOEncounteredWhileWalking covers C5: a FIFO met while
// walking a directory is skipped, even when its name would otherwise
// classify it, while regular sibling files are still returned.
func TestDiscoverSkipsFIFOEncounteredWhileWalking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFOs via syscall.Mkfifo are not available on Windows")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "real", "AGENTS.md"), "harmless\n")

	fifoDir := filepath.Join(root, "piped")
	if err := os.MkdirAll(fifoDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(%q): %v", fifoDir, err)
	}
	fifoPath := filepath.Join(fifoDir, "AGENTS.md")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo(%q): %v", fifoPath, err)
	}

	targets, err := scan.Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover(%q): unexpected error walking a directory containing a FIFO: %v", root, err)
	}
	for _, target := range targets {
		if target.Path == filepath.ToSlash(fifoPath) {
			t.Fatalf("Discover must skip a FIFO encountered while walking, even when its name would otherwise classify; got %+v", target)
		}
	}
	wantReal := filepath.ToSlash(filepath.Join(root, "real", "AGENTS.md"))
	found := false
	for _, target := range targets {
		if target.Path == wantReal {
			found = true
		}
	}
	if !found {
		t.Fatalf("Discover must still return the regular sibling AGENTS.md; targets=%+v", targets)
	}
}
