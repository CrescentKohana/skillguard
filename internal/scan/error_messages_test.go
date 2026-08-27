package scan_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestDiscoverNonexistentRootErrorMessageNotDoubleWrapped covers C5: error
// messages must name the offending path once, not twice (no
// "discover X: stat X: ...").
func TestDiscoverNonexistentRootErrorMessageNotDoubleWrapped(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "does-not-exist")
	_, err := scan.Discover([]string{missing})
	if err == nil {
		t.Fatalf("Discover(%q): expected an error for a nonexistent root, got nil", missing)
	}
	msg := err.Error()
	if n := strings.Count(msg, missing); n > 1 {
		t.Fatalf("Discover error message repeats the path %d times, want at most once: %q", n, msg)
	}
}
