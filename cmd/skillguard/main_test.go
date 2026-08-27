package main_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("could not determine the test file's own path")
	}
	// cmd/skillguard/main_test.go -> repo root is two levels up.
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

func buildSkillguard(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping binary build/exec end-to-end test under -short: requires go build and exec, which are slow")
	}

	root := repoRoot(t)
	binPath := filepath.Join(t.TempDir(), "skillguard")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd/skillguard") //nolint:gosec // G204: fixed test-controlled arguments, not external input
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./cmd/skillguard failed: %v\n%s", err, out)
	}
	return binPath
}

func runBinary(t *testing.T, bin string, args ...string) (output string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: bin is the binary this test just built, not external input
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("running %v failed to start: %v", cmd.Args, err)
	return "", -1
}

func TestBinaryVersionExitsZero(t *testing.T) {
	bin := buildSkillguard(t)
	out, exitCode := runBinary(t, bin, "version")
	if exitCode != 0 {
		t.Fatalf("skillguard version: exit code = %d, want 0; output=%s", exitCode, out)
	}
}

func TestBinaryUnknownCommandExitsTwo(t *testing.T) {
	bin := buildSkillguard(t)
	out, exitCode := runBinary(t, bin, "not-a-real-command")
	if exitCode != 2 {
		t.Fatalf("skillguard not-a-real-command: exit code = %d, want 2; output=%s", exitCode, out)
	}
}

func TestBinaryScanNonexistentPathExitsTwo(t *testing.T) {
	bin := buildSkillguard(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	out, exitCode := runBinary(t, bin, "scan", missing)
	if exitCode != 2 {
		t.Fatalf("skillguard scan <missing>: exit code = %d, want 2; output=%s", exitCode, out)
	}
}

func TestBinaryScanCleanDirExitsZero(t *testing.T) {
	bin := buildSkillguard(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("Tell the user which files were changed.\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, exitCode := runBinary(t, bin, "scan", dir)
	if exitCode != 0 {
		t.Fatalf("skillguard scan <clean dir>: exit code = %d, want 0; output=%s", exitCode, out)
	}
}
