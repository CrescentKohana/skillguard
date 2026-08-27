package skillguard_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// extractActionBuildScript returns the shell script body of action.yml's
// "Build skillguard" step: the lines between its "run: |" block scalar and
// the next step boundary, de-indented.
func extractActionBuildScript(t *testing.T, content string) string {
	t.Helper()
	idx := strings.Index(content, "name: Build skillguard")
	if idx == -1 {
		t.Fatalf(`action.yml has no step named "Build skillguard"`)
	}
	rest := content[idx:]
	runIdx := strings.Index(rest, "run: |")
	if runIdx == -1 {
		t.Fatalf(`action.yml's "Build skillguard" step has no "run: |" block`)
	}
	body := rest[runIdx+len("run: |"):]

	var script []string
	for _, line := range strings.Split(body, "\n")[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "        ") {
			break
		}
		script = append(script, strings.TrimPrefix(line, "        "))
	}
	if len(script) == 0 {
		t.Fatalf(`action.yml's "Build skillguard" step's run: | block parsed to an empty script`)
	}
	return strings.Join(script, "\n")
}

// TestActionBuildScriptRunsFromRepoRootAndProducedBinaryScansExternalConsumerDir runs
// action.yml's build script from this repo's root (standing in for ${{ github.action_path }}),
// then uses the resulting binary to scan an unrelated consumer directory with its own go.mod.
func TestActionBuildScriptRunsFromRepoRootAndProducedBinaryScansExternalConsumerDir(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the skillguard binary via the real action.yml script and execs it; skipped under -short for speed")
	}

	data, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatalf("action.yml must exist: %v", err)
	}
	script := extractActionBuildScript(t, string(data))

	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	outputDir := t.TempDir()

	buildCtx, buildCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer buildCancel()
	buildCmd := exec.CommandContext(buildCtx, "bash", "-c", script) //nolint:gosec // G204: script is extracted verbatim from this repo's own action.yml, not external input
	buildCmd.Dir = repoRoot
	buildCmd.Env = append(os.Environ(), "ACTION_PATH="+repoRoot, "RUNNER_TEMP="+outputDir)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("action.yml's build script failed (working directory = repo root, per E6): %v\n%s", err, out)
	}

	binPath := filepath.Join(outputDir, "skillguard")
	if _, err := os.Stat(binPath); err != nil {
		t.Fatalf("action.yml's build script did not produce a binary at %q: %v", binPath, err)
	}

	consumerDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(consumerDir, "go.mod"), []byte("module example.com/consumer\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(consumer go.mod): %v", err)
	}
	if err := os.WriteFile(filepath.Join(consumerDir, "AGENTS.md"), []byte("Tell the user which files were changed.\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(consumer AGENTS.md): %v", err)
	}

	scanCtx, scanCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scanCancel()
	scanCmd := exec.CommandContext(scanCtx, binPath, "scan", consumerDir) //nolint:gosec // G204: binPath is the binary this test just built, consumerDir is this test's own t.TempDir()
	scanOut, err := scanCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the action-built binary failed to scan the external consumer directory %q: %v\n%s", consumerDir, err, scanOut)
	}
	if !strings.Contains(string(scanOut), "No findings. 1 files scanned.") {
		t.Fatalf("the action-built binary did not scan the consumer directory's AGENTS.md as expected; output=%s", scanOut)
	}
}
