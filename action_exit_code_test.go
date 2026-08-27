package skillguard_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// extractActionStepRunScript returns the shell script body (de-indented) of
// action.yml's named step's "run: |" block scalar.
func extractActionStepRunScript(t *testing.T, content, stepName string) string {
	t.Helper()
	idx := strings.Index(content, "name: "+stepName)
	if idx == -1 {
		t.Fatalf("action.yml has no step named %q", stepName)
	}
	rest := content[idx:]
	runIdx := strings.Index(rest, "run: |")
	if runIdx == -1 {
		t.Fatalf("action.yml's %q step has no \"run: |\" block", stepName)
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
		t.Fatalf("action.yml's %q step's run: | block parsed to an empty script", stepName)
	}
	return strings.Join(script, "\n")
}

// filteredEnv returns os.Environ() with every entry for name removed, so a
// subprocess test can exercise "name is unset" deterministically regardless
// of the ambient environment.
func filteredEnv(name string) []string {
	prefix := name + "="
	base := os.Environ()
	out := make([]string, 0, len(base))
	for _, e := range base {
		if !strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}

// TestActionYAMLFinalStepDefaultsUnsetExitCodeToTwoWithClearError verifies
// the final step defaults to exit code 2 with a clear error when the scan
// step's exit-code output is empty, e.g. because an earlier step failed first.
func TestActionYAMLFinalStepDefaultsUnsetExitCodeToTwoWithClearError(t *testing.T) {
	data, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatalf("action.yml must exist: %v", err)
	}
	script := extractActionStepRunScript(t, string(data), "Fail on findings")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", script) //nolint:gosec // G204: script is extracted verbatim from this repo's own action.yml, not external input
	cmd.Env = filteredEnv("SCAN_EXIT_CODE")
	out, runErr := cmd.CombinedOutput()

	exitCode := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(runErr, &exitErr):
		exitCode = exitErr.ExitCode()
	case runErr != nil:
		t.Fatalf(`running action.yml's "Fail on findings" step with SCAN_EXIT_CODE unset failed to start: %v; output:\n%s`, runErr, out)
	}

	if exitCode != 2 {
		t.Errorf(`"Fail on findings" step with SCAN_EXIT_CODE unset: exit code = %d, want 2 (an unset scan exit code must default to 2); output:%s`, exitCode, out)
	}
	if !strings.Contains(string(out), "::error::") {
		t.Errorf(`"Fail on findings" step with SCAN_EXIT_CODE unset must print a clear "::error::"-annotated message, not merely rely on a raw shell error; output:%s`, out)
	}
	if strings.Contains(string(out), "numeric argument required") {
		t.Errorf(`"Fail on findings" step with SCAN_EXIT_CODE unset must not fail on an empty variable (bash's own "numeric argument required" error leaked instead of a handled default); output:%s`, out)
	}
}
