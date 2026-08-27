package skillguard_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestCIActionSmokeJobProvesBuildFromForeignWorkspace verifies the smoke job
// checks SkillGuard out into a subdirectory, creates an unrelated consumer
// go.mod at the workspace root, and invokes the action as a local reference against it.
func TestCIActionSmokeJobProvesBuildFromForeignWorkspace(t *testing.T) {
	ciData, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf(".github/workflows/ci.yml must exist: %v", err)
	}
	content := string(ciData)

	smokeJob := jobBlockContaining(content, "uses: ./skillguard")
	if smokeJob == "" {
		t.Fatalf(`ci.yml: no job invokes the action via "uses: ./skillguard" (G5 requires checking SkillGuard out into a "skillguard" subdirectory and invoking it as a local relative action from there)`)
	}

	if !strings.Contains(smokeJob, "path: skillguard") {
		t.Errorf(`ci.yml: the action smoke job must check SkillGuard out into a subdirectory via actions/checkout's "path: skillguard" input; job=%q`, smokeJob)
	}

	modData, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("go.mod must exist: %v", err)
	}
	realModuleLine := strings.TrimSpace(strings.SplitN(string(modData), "\n", 2)[0])

	goModDeclarationRe := regexp.MustCompile(`module\s+\S+`)
	declarations := goModDeclarationRe.FindAllString(smokeJob, -1)
	if len(declarations) == 0 {
		t.Fatalf(`ci.yml: the action smoke job must create a consumer go.mod (a "module ..." declaration) at the workspace root, outside the "skillguard" checkout; job=%q`, smokeJob)
	}
	for _, decl := range declarations {
		if strings.TrimSpace(decl) == realModuleLine {
			t.Errorf("ci.yml: the action smoke job's consumer go.mod must declare a module different from SkillGuard's own (%q), got %q", realModuleLine, decl)
		}
	}

	usesIdx := strings.Index(smokeJob, "uses: ./skillguard")
	rest := smokeJob[usesIdx:]
	pathValueRe := regexp.MustCompile(`(?m)^\s*path:\s*(\S+)\s*$`)
	m := pathValueRe.FindStringSubmatch(rest)
	if m == nil {
		t.Fatalf(`ci.yml: the "uses: ./skillguard" step must declare a "path:" input; job=%q`, smokeJob)
	}
	pathValue := strings.Trim(m[1], `"'`)
	if pathValue == "skillguard" || pathValue == "." || pathValue == "skillguard/examples/benign" || pathValue == "examples/benign" {
		t.Errorf(`ci.yml: the "uses: ./skillguard" step's "path:" input must point at a consumer samples directory distinct from the skillguard checkout's own examples/benign, got %q`, pathValue)
	}

	if !strings.Contains(smokeJob, "examples/benign") {
		t.Errorf(`ci.yml: the action smoke job must still derive its consumer samples from examples/benign (e.g. by copying it into the consumer directory); job=%q`, smokeJob)
	}

	if !strings.Contains(smokeJob, `upload-sarif: "false"`) && !strings.Contains(smokeJob, "upload-sarif: 'false'") {
		t.Errorf(`ci.yml: the action smoke job must still pass upload-sarif: "false"; job=%q`, smokeJob)
	}
}
