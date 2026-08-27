package skillguard_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// extractScalarValue does simple line-based parsing (no YAML library, per
// project convention) of a single `key: value` line, returning the value with
// surrounding whitespace and matching quotes stripped.
func extractScalarValue(t *testing.T, content, key string) string {
	t.Helper()
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "- ")
		if !strings.HasPrefix(trimmed, key+":") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, key+":"))
		value = strings.Trim(value, `"'`)
		return value
	}
	t.Fatalf("key %q not found", key)
	return ""
}

func TestPreCommitHooksYAMLContract(t *testing.T) {
	path := ".pre-commit-hooks.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist at the repo root per the spec's distribution section: %v", path, err)
	}
	content := string(data)

	if got := extractScalarValue(t, content, "id"); got != "skillguard" {
		t.Errorf("id = %q, want %q", got, "skillguard")
	}
	if got := extractScalarValue(t, content, "language"); got != "golang" {
		t.Errorf("language = %q, want %q", got, "golang")
	}
	if got := extractScalarValue(t, content, "entry"); got != "skillguard scan" {
		t.Errorf("entry = %q, want %q", got, "skillguard scan")
	}

	filesPattern := extractScalarValue(t, content, "files")
	re, err := regexp.Compile(filesPattern)
	if err != nil {
		t.Fatalf("files: regex %q does not compile: %v", filesPattern, err)
	}

	mustMatch := []string{
		"SKILL.md",
		"skills/example/SKILL.md",
		"AGENTS.md",
		"repo/AGENTS.md",
		".kiro/steering/style.md",
		"project/.kiro/steering/style.md",
		".kiro/hooks/on-save.kiro.hook",
		"project/.kiro/hooks/on-save.kiro.hook",
		".mcp.json",
		"mcp.json",
		"mcp_config.json",
		"claude_desktop_config.json",
	}
	for _, path := range mustMatch {
		if !re.MatchString(path) {
			t.Errorf("files regex %q does not match classified filename %q", filesPattern, path)
		}
	}

	mustNotMatch := []string{"README.md", "main.go", "notes.txt"}
	for _, path := range mustNotMatch {
		if re.MatchString(path) {
			t.Errorf("files regex %q unexpectedly matches %q", filesPattern, path)
		}
	}
}

func TestActionYAMLContract(t *testing.T) {
	path := "action.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist at the repo root per the spec's distribution section: %v", path, err)
	}
	content := string(data)

	inputsIdx := strings.Index(content, "\ninputs:")
	runsIdx := strings.Index(content, "\nruns:")
	if inputsIdx == -1 || runsIdx == -1 || runsIdx < inputsIdx {
		t.Fatalf("action.yml must have an `inputs:` block before a `runs:` block")
	}
	inputsSection := content[inputsIdx:runsIdx]

	for _, key := range []string{"path", "fail-on", "sarif-file", "upload-sarif"} {
		pattern := regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(key) + `:\s*$`)
		if !pattern.MatchString(inputsSection) {
			t.Errorf("action.yml inputs block does not declare input %q", key)
		}
	}
}

// extractJobKeys returns the top-level job identifiers under a workflow's
// "jobs:" block (2-space-indented "key:" lines), no YAML library per
// project convention.
func extractJobKeys(t *testing.T, content string) []string {
	t.Helper()
	jobsIdx := strings.Index(content, "\njobs:")
	if jobsIdx == -1 {
		t.Fatalf("workflow has no jobs: block")
	}
	return jobKeyRe.FindAllString(content[jobsIdx:], -1)
}

// jobBlockContaining returns the single top-level job block (from its
// "  <key>:" line up to the next same-indent key, or EOF) that contains
// marker, or "" if no job block does.
func jobBlockContaining(content, marker string) string {
	locs := jobKeyRe.FindAllStringIndex(content, -1)
	for i, loc := range locs {
		end := len(content)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		if block := content[loc[0]:end]; strings.Contains(block, marker) {
			return block
		}
	}
	return ""
}

var jobKeyRe = regexp.MustCompile(`(?m)^  [a-zA-Z0-9_-]+:\s*$`)

func TestCIWorkflowYAMLContract(t *testing.T) {
	path := ".github/workflows/ci.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist per the spec's distribution section: %v", path, err)
	}
	content := string(data)

	for _, want := range []string{"push", "pull_request"} {
		if !strings.Contains(content, want) {
			t.Errorf("%s does not trigger on %q", path, want)
		}
	}

	if jobKeys := extractJobKeys(t, content); len(jobKeys) < 4 {
		t.Fatalf("%s: jobs: block has %d job keys, want at least 4 (build/vet/test, golangci-lint, actionlint, action smoke); got %v", path, len(jobKeys), jobKeys)
	}

	buildJob := jobBlockContaining(content, "go build ./...")
	if buildJob == "" {
		t.Fatalf("%s: no job runs `go build ./...`", path)
	}
	for _, want := range []string{"go vet ./...", "gofmt -l", "go test -race"} {
		if !strings.Contains(buildJob, want) {
			t.Errorf("%s: the build job does not run %q", path, want)
		}
	}

	if !strings.Contains(content, "golangci-lint-action") {
		t.Errorf("%s: no job uses golangci-lint-action", path)
	}
	if !strings.Contains(content, "actionlint") {
		t.Errorf("%s: no job installs or runs actionlint", path)
	}

	smokeJob := jobBlockContaining(content, "uses: ./")
	if smokeJob == "" {
		t.Fatalf("%s: no job runs the action via `uses: ./`", path)
	}
	if !strings.Contains(smokeJob, "examples/benign") {
		t.Errorf("%s: the action smoke job does not scan examples/benign", path)
	}
	if !strings.Contains(smokeJob, `upload-sarif: "false"`) && !strings.Contains(smokeJob, "upload-sarif: 'false'") {
		t.Errorf("%s: the action smoke job must pass upload-sarif: \"false\"", path)
	}
}

// distUsesValueRe captures the value of a "uses: <ref>" line.
var distUsesValueRe = regexp.MustCompile(`uses:\s*(\S+)`)

// distShaCommentRe matches a bare "<ref>@<40-hex-sha>" with no comment yet attached.
var distShaCommentRe = regexp.MustCompile(`^[^\s@]+@[0-9a-f]{40}$`)

// TestThirdPartyActionsArePinnedToFullSHAWithVersionComment verifies every
// `uses:` of a third-party action in ci.yml and action.yml is pinned to a
// 40-hex commit SHA with a version comment; local action references are skipped.
func TestThirdPartyActionsArePinnedToFullSHAWithVersionComment(t *testing.T) {
	for _, path := range []string{".github/workflows/ci.yml", "action.yml"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path) //nolint:gosec // G304: path is one of two fixed repo-relative filenames, not external input
			if err != nil {
				t.Fatalf("%s must exist: %v", path, err)
			}
			checked := 0
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				m := distUsesValueRe.FindStringSubmatch(trimmed)
				if m == nil || strings.HasPrefix(m[1], "./") {
					continue
				}
				checked++
				hashIdx := strings.Index(trimmed, "#")
				if hashIdx == -1 {
					t.Errorf("%s: %q has no trailing version comment", path, trimmed)
					continue
				}
				before := strings.TrimSpace(trimmed[:hashIdx])
				comment := strings.TrimSpace(trimmed[hashIdx+1:])
				ref := strings.TrimSpace(strings.TrimPrefix(before, "uses:"))
				if !distShaCommentRe.MatchString(ref) {
					t.Errorf("%s: %q is not pinned to a 40-hex commit SHA", path, trimmed)
				}
				if !strings.HasPrefix(comment, "v") {
					t.Errorf("%s: %q trailing comment must start with \"v<version>\", got %q", path, trimmed, comment)
				}
			}
			if checked == 0 {
				t.Fatalf("%s: found no third-party uses: lines to verify", path)
			}
		})
	}
}

// TestNoAtLatestInCIOrAction covers C6: no "@latest" anywhere in ci.yml or action.yml.
func TestNoAtLatestInCIOrAction(t *testing.T) {
	for _, path := range []string{".github/workflows/ci.yml", "action.yml"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path) //nolint:gosec // G304: path is one of two fixed repo-relative filenames, not external input
			if err != nil {
				t.Fatalf("%s must exist: %v", path, err)
			}
			if strings.Contains(string(data), "@latest") {
				t.Errorf("%s must not reference @latest anywhere", path)
			}
		})
	}
}

// TestActionlintInstalledAtPinnedVersion covers C6: actionlint is installed
// pinned to the exact version the spec names.
func TestActionlintInstalledAtPinnedVersion(t *testing.T) {
	path := ".github/workflows/ci.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
	want := "go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12"
	if !strings.Contains(string(data), want) {
		t.Errorf("%s does not install actionlint pinned to the required version; want to contain %q", path, want)
	}
}

// TestActionYAMLUploadStepGuardsSuccessAndHashFiles covers C6: the SARIF
// upload step runs only if earlier steps succeeded and the SARIF file
// exists, i.e. its if: condition contains both success() and hashFiles.
func TestActionYAMLUploadStepGuardsSuccessAndHashFiles(t *testing.T) {
	path := "action.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
	content := string(data)
	idx := strings.Index(content, "Upload SARIF")
	if idx == -1 {
		t.Fatalf("%s: no step named \"Upload SARIF\" found", path)
	}
	rest := content[idx:]
	ifIdx := strings.Index(rest, "if:")
	if ifIdx == -1 || ifIdx > 200 {
		t.Fatalf("%s: Upload SARIF step has no nearby if: condition", path)
	}
	ifLine := rest[ifIdx:]
	if nl := strings.Index(ifLine, "\n"); nl != -1 {
		ifLine = ifLine[:nl]
	}
	if !strings.Contains(ifLine, "success()") {
		t.Errorf("%s: Upload SARIF step's if: condition does not guard on success(): %q", path, ifLine)
	}
	if !strings.Contains(ifLine, "hashFiles") {
		t.Errorf("%s: Upload SARIF step's if: condition does not guard on hashFiles(...): %q", path, ifLine)
	}
}

// actionStepKeyRe matches a composite action's "    - name:" step marker.
var actionStepKeyRe = regexp.MustCompile(`(?m)^    - name:`)

// actionStepBlockContaining returns the single composite-action step block
// (from its "    - name:" line to the next step marker or EOF) that
// contains marker, or "" if none does.
func actionStepBlockContaining(content, marker string) string {
	locs := actionStepKeyRe.FindAllStringIndex(content, -1)
	for i, loc := range locs {
		end := len(content)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		if block := content[loc[0]:end]; strings.Contains(block, marker) {
			return block
		}
	}
	return ""
}

// TestActionYAMLBuildStepUsesWorkingDirectoryActionPath covers E6: the build
// runs with working-directory: ${{ github.action_path }}, so it does not
// depend on the caller's working directory.
func TestActionYAMLBuildStepUsesWorkingDirectoryActionPath(t *testing.T) {
	path := "action.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
	content := string(data)

	buildStep := actionStepBlockContaining(content, "Build skillguard")
	if buildStep == "" {
		t.Fatalf(`%s: no step named "Build skillguard" found`, path)
	}
	if !strings.Contains(buildStep, "working-directory: ${{ github.action_path }}") {
		t.Errorf("%s: the \"Build skillguard\" step must set working-directory: ${{ github.action_path }} (E6: the build must not depend on the caller's working directory); step block=%q", path, buildStep)
	}
}

// TestActionYAMLSetupGoUsesActionPathGoMod covers E6: Go is set up from the
// action's own go.mod (${{ github.action_path }}/go.mod), not the caller's.
func TestActionYAMLSetupGoUsesActionPathGoMod(t *testing.T) {
	path := "action.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
	content := string(data)

	setupStep := actionStepBlockContaining(content, "Set up Go")
	if setupStep == "" {
		t.Fatalf(`%s: no step named "Set up Go" found`, path)
	}
	if !strings.Contains(setupStep, "go-version-file: ${{ github.action_path }}/go.mod") {
		t.Errorf("%s: the \"Set up Go\" step must resolve go-version-file from ${{ github.action_path }}/go.mod, not the caller's go.mod; step block=%q", path, setupStep)
	}
}

// TestPreCommitHooksFilesRegexMatchesCaseInsensitiveVariants covers E6:
// .pre-commit-hooks.yaml's files: regex must match SKILL.md and AGENTS.md
// case-insensitively, consistent with Classify.
func TestPreCommitHooksFilesRegexMatchesCaseInsensitiveVariants(t *testing.T) {
	path := ".pre-commit-hooks.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
	content := string(data)

	filesPattern := extractScalarValue(t, content, "files")
	re, err := regexp.Compile(filesPattern)
	if err != nil {
		t.Fatalf("files: regex %q does not compile: %v", filesPattern, err)
	}

	mustMatch := []string{"skill.md", "Skill.MD", "agents.md", "SKILL.md", "AGENTS.md"}
	for _, p := range mustMatch {
		if !re.MatchString(p) {
			t.Errorf("E6: files regex %q must match %q case-insensitively, consistent with Classify", filesPattern, p)
		}
	}
}
