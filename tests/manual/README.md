# Manual test cases

Cases below cannot be automated from this worktree because they require a real
GitHub-hosted environment (Actions runner, Code Scanning UI, or a published
module) that is unavailable to a local, offline test run. Each case documents
preconditions, steps, expected result, and why it cannot be scripted here.

## 1. `action.yml` SARIF upload to GitHub Code Scanning

- **Preconditions:** the repository is pushed to GitHub with Actions enabled
  and the `security-events: write` permission granted to the workflow.
- **Steps:**
  1. Push a branch containing a file under `examples/malicious/` (or an
     equivalent deliberately-flagged file) to GitHub.
  2. Let `action.yml` run via the CI workflow with `upload-sarif: "true"`.
  3. Open the repository's Security → Code scanning alerts tab.
- **Expected result:** one alert per finding, grouped by rule, with the
  correct severity and the file/line location from the SARIF report.
- **Why manual:** `github/codeql-action/upload-sarif` talks to GitHub's API
  and only operates inside a GitHub Actions runner; there is no local
  equivalent, and the spec forbids network access at scan time.

## 2. Action step fails with the scan's exit code even when SARIF upload succeeds

- **Preconditions:** same as case 1.
- **Steps:**
  1. Run the action against an input path that produces at least one finding
     at or above the default `fail-on` threshold.
  2. Observe the workflow run's conclusion for the step that invokes the
     built `skillguard scan`.
- **Expected result:** the SARIF upload step still runs and succeeds, but the
  overall job is marked failed, matching the scan's exit code (1).
- **Why manual:** this is an ordering/outcome guarantee across two real GitHub
  Actions steps (`upload-sarif` + a trailing exit step); it cannot be observed
  without an actual Actions run.

## 3. `go install github.com/CrescentKohana/skillguard/cmd/skillguard@latest`

- **Preconditions:** a tagged release exists on the public module proxy.
- **Steps:** run the install command from the README on a machine with
  network access, then run `skillguard version`.
- **Expected result:** the binary installs and prints a tagged version, not
  `dev`.
- **Why manual:** tagged releases are explicitly out of scope for this
  worktree, and the test suite must not depend on network access or an
  external module proxy.

## 4. Action's own `go.mod` / Go setup inside `action.yml`

- **Preconditions:** a GitHub Actions runner.
- **Steps:** trigger the composite action and inspect the "Set up Go" step
  logs for the Go version it resolves from the action's own `go.mod`.
- **Expected result:** Go is set up successfully and `go build ./cmd/skillguard`
  succeeds from `${{ github.action_path }}`.
- **Why manual:** depends on GitHub-hosted runner tooling (`actions/setup-go`)
  not available offline; local builds are already covered by
  `cmd/skillguard/main_test.go`'s `go build` based end-to-end test.
