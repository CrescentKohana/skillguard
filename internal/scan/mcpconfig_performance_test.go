// Wall-clock budgets are meaningless under the race detector's instrumentation; CI runs this file without -race.
//go:build !race

package scan_test

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

const perfServerCount = 20000

// writeGeneratedMCPConfig writes a single-line .mcp.json of serverCount
// unpinned npx servers, targeting the ~3 MB file size C2's performance bound
// is specified against.
func writeGeneratedMCPConfig(t *testing.T, path string, serverCount int) {
	t.Helper()
	f, err := os.Create(path) //nolint:gosec // G304: path is this test's own t.TempDir() file, not external input
	if err != nil {
		t.Fatalf("Create(%q): %v", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Fatalf("Close(%q): %v", path, cerr)
		}
	}()

	w := bufio.NewWriter(f)
	filler := strings.Repeat("x", 100)
	if _, err := w.WriteString(`{"mcpServers":{`); err != nil {
		t.Fatalf("write: %v", err)
	}
	for i := 0; i < serverCount; i++ {
		if i > 0 {
			if _, err := w.WriteString(","); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		if _, err := fmt.Fprintf(w, `"svc%05d":{"command":"npx","args":["-y","left-pad"],"description":%q}`, i, filler); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if _, err := w.WriteString(`}}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// TestMCPConfigLargeServerCountScansWithinBudget verifies locating each
// server's position is linear in file size overall, not a per-server re-scan
// of the whole file. The 60s hard cap bounds the goroutine below instead of hanging on a quadratic regression.
func TestMCPConfigLargeServerCountScansWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("generates and scans a ~3 MB / 20,000-server fixture; skipped under -short for speed")
	}

	path := filepath.Join(t.TempDir(), ".mcp.json")
	writeGeneratedMCPConfig(t, path, perfServerCount)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	t.Logf("generated fixture size: %d bytes", info.Size())

	content, err := os.ReadFile(path) //nolint:gosec // G304: path is this test's own t.TempDir() file, not external input
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}

	type result struct {
		findings []finding.Finding
		elapsed  time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, content)
		done <- result{findings: findings, elapsed: time.Since(start)}
	}()

	const budget = 5 * time.Second
	const safetyCap = 60 * time.Second
	select {
	case r := <-done:
		if r.elapsed > budget {
			t.Errorf("ScanContent took %s for %d servers, want under %s (locating a server's position must be linear in file size overall)", r.elapsed, perfServerCount, budget)
		}
		if n := countRule(r.findings, "SG050"); n != perfServerCount {
			t.Fatalf("expected %d SG050 findings (one per unpinned server), got %d", perfServerCount, n)
		}
	case <-time.After(safetyCap):
		t.Fatalf("ScanContent did not return within %s for %d servers (budget is %s); likely quadratic per-server location", safetyCap, perfServerCount, budget)
	}
}

// writeGeneratedMCPConfigWithSecretEnv writes a single-line .mcp.json of
// serverCount unpinned npx servers, each with its own SG060 JSON-env secret,
// to verify masking cost stays linear rather than rechecking every secret in the file per finding.
func writeGeneratedMCPConfigWithSecretEnv(t *testing.T, path string, serverCount int) {
	t.Helper()
	f, err := os.Create(path) //nolint:gosec // G304: path is this test's own t.TempDir() file, not external input
	if err != nil {
		t.Fatalf("Create(%q): %v", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Fatalf("Close(%q): %v", path, cerr)
		}
	}()

	w := bufio.NewWriter(f)
	if _, err := w.WriteString(`{"mcpServers":{`); err != nil {
		t.Fatalf("write: %v", err)
	}
	for i := 0; i < serverCount; i++ {
		if i > 0 {
			if _, err := w.WriteString(","); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		secret := fmt.Sprintf("secretvalue%08d", i) // >= 8 chars, no placeholder markers
		if _, err := fmt.Fprintf(w, `"svc%05d":{"command":"npx","args":["-y","left-pad"],"env":{"API_KEY":%q}}`, i, secret); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if _, err := w.WriteString(`}}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// TestMCPConfigLargeServerCountWithSecretsScansWithinBudget verifies 20,000
// servers, each with its own SG060 JSON-env secret, still scan in well under
// 5 seconds; re-checking every secret against every finding would be quadratic in server count.
func TestMCPConfigLargeServerCountWithSecretsScansWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("generates and scans a large multi-secret fixture; skipped under -short for speed")
	}

	path := filepath.Join(t.TempDir(), ".mcp.json")
	writeGeneratedMCPConfigWithSecretEnv(t, path, perfServerCount)

	content, err := os.ReadFile(path) //nolint:gosec // G304: path is this test's own t.TempDir() file, not external input
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}

	type result struct {
		findings []finding.Finding
		elapsed  time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, content)
		done <- result{findings: findings, elapsed: time.Since(start)}
	}()

	const budget = 5 * time.Second
	const safetyCap = 60 * time.Second
	select {
	case r := <-done:
		if r.elapsed > budget {
			t.Errorf("ScanContent took %s for %d servers each with its own secret, want under %s (masking a finding must consult only the secrets on its own line, never every secret in the file)", r.elapsed, perfServerCount, budget)
		}
		if n := countRule(r.findings, "SG060"); n != perfServerCount {
			t.Fatalf("expected %d SG060 findings (one per server's secret env value), got %d", perfServerCount, n)
		}
		// Sample across the whole generated range, not just secret 0: a masking bug limited to
		// some servers (e.g. stale per-line state) would otherwise go undetected.
		const sampleStride = 97
		secretSample := make([]string, 0, perfServerCount/sampleStride+1)
		for i := 0; i < perfServerCount; i += sampleStride {
			secretSample = append(secretSample, fmt.Sprintf("secretvalue%08d", i))
		}
		for _, f := range r.findings {
			if f.RuleID != "SG060" {
				continue
			}
			for _, secret := range secretSample {
				if strings.Contains(f.Message, secret) {
					t.Errorf("SG060 finding leaks a full secret value unmasked: message=%q contains %q", f.Message, secret)
				}
				if strings.Contains(f.Snippet, secret) {
					t.Errorf("SG060 finding leaks a full secret value unmasked: snippet=%q contains %q", f.Snippet, secret)
				}
			}
		}
	case <-time.After(safetyCap):
		t.Fatalf("ScanContent did not return within %s for %d servers each with its own secret (budget is %s); likely re-masking every secret in the file per finding", safetyCap, perfServerCount, budget)
	}
}

// TestMCPConfigNearSizeCapSingleLineWithTextRuleTriggersScansWithinBudget verifies a single line
// just under the 5 MiB per-file cap, with text rules firing, scans in under 5 seconds.
func TestMCPConfigNearSizeCapSingleLineWithTextRuleTriggersScansWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("generates and scans a ~5 MiB single-line fixture; skipped under -short for speed")
	}

	const nearFiveMiBCap = 5*1024*1024 - 4096
	awsKey := "AKIA" + strings.Repeat("Q", 16)
	filler := strings.Repeat("x", nearFiveMiBCap)
	content := fmt.Sprintf(
		`{"mcpServers":{"svc":{"command":"npx","args":["-y","left-pad"],"description":%q,"note":"please avoid running rm -rf / and never leak key=%s"}}}`,
		filler, awsKey,
	)

	type result struct {
		findings []finding.Finding
		elapsed  time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
		done <- result{findings: findings, elapsed: time.Since(start)}
	}()

	const budget = 5 * time.Second
	const safetyCap = 60 * time.Second
	select {
	case r := <-done:
		if r.elapsed > budget {
			t.Errorf("ScanContent took %s for a ~5 MiB single-line file, want under %s", r.elapsed, budget)
		}
		if n := countRule(r.findings, "SG030"); n != 1 {
			t.Errorf("expected exactly 1 SG030 finding for the embedded \"rm -rf /\", got %d: %+v", n, r.findings)
		}
		if n := countRule(r.findings, "SG060"); n != 1 {
			t.Errorf("expected exactly 1 SG060 finding for the embedded AWS-shaped key, got %d: %+v", n, r.findings)
		}
		for _, f := range r.findings {
			for i := 0; i+5 <= len(awsKey); i++ {
				window := awsKey[i : i+5]
				if strings.Contains(f.Message, window) || strings.Contains(f.Snippet, window) {
					t.Errorf("rule %s leaks a 5-character window of the embedded secret: %q", f.RuleID, window)
				}
			}
		}
	case <-time.After(safetyCap):
		t.Fatalf("ScanContent did not return within %s for a ~5 MiB single-line file (budget is %s)", safetyCap, budget)
	}
}

func TestRepeatedCredentialWordsScanInLinearTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-megabyte cost-bound test under -short")
	}
	line := "--yolo " + strings.Repeat("key", 1<<20/3)
	tagged := make([]rune, 0, 1<<18)
	for _, r := range strings.Repeat("key", 1<<18/3) {
		tagged = append(tagged, 0xE0000+r)
	}
	for name, content := range map[string]string{"plain": line, "tag-encoded": string(tagged)} {
		start := time.Now()
		findings := scan.ScanContent("SKILL.md", scan.KindSkill, []byte(content+"\n"))
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("%s: 1 MiB of repeated credential words took %v, want well under 2s", name, elapsed)
		}
		if len(findings) == 0 {
			t.Errorf("%s: expected at least one finding", name)
		}
	}
}
