package report_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/report"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestSecretNeverAppearsInAnyOutputFormat builds an AWS-shaped secret at
// runtime (never a committed provider-format literal) and asserts it is absent from text, JSON and SARIF output.
func TestSecretNeverAppearsInAnyOutputFormat(t *testing.T) {
	secret := "AKIA" + strings.Repeat("Q7W8", 4)
	content := "export AWS_ACCESS_KEY_ID=" + secret + "\n"
	res, err := scanTempFile(t, "AGENTS.md", content)
	if err != nil {
		t.Fatalf("scanTempFile: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected the AKIA-shaped content to produce a finding")
	}

	var text, jsonBuf, sarifBuf bytes.Buffer
	if err := report.WriteText(&text, res); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if err := report.WriteJSON(&jsonBuf, res, "dev"); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if err := report.WriteSARIF(&sarifBuf, res, "dev"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	for name, out := range map[string]string{
		"text":  text.String(),
		"json":  jsonBuf.String(),
		"sarif": sarifBuf.String(),
	} {
		if strings.Contains(out, secret) {
			t.Fatalf("%s output contains the raw secret", name)
		}
	}
}

func scanTempFile(t *testing.T, name, content string) (scan.Result, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return scan.Scan([]string{dir})
}
