package cli_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRunScanNeverLeaksSecretsInAnyOutputFormat verifies a minified
// single-line MCP config with two secret env values and an SG031 text-rule
// trigger does not leak either secret in text, JSON, or SARIF output through cli.Run's in-memory writers.
func TestRunScanNeverLeaksSecretsInAnyOutputFormat(t *testing.T) {
	secret1 := "s3cr3t-" + strings.Repeat("Ab1c", 4)
	secret2 := "s3cr3t-" + strings.Repeat("Zy9x", 4)
	root := t.TempDir()
	content := `{"mcpServers":{"svc":{"command":"cat","args":["~/.ssh/id_rsa"],"env":{"API_KEY":"` +
		secret1 + `","AUTH_TOKEN":"` + secret2 + `"}}}}` + "\n"
	writeFile(t, filepath.Join(root, ".mcp.json"), content)

	for _, format := range []string{"text", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			stdout, stderr, _ := run("scan", "--format", format, "--fail-on", "none", root)
			for _, secret := range []string{secret1, secret2} {
				if strings.Contains(stdout, secret) {
					t.Errorf("%s stdout leaks the raw secret %q", format, secret)
				}
				if strings.Contains(stderr, secret) {
					t.Errorf("%s stderr leaks the raw secret %q", format, secret)
				}
			}
		})
	}
}

// TestRunScan400CharacterSecretEnvValueNeverLeaksMoreThanFourCharsInAnyFormat
// verifies masking applies to the full line before 200-rune truncation, so no
// 8-rune window of a secret far longer than that window survives in any output format.
func TestRunScan400CharacterSecretEnvValueNeverLeaksMoreThanFourCharsInAnyFormat(t *testing.T) {
	secret := strings.Repeat("A1b2C3d4E5f6G7h8", 25) // 400 chars, no placeholder markers
	root := t.TempDir()
	content := `{"mcpServers":{"svc":{"command":"npx","args":["-y","left-pad"],"env":{"API_TOKEN":"` +
		secret + `"}}}}` + "\n"
	writeFile(t, filepath.Join(root, ".mcp.json"), content)

	for _, format := range []string{"text", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			stdout, stderr, _ := run("scan", "--format", format, "--fail-on", "none", root)
			combined := stdout + stderr
			for i := 0; i+8 <= len(secret); i++ {
				window := secret[i : i+8]
				if strings.Contains(combined, window) {
					t.Fatalf("%s output leaks an 8-character window of the 400-char secret at offset %d (%q); masking must apply to the full line before 200-rune truncation", format, i, window)
				}
			}
		})
	}
}

// TestRunScanUnparsableMCPConfigMasksLiteralKeyValueSecretAndWarns verifies
// that when an MCP config cannot be parsed at all, a secret-looking "<key>":
// "<value>" pair is still masked in every finding, and Scan's warning for the unparsable file still surfaces.
func TestRunScanUnparsableMCPConfigMasksLiteralKeyValueSecretAndWarns(t *testing.T) {
	secret := "zz" + strings.Repeat("H4i5", 4) // 18 chars, no placeholder markers
	root := t.TempDir()
	content := `{"mcpServers":{"svc":{"command":"npx","env":{"API_KEY":"` + secret +
		`"}}}} ; rm -rf / extra-garbage-that-breaks-json-parsing` + "\n"
	writeFile(t, filepath.Join(root, ".mcp.json"), content)

	for _, format := range []string{"text", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			stdout, stderr, _ := run("scan", "--format", format, "--fail-on", "none", root)
			if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
				t.Fatalf(`%s output leaks the literal secret from an unparsable MCP config's "API_KEY" pair; stdout=%q stderr=%q`, format, stdout, stderr)
			}
			if !strings.Contains(stderr, "warning: ") {
				t.Errorf(`%s run: stderr must still contain a "warning: " line for the unparsable MCP config; stderr=%q`, format, stderr)
			}
		})
	}
}
