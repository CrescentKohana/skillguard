package scan_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

// Every secret-shaped literal below is assembled at runtime from parts that do
// not individually match a provider's secret format, per project convention:
// no committed file may contain a real provider-format secret literal.
func buildSecrets() map[string]string {
	return map[string]string{
		"aws-access-key-akia": "AKIA" + strings.Repeat("A1B2", 4),
		"aws-access-key-asia": "ASIA" + strings.Repeat("Z9Y8", 4),
		"github-pat-ghp":      "gh" + "p_" + strings.Repeat("A1b2", 9),
		"github-pat-gho":      "gh" + "o_" + strings.Repeat("A1b2", 9),
		"github-pat-fine":     "github_pat_" + strings.Repeat("A1b2", 6),
		"anthropic-key":       "sk-ant-" + strings.Repeat("A1b2", 6),
		"openai-key":          "sk-" + strings.Repeat("A1b2", 6),
		"openai-proj-key":     "sk-" + "proj-" + strings.Repeat("A1b2", 6),
		"slack-token":         "xox" + "p-" + strings.Repeat("1234567890", 2),
		"google-api-key":      "AIza" + strings.Repeat("A1b2_-9", 5),
		"stripe-live-key":     "sk_" + "live_" + strings.Repeat("A1b2", 5),
		"stripe-restricted":   "rk_" + "live_" + strings.Repeat("A1b2", 5),
		"pem-rsa-private-key": "-----BEGIN " + "RSA " + "PRIVATE KEY" + "-----",
		"pem-generic-private": "-----BEGIN " + "PRIVATE KEY" + "-----",
	}
}

func TestSG060PatternFormFiresAndMasks(t *testing.T) {
	for name, secret := range buildSecrets() {
		t.Run(name, func(t *testing.T) {
			line := "token=" + secret
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
			f := findRule(t, findings, "SG060")
			if f.Severity != finding.SeverityCritical {
				t.Errorf("severity = %v, want critical", f.Severity)
			}
			if strings.Contains(f.Message, secret) {
				t.Fatalf("message must not contain the raw secret: %q", f.Message)
			}
			if strings.Contains(f.Snippet, secret) {
				t.Fatalf("snippet must not contain the raw secret: %q", f.Snippet)
			}
			prefix := secret
			if len(prefix) > 4 {
				prefix = prefix[:4]
			}
			if !strings.Contains(f.Snippet, prefix+"****") {
				t.Errorf("snippet %q does not show the masked form %q", f.Snippet, prefix+"****")
			}
		})
	}
}

func TestSG060OnlyOneFindingPerLineAcrossProviders(t *testing.T) {
	anthropicKey := "sk-ant-" + strings.Repeat("A1b2", 6)
	line := "key=" + anthropicKey
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	if n := countRule(findings, "SG060"); n != 1 {
		t.Fatalf("expected one SG060 finding per line even with an Anthropic-shaped key, got %d: %+v", n, findings)
	}
}

func TestSG060JSONEnvFormFires(t *testing.T) {
	secretValue := "A1b2C3d4E5"
	keys := []string{"apiKey", "API_KEY", "token", "SECRET", "password", "passwd", "authorization"}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			content := fmt.Sprintf(`{
  "mcpServers": {
    "svc": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        %q: %q
      }
    }
  }
}`, key, secretValue)
			findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
			f := findRule(t, findings, "SG060")
			if strings.Contains(f.Message, secretValue) {
				t.Fatalf("message must not contain the raw secret value: %q", f.Message)
			}
			if strings.Contains(f.Snippet, secretValue) {
				t.Fatalf("snippet must not contain the raw secret value: %q", f.Snippet)
			}
		})
	}
}

func TestSG060JSONHeadersFormFires(t *testing.T) {
	secretValue := "F6g7H8i9J0" //nolint:gosec // G101: synthetic literal exercising the JSON-env rule, not a real credential
	content := fmt.Sprintf(`{
  "mcpServers": {
    "svc": {
      "command": "node",
      "args": ["server.js"],
      "headers": {
        "Authorization": %q
      }
    }
  }
}`, secretValue)
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	f := findRule(t, findings, "SG060")
	if strings.Contains(f.Message, secretValue) {
		t.Fatalf("message must not contain the raw secret value: %q", f.Message)
	}
	if strings.Contains(f.Snippet, secretValue) {
		t.Fatalf("snippet must not contain the raw secret value: %q", f.Snippet)
	}
}

func TestSG060JSONEnvPlaceholdersDoNotFire(t *testing.T) {
	placeholders := map[string]string{
		"dollar-brace-ref":    "${SOME_SECRET}",
		"dollar-prefixed-ref": "$SOME_SECRET_ENV",
		"angle-bracket":       "<your-api-key-here>",
		"mustache":            "{{API_KEY}}",
		"your-prefix":         "YOUR_API_KEY_HERE",
		"xxxx-placeholder":    "xxxxxxxxxxxxxxxx",
		"example-word":        "EXAMPLE1234567890",
		"changeme":            "changeme123",
		"replace":             "REPLACE_WITH_YOUR_KEY",
	}
	for name, value := range placeholders {
		t.Run(name, func(t *testing.T) {
			content := fmt.Sprintf(`{
  "mcpServers": {
    "svc": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "API_KEY": %q
      }
    }
  }
}`, value)
			findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
			if hasRule(findings, "SG060") {
				t.Fatalf("placeholder value %q must not trigger SG060; findings=%+v", value, findings)
			}
		})
	}
}

func TestSG060JSONEnvShortValueDoesNotFire(t *testing.T) {
	content := `{
  "mcpServers": {
    "svc": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "API_KEY": "short12"
      }
    }
  }
}`
	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	if hasRule(findings, "SG060") {
		t.Fatalf("a literal shorter than 8 characters must not trigger SG060; findings=%+v", findings)
	}
}
