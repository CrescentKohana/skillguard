package scan_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestFindingsTiedOnLocationAndRuleAreOrderedByMessage verifies findings sort
// stably by Path, Line, Column, RuleID, Message. Unicode-escaped keys defeat
// the exact-string location lookup so every finding ties on the first four fields, leaving Message as the only tiebreaker.
func TestFindingsTiedOnLocationAndRuleAreOrderedByMessage(t *testing.T) {
	const serverCount = 10
	var b strings.Builder
	b.WriteString(`{"mcpServers":{`)
	for i := 0; i < serverCount; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"svc%02d":{"command":"npx","args":["-y","left-pad@1.0.0"],"auto\u0041pprove":true,"always\u0041llow":true}`, i)
	}
	b.WriteString(`}}`)
	content := b.String()

	findings := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))

	var tied []finding.Finding
	for _, f := range findings {
		if f.RuleID == "SG040" && f.Line == 1 && f.Column == 1 {
			tied = append(tied, f)
		}
	}
	if len(tied) != serverCount*2 {
		t.Fatalf("setup: want %d tied SG040 findings at (1,1) (the \\u0041-escaped keys must defeat exact-string location lookup for every server), got %d: %+v", serverCount*2, len(tied), tied)
	}

	for i := 1; i < len(tied); i++ {
		if tied[i-1].Message > tied[i].Message {
			t.Fatalf("G3: findings tied on (Path, Line, Column, RuleID) must be ordered by Message; at index %d, %q sorts after %q", i, tied[i-1].Message, tied[i].Message)
		}
	}

	findings2 := scan.ScanContent(".mcp.json", scan.KindMCPConfig, []byte(content))
	if !reflect.DeepEqual(findings, findings2) {
		t.Fatalf("G3: repeated ScanContent calls on identical input must produce identical ordering; first=%+v second=%+v", findings, findings2)
	}
}
