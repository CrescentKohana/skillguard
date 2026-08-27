package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/report"
	"github.com/CrescentKohana/skillguard/internal/rules"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

func sampleResult() scan.Result {
	return scan.Result{
		Findings: []finding.Finding{
			{
				RuleID:   "SG001",
				Severity: finding.SeverityHigh,
				Path:     "a/SKILL.md",
				Line:     3,
				Column:   5,
				Message:  "2 zero-width characters (U+200B)",
				Snippet:  "some<U+200B>text",
			},
			{
				RuleID:   "SG060",
				Severity: finding.SeverityCritical,
				Path:     "b/AGENTS.md",
				Line:     10,
				Column:   1,
				Message:  "hardcoded secret detected (AKIA****)",
				Snippet:  "token=AKIA****",
			},
		},
		Suppressed: 1,
		Files:      4,
	}
}

func TestWriteTextFormat(t *testing.T) {
	var buf bytes.Buffer
	res := sampleResult()
	if err := report.WriteText(&buf, res); err != nil {
		t.Fatalf("WriteText: unexpected error: %v", err)
	}
	out := buf.String()

	wantLine1 := "a/SKILL.md:3:5: high SG001 2 zero-width characters (U+200B)"
	if !strings.Contains(out, wantLine1) {
		t.Errorf("output does not contain finding line %q; got:\n%s", wantLine1, out)
	}
	wantSnippet1 := "    some<U+200B>text"
	if !strings.Contains(out, wantSnippet1) {
		t.Errorf("output does not contain indented snippet %q; got:\n%s", wantSnippet1, out)
	}
	wantLine2 := "b/AGENTS.md:10:1: critical SG060 hardcoded secret detected (AKIA****)"
	if !strings.Contains(out, wantLine2) {
		t.Errorf("output does not contain finding line %q; got:\n%s", wantLine2, out)
	}

	wantSummary := "2 findings (1 critical, 1 high, 0 medium, 0 low, 0 info), 1 suppressed, 4 files scanned"
	if !strings.Contains(out, wantSummary) {
		t.Errorf("output does not contain summary line %q; got:\n%s", wantSummary, out)
	}
}

func TestWriteTextNoFindings(t *testing.T) {
	var buf bytes.Buffer
	res := scan.Result{Findings: nil, Suppressed: 0, Files: 7}
	if err := report.WriteText(&buf, res); err != nil {
		t.Fatalf("WriteText: unexpected error: %v", err)
	}
	want := "No findings. 7 files scanned."
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("output = %q, want to contain %q", buf.String(), want)
	}
}

func TestWriteJSONFields(t *testing.T) {
	var buf bytes.Buffer
	res := sampleResult()
	if err := report.WriteJSON(&buf, res, "1.2.3"); err != nil {
		t.Fatalf("WriteJSON: unexpected error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v; raw: %s", err, buf.String())
	}

	if doc["tool"] != "skillguard" {
		t.Errorf(`doc["tool"] = %v, want "skillguard"`, doc["tool"])
	}
	if doc["version"] != "1.2.3" {
		t.Errorf(`doc["version"] = %v, want "1.2.3"`, doc["version"])
	}

	findingsRaw, ok := doc["findings"].([]any)
	if !ok {
		t.Fatalf(`doc["findings"] is not a JSON array: %T %v`, doc["findings"], doc["findings"])
	}
	if len(findingsRaw) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findingsRaw))
	}

	first, ok := findingsRaw[0].(map[string]any)
	if !ok {
		t.Fatalf("findings[0] is not an object: %T", findingsRaw[0])
	}
	wantFields := map[string]any{
		"ruleId":   "SG001",
		"severity": "high",
		"path":     "a/SKILL.md",
		"line":     float64(3),
		"column":   float64(5),
	}
	for k, want := range wantFields {
		if got := first[k]; got != want {
			t.Errorf("findings[0][%q] = %v, want %v", k, got, want)
		}
	}
	if _, ok := first["message"].(string); !ok {
		t.Errorf("findings[0][\"message\"] missing or not a string")
	}
	if _, ok := first["snippet"].(string); !ok {
		t.Errorf("findings[0][\"snippet\"] missing or not a string")
	}

	summary, ok := doc["summary"].(map[string]any)
	if !ok {
		t.Fatalf(`doc["summary"] is not an object: %T`, doc["summary"])
	}
	wantSummary := map[string]float64{
		"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0,
		"suppressed": 1, "files": 4,
	}
	for k, want := range wantSummary {
		got, ok := summary[k].(float64)
		if !ok || got != want {
			t.Errorf("summary[%q] = %v, want %v", k, summary[k], want)
		}
	}
}

func TestWriteJSONEmptyFindingsIsArrayNotNull(t *testing.T) {
	var buf bytes.Buffer
	res := scan.Result{Findings: nil, Suppressed: 0, Files: 3}
	if err := report.WriteJSON(&buf, res, "dev"); err != nil {
		t.Fatalf("WriteJSON: unexpected error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	findingsRaw, ok := doc["findings"].([]any)
	if !ok {
		t.Fatalf(`doc["findings"] is null or not an array (must be []), got %T %v`, doc["findings"], doc["findings"])
	}
	if len(findingsRaw) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findingsRaw))
	}
}

func TestWriteSARIFTopLevelStructure(t *testing.T) {
	var buf bytes.Buffer
	res := sampleResult()
	if err := report.WriteSARIF(&buf, res, "1.2.3"); err != nil {
		t.Fatalf("WriteSARIF: unexpected error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v; raw: %s", err, buf.String())
	}

	if doc["$schema"] != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Errorf(`doc["$schema"] = %v`, doc["$schema"])
	}
	if doc["version"] != "2.1.0" {
		t.Errorf(`doc["version"] = %v, want "2.1.0"`, doc["version"])
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf(`doc["runs"] = %v, want a single-element array`, doc["runs"])
	}
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)

	if driver["name"] != "skillguard" {
		t.Errorf(`driver["name"] = %v, want "skillguard"`, driver["name"])
	}
	if driver["version"] != "1.2.3" {
		t.Errorf(`driver["version"] = %v, want "1.2.3"`, driver["version"])
	}
	if driver["informationUri"] != "https://github.com/CrescentKohana/skillguard" {
		t.Errorf(`driver["informationUri"] = %v`, driver["informationUri"])
	}
}

func TestWriteSARIFRulesArray(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, sampleResult(), "dev"); err != nil {
		t.Fatalf("WriteSARIF: unexpected error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	sarifRules, ok := driver["rules"].([]any)
	if !ok {
		t.Fatalf(`driver["rules"] is not an array: %T`, driver["rules"])
	}

	wantAll := rules.All()
	if len(sarifRules) != len(wantAll) {
		t.Fatalf("len(driver.rules) = %d, want %d (rules.All())", len(sarifRules), len(wantAll))
	}

	wantSecuritySeverity := map[finding.Severity]string{
		finding.SeverityCritical: "9.5",
		finding.SeverityHigh:     "8.0",
		finding.SeverityMedium:   "5.5",
		finding.SeverityLow:      "3.0",
		finding.SeverityInfo:     "1.0",
	}
	wantLevel := map[finding.Severity]string{
		finding.SeverityCritical: "error",
		finding.SeverityHigh:     "error",
		finding.SeverityMedium:   "warning",
		finding.SeverityLow:      "note",
		finding.SeverityInfo:     "note",
	}

	for i, raw := range sarifRules {
		r := raw.(map[string]any)
		wantRule := wantAll[i]
		if r["id"] != wantRule.ID {
			t.Errorf("rules[%d].id = %v, want %v (rules.All() must be in ID order)", i, r["id"], wantRule.ID)
		}
		if r["name"] != wantRule.Name {
			t.Errorf("rules[%d].name = %v, want %v", i, r["name"], wantRule.Name)
		}
		shortDesc := r["shortDescription"].(map[string]any)
		if _, ok := shortDesc["text"].(string); !ok {
			t.Errorf("rules[%d].shortDescription.text missing", i)
		}
		fullDesc := r["fullDescription"].(map[string]any)
		if _, ok := fullDesc["text"].(string); !ok {
			t.Errorf("rules[%d].fullDescription.text missing", i)
		}
		help := r["help"].(map[string]any)
		if _, ok := help["text"].(string); !ok {
			t.Errorf("rules[%d].help.text missing", i)
		}

		defaultConfig := r["defaultConfiguration"].(map[string]any)
		if defaultConfig["level"] != wantLevel[wantRule.Severity] {
			t.Errorf("rules[%d].defaultConfiguration.level = %v, want %v", i, defaultConfig["level"], wantLevel[wantRule.Severity])
		}

		props := r["properties"].(map[string]any)
		tags, ok := props["tags"].([]any)
		if !ok {
			t.Fatalf("rules[%d].properties.tags is not an array: %T", i, props["tags"])
		}
		tagSet := make(map[string]bool, len(tags))
		for _, tg := range tags {
			tagSet[tg.(string)] = true
		}
		if !tagSet["security"] {
			t.Errorf("rules[%d].properties.tags does not contain \"security\"", i)
		}
		for _, owaspID := range wantRule.OWASP {
			if !tagSet[owaspID] {
				t.Errorf("rules[%d].properties.tags does not contain OWASP id %q", i, owaspID)
			}
		}
		for _, atlasID := range wantRule.ATLAS {
			if !tagSet[atlasID] {
				t.Errorf("rules[%d].properties.tags does not contain ATLAS id %q", i, atlasID)
			}
		}

		gotSeverityStr, ok := props["security-severity"].(string)
		if !ok {
			t.Fatalf("rules[%d].properties[\"security-severity\"] is not a string: %T", i, props["security-severity"])
		}
		if gotSeverityStr != wantSecuritySeverity[wantRule.Severity] {
			t.Errorf("rules[%d].properties[\"security-severity\"] = %q, want %q", i, gotSeverityStr, wantSecuritySeverity[wantRule.Severity])
		}
	}
}

func TestWriteSARIFResultsAndRuleIndex(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, sampleResult(), "dev"); err != nil {
		t.Fatalf("WriteSARIF: unexpected error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	sarifRules := driver["rules"].([]any)
	ruleIndexByID := make(map[string]int, len(sarifRules))
	for i, raw := range sarifRules {
		ruleIndexByID[raw.(map[string]any)["id"].(string)] = i
	}

	results, ok := run["results"].([]any)
	if !ok || len(results) != 2 {
		t.Fatalf("run.results = %v, want 2 entries", run["results"])
	}

	wantLevels := map[string]string{"SG001": "error", "SG060": "error"}
	for _, raw := range results {
		res := raw.(map[string]any)
		ruleID := res["ruleId"].(string)
		wantIndex := ruleIndexByID[ruleID]
		gotIndex := int(res["ruleIndex"].(float64))
		if gotIndex != wantIndex {
			t.Errorf("result %s: ruleIndex = %d, want %d (index into driver.rules)", ruleID, gotIndex, wantIndex)
		}
		if res["level"] != wantLevels[ruleID] {
			t.Errorf("result %s: level = %v, want %v", ruleID, res["level"], wantLevels[ruleID])
		}
		if _, ok := res["message"].(map[string]any)["text"].(string); !ok {
			t.Errorf("result %s: message.text missing", ruleID)
		}

		locs, ok := res["locations"].([]any)
		if !ok || len(locs) != 1 {
			t.Fatalf("result %s: locations = %v, want single-element array", ruleID, res["locations"])
		}
		loc := locs[0].(map[string]any)
		physical := loc["physicalLocation"].(map[string]any)
		artifact := physical["artifactLocation"].(map[string]any)
		region := physical["region"].(map[string]any)

		if _, ok := artifact["uri"].(string); !ok {
			t.Errorf("result %s: artifactLocation.uri missing", ruleID)
		}
		if _, ok := region["startLine"].(float64); !ok {
			t.Errorf("result %s: region.startLine missing", ruleID)
		}
		if _, ok := region["startColumn"].(float64); !ok {
			t.Errorf("result %s: region.startColumn missing", ruleID)
		}
	}
}

func TestWriteSARIFLevelReflectsFindingSeverityNotRuleDefault(t *testing.T) {
	// SG040's default severity is high, but a low-severity instance (e.g. a
	// non-empty MCP auto-approve allow-list) must map to SARIF level "note".
	res := scan.Result{
		Findings: []finding.Finding{
			{RuleID: "SG040", Severity: finding.SeverityLow, Path: "x/.mcp.json", Line: 1, Column: 1, Message: "low-severity SG040 instance", Snippet: "..."},
		},
		Files: 1,
	}
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, res, "dev"); err != nil {
		t.Fatalf("WriteSARIF: unexpected error: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)
	if result["level"] != "note" {
		t.Fatalf(`result.level = %v, want "note" for a low-severity finding regardless of SG040's high default`, result["level"])
	}
}

func TestWriteSARIFURINormalization(t *testing.T) {
	res := scan.Result{
		Findings: []finding.Finding{
			{RuleID: "SG001", Severity: finding.SeverityHigh, Path: "./weird/path.md", Line: 1, Column: 1, Message: "m", Snippet: "s"},
			{RuleID: "SG002", Severity: finding.SeverityHigh, Path: "already/clean/path.md", Line: 1, Column: 1, Message: "m", Snippet: "s"},
		},
		Files: 2,
	}
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, res, "dev"); err != nil {
		t.Fatalf("WriteSARIF: unexpected error: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)

	wantURIs := map[string]string{"SG001": "weird/path.md", "SG002": "already/clean/path.md"}
	for _, raw := range results {
		r := raw.(map[string]any)
		ruleID := r["ruleId"].(string)
		uri := r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
		if uri != wantURIs[ruleID] {
			t.Errorf("result %s: uri = %q, want %q (no leading ./, forward slashes)", ruleID, uri, wantURIs[ruleID])
		}
	}
}

func TestWriteSARIFEmptyResultsIsArrayNotNull(t *testing.T) {
	var buf bytes.Buffer
	res := scan.Result{Findings: nil, Files: 5}
	if err := report.WriteSARIF(&buf, res, "dev"); err != nil {
		t.Fatalf("WriteSARIF: unexpected error: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf(`run["results"] is null or not an array (must be []), got %T %v`, run["results"], run["results"])
	}
	if len(results) != 0 {
		t.Fatalf("len(results) = %d, want 0", len(results))
	}
}

// TestSeverityMappingTableIsExhaustive verifies the SARIF level and
// security-severity tables, restated here independently of sarif.go's own switch statements, cover every Severity value.
func TestSeverityMappingTableIsExhaustive(t *testing.T) {
	wantLevel := map[finding.Severity]string{
		finding.SeverityCritical: "error",
		finding.SeverityHigh:     "error",
		finding.SeverityMedium:   "warning",
		finding.SeverityLow:      "note",
		finding.SeverityInfo:     "note",
	}
	wantSecuritySeverity := map[finding.Severity]string{
		finding.SeverityCritical: "9.5",
		finding.SeverityHigh:     "8.0",
		finding.SeverityMedium:   "5.5",
		finding.SeverityLow:      "3.0",
		finding.SeverityInfo:     "1.0",
	}
	for s := finding.SeverityInfo; s <= finding.SeverityCritical; s++ {
		if _, ok := wantLevel[s]; !ok {
			t.Errorf("Severity(%d) %q has no expected SARIF level in the exhaustiveness table", int(s), s)
		}
		if _, ok := wantSecuritySeverity[s]; !ok {
			t.Errorf("Severity(%d) %q has no expected security-severity in the exhaustiveness table", int(s), s)
		}
		if s.String() == "unknown" {
			t.Errorf("Severity(%d) in SeverityInfo..SeverityCritical has String() == \"unknown\"", int(s))
		}
	}
}
