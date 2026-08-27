package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/rules"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

const sarifInformationURI = "https://github.com/CrescentKohana/skillguard"

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifRuleProperties struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     sarifMessage        `json:"shortDescription"`
	FullDescription      sarifMessage        `json:"fullDescription"`
	Help                 sarifMessage        `json:"help"`
	DefaultConfiguration sarifDefaultConfig  `json:"defaultConfiguration"`
	Properties           sarifRuleProperties `json:"properties"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

func sarifLevel(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// sarifURI normalizes a finding path to forward slashes with no leading "./".
func sarifURI(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.HasPrefix(p, "./") {
		p = strings.TrimPrefix(p, "./")
	}
	return p
}

func securitySeverity(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return "9.5"
	case finding.SeverityHigh:
		return "8.0"
	case finding.SeverityMedium:
		return "5.5"
	case finding.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

// WriteSARIF renders res as a single-run SARIF 2.1.0 log.
func WriteSARIF(w io.Writer, res scan.Result, toolVersion string) error {
	allRules := rules.All()
	ruleIndex := make(map[string]int, len(allRules))
	sarifRules := make([]sarifRule, 0, len(allRules))
	for i, r := range allRules {
		ruleIndex[r.ID] = i
		tags := make([]string, 0, 1+len(r.OWASP)+len(r.ATLAS))
		tags = append(tags, "security")
		tags = append(tags, r.OWASP...)
		tags = append(tags, r.ATLAS...)
		sarifRules = append(sarifRules, sarifRule{
			ID:                   r.ID,
			Name:                 r.Name,
			ShortDescription:     sarifMessage{Text: r.Description},
			FullDescription:      sarifMessage{Text: r.Description},
			Help:                 sarifMessage{Text: r.Description},
			DefaultConfiguration: sarifDefaultConfig{Level: sarifLevel(r.Severity)},
			Properties:           sarifRuleProperties{Tags: tags, SecuritySeverity: securitySeverity(r.Severity)},
		})
	}

	results := make([]sarifResult, 0, len(res.Findings))
	for _, f := range res.Findings {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			return fmt.Errorf("SARIF: finding has unknown rule ID %q", f.RuleID)
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: sarifURI(f.Path)},
					Region:           sarifRegion{StartLine: f.Line, StartColumn: f.Column},
				},
			}},
		})
	}

	rep := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "skillguard",
				Version:        toolVersion,
				InformationURI: sarifInformationURI,
				Rules:          sarifRules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
