package report

import (
	"encoding/json"
	"io"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

type jsonFinding struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Message  string `json:"message"`
	Snippet  string `json:"snippet"`
}

type jsonSummary struct {
	Total      int `json:"total"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Info       int `json:"info"`
	Suppressed int `json:"suppressed"`
	Files      int `json:"files"`
}

type jsonReport struct {
	Tool     string        `json:"tool"`
	Version  string        `json:"version"`
	Findings []jsonFinding `json:"findings"`
	Summary  jsonSummary   `json:"summary"`
}

// WriteJSON renders res as the fixed SkillGuard JSON report shape.
func WriteJSON(w io.Writer, res scan.Result, toolVersion string) error {
	findings := make([]jsonFinding, 0, len(res.Findings))
	for _, f := range res.Findings {
		findings = append(findings, jsonFinding{
			RuleID:   f.RuleID,
			Severity: f.Severity.String(),
			Path:     f.Path,
			Line:     f.Line,
			Column:   f.Column,
			Message:  f.Message,
			Snippet:  f.Snippet,
		})
	}
	c := countSeverities(res.Findings)
	rep := jsonReport{
		Tool:     "skillguard",
		Version:  toolVersion,
		Findings: findings,
		Summary: jsonSummary{
			Total:      len(res.Findings),
			Critical:   c.critical,
			High:       c.high,
			Medium:     c.medium,
			Low:        c.low,
			Info:       c.info,
			Suppressed: res.Suppressed,
			Files:      res.Files,
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
