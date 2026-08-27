// Package report renders a scan.Result as text, JSON, or SARIF 2.1.0.
package report

import (
	"fmt"
	"io"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

type severityCounts struct {
	critical, high, medium, low, info int
}

func countSeverities(findings []finding.Finding) severityCounts {
	var c severityCounts
	for _, f := range findings {
		switch f.Severity {
		case finding.SeverityCritical:
			c.critical++
		case finding.SeverityHigh:
			c.high++
		case finding.SeverityMedium:
			c.medium++
		case finding.SeverityLow:
			c.low++
		case finding.SeverityInfo:
			c.info++
		}
	}
	return c
}

// WriteText renders res in the human-readable text format.
func WriteText(w io.Writer, res scan.Result) error {
	for _, f := range res.Findings {
		if _, err := fmt.Fprintf(w, "%s:%d:%d: %s %s %s\n", f.Path, f.Line, f.Column, f.Severity, f.RuleID, f.Message); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "    %s\n", f.Snippet); err != nil {
			return err
		}
	}

	if len(res.Findings) == 0 {
		_, err := fmt.Fprintf(w, "No findings. %d files scanned.\n", res.Files)
		return err
	}

	c := countSeverities(res.Findings)
	_, err := fmt.Fprintf(w, "%d findings (%d critical, %d high, %d medium, %d low, %d info), %d suppressed, %d files scanned\n",
		len(res.Findings), c.critical, c.high, c.medium, c.low, c.info, res.Suppressed, res.Files)
	return err
}
