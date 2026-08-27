// Package finding defines the shared result type that every detection rule
// produces and every report writer consumes.
package finding

import (
	"fmt"
	"strings"
)

// Severity ranks a Finding. Zero value is SeverityInfo.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns "info", "low", "medium", "high", or "critical".
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity accepts "info", "low", "medium", "high", "critical" case-insensitively.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return 0, fmt.Errorf("invalid severity %q", s)
	}
}

// Finding is one detection-rule hit at a specific file location.
type Finding struct {
	RuleID   string
	Severity Severity
	// Path is forward-slash, as discovered (relative to the CWD if the root was relative).
	Path string
	// Line is 1-based.
	Line int
	// Column is 1-based, counted in Unicode code points (runes) on that line.
	Column int
	// Message is human-readable; for SG060 it must not contain the raw secret.
	Message string
	// Snippet is the offending line, trimmed, at most 200 runes, secrets masked,
	// with invisible characters rendered as <U+XXXX>.
	Snippet string
}
