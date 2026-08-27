package finding_test

import (
	"testing"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  finding.Severity
		want string
	}{
		{finding.SeverityInfo, "info"},
		{finding.SeverityLow, "low"},
		{finding.SeverityMedium, "medium"},
		{finding.SeverityHigh, "high"},
		{finding.SeverityCritical, "critical"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.sev.String(); got != tc.want {
				t.Fatalf("Severity(%d).String() = %q, want %q", tc.sev, got, tc.want)
			}
		})
	}
}

func TestParseSeverityValid(t *testing.T) {
	cases := []struct {
		input string
		want  finding.Severity
	}{
		{"info", finding.SeverityInfo},
		{"INFO", finding.SeverityInfo},
		{"Info", finding.SeverityInfo},
		{"low", finding.SeverityLow},
		{"LOW", finding.SeverityLow},
		{"medium", finding.SeverityMedium},
		{"MEDIUM", finding.SeverityMedium},
		{"Medium", finding.SeverityMedium},
		{"high", finding.SeverityHigh},
		{"HIGH", finding.SeverityHigh},
		{"critical", finding.SeverityCritical},
		{"CRITICAL", finding.SeverityCritical},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := finding.ParseSeverity(tc.input)
			if err != nil {
				t.Fatalf("ParseSeverity(%q) returned error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ParseSeverity(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseSeverityInvalid(t *testing.T) {
	for _, input := range []string{"", "none", "extreme", "HIGHH", " high", "high ", "fatal", "warn"} {
		t.Run(input, func(t *testing.T) {
			if _, err := finding.ParseSeverity(input); err == nil {
				t.Fatalf("ParseSeverity(%q): expected error, got nil", input)
			}
		})
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	for s := finding.SeverityInfo; s <= finding.SeverityCritical; s++ {
		parsed, err := finding.ParseSeverity(s.String())
		if err != nil {
			t.Fatalf("ParseSeverity(%q): %v", s.String(), err)
		}
		if parsed != s {
			t.Fatalf("ParseSeverity(%q) = %v, want %v", s.String(), parsed, s)
		}
	}
}
