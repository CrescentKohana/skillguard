// Package cli implements the skillguard command-line interface.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CrescentKohana/skillguard/internal/finding"
	"github.com/CrescentKohana/skillguard/internal/report"
	"github.com/CrescentKohana/skillguard/internal/rules"
	"github.com/CrescentKohana/skillguard/internal/scan"
)

// Version is the released version; overridable with -ldflags -X.
var Version = "dev"

const usage = `skillguard - static analysis for AI-agent skill and configuration files

Usage:
  skillguard scan [flags] [path ...]     scan paths for findings (default path ".")
  skillguard rules [--format text|json]  list detection rules
  skillguard version                     print the version
  skillguard help | -h | --help          show this help

scan flags:
  --format text|json|sarif   output format (default "text")
  --output FILE              write output to FILE (default stdout)
  --fail-on SEVERITY         minimum severity that causes a non-zero exit:
                             info|low|medium|high|critical|none (default "medium")
`

// Run executes the CLI with args excluding the program name and returns the
// process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}

	switch cmd := args[0]; cmd {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "rules":
		return runRules(args[1:], stdout, stderr)
	case "version":
		_, _ = fmt.Fprintf(stdout, "skillguard %s\n", Version)
		return 0
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "skillguard: unknown command %q\n", cmd)
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text|json|sarif")
	output := fs.String("output", "", "output file (default stdout)")
	failOn := fs.String("fail-on", "medium", "minimum severity to fail on: info|low|medium|high|critical|none")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	switch *format {
	case "text", "json", "sarif":
	default:
		_, _ = fmt.Fprintf(stderr, "skillguard: invalid --format value %q\n", *format)
		return 2
	}

	failNone := strings.EqualFold(*failOn, "none")
	var failSeverity finding.Severity
	if !failNone {
		sev, err := finding.ParseSeverity(*failOn)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "skillguard: invalid --fail-on value %q\n", *failOn)
			return 2
		}
		failSeverity = sev
	}

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	res, err := scan.Scan(paths)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "skillguard: %v\n", err)
		return 2
	}
	for _, w := range res.Warnings {
		_, _ = fmt.Fprintf(stderr, "warning: %s\n", w)
	}

	out := stdout
	var closeOutput func() error
	if *output != "" {
		f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // G304: path comes from the user's own --output flag
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "skillguard: %v\n", err)
			return 2
		}
		out = f
		closeOutput = f.Close
	}

	writeErr := writeReport(out, *format, res)
	if closeOutput != nil {
		if cerr := closeOutput(); writeErr == nil {
			writeErr = cerr
		}
	}
	if writeErr != nil {
		_, _ = fmt.Fprintf(stderr, "skillguard: %v\n", writeErr)
		return 2
	}

	if failNone {
		return 0
	}
	for _, f := range res.Findings {
		if f.Severity >= failSeverity {
			return 1
		}
	}
	return 0
}

func writeReport(w io.Writer, format string, res scan.Result) error {
	switch format {
	case "json":
		return report.WriteJSON(w, res, Version)
	case "sarif":
		return report.WriteSARIF(w, res, Version)
	default:
		return report.WriteText(w, res)
	}
}

func runRules(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text|json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	switch *format {
	case "text":
		for _, r := range rules.All() {
			_, _ = fmt.Fprintf(stdout, "%s %s %s owasp=%s atlas=%s\n",
				r.ID, r.Name, r.Severity, strings.Join(r.OWASP, ","), strings.Join(r.ATLAS, ","))
		}
		return 0
	case "json":
		return writeRulesJSON(stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "skillguard: invalid --format value %q\n", *format)
		return 2
	}
}

type ruleJSON struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	OWASP    []string `json:"owasp"`
	ATLAS    []string `json:"atlas"`
}

func writeRulesJSON(stdout, stderr io.Writer) int {
	all := rules.All()
	out := make([]ruleJSON, 0, len(all))
	for _, r := range all {
		out = append(out, ruleJSON{ID: r.ID, Name: r.Name, Severity: r.Severity.String(), OWASP: r.OWASP, ATLAS: r.ATLAS})
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		_, _ = fmt.Fprintf(stderr, "skillguard: %v\n", err)
		return 2
	}
	return 0
}
