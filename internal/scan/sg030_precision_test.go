package scan_test

import (
	"testing"

	"github.com/CrescentKohana/skillguard/internal/scan"
)

// TestSG030RmQuotedTargetsIgnoreSurroundingQuotes covers C4: surrounding
// single or double quotes on an rm target must be ignored when matching
// against the catastrophic-target list.
func TestSG030RmQuotedTargetsIgnoreSurroundingQuotes(t *testing.T) {
	cases := []string{
		`rm -rf "$HOME"`,
		`rm -rf '/'`,
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
			if !hasRule(findings, "SG030") {
				t.Fatalf("line %q must trigger SG030 (quotes around the target must be ignored); findings=%+v", line, findings)
			}
		})
	}
}

// TestSG030MkfsRequiresDeviceArgument covers C4: mkfs only fires when
// invoked with a device argument, not on mere prose mentions of the word.
func TestSG030MkfsRequiresDeviceArgument(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		fires bool
	}{
		{"mkfs-ext4-device", "mkfs.ext4 /dev/sda1", true},
		{"mkfs-t-ext4-device", "mkfs -t ext4 /dev/sdb", true},
		{"prose-mention-no-device", "never run `mkfs` on the host", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(tc.line+"\n"))
			got := hasRule(findings, "SG030")
			if got != tc.fires {
				t.Fatalf("line %q: SG030 fired=%v, want %v; findings=%+v", tc.line, got, tc.fires, findings)
			}
		})
	}
}

// TestSG030MkfsFiresOnlyWhenDeviceOrVarArgumentPrecedesAnyShellSeparator verifies
// mkfs/mkfs.<fs> must be followed, before any shell separator (";", "|", "&", or
// end of line), by a token starting with "/dev/" or "$"; a path after the separator must not fire.
func TestSG030MkfsFiresOnlyWhenDeviceOrVarArgumentPrecedesAnyShellSeparator(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		fires bool
	}{
		{"device-arg", "mkfs.ext4 /dev/sda1", true},
		{"flag-then-device-arg", "mkfs -t ext4 /dev/sdb", true},
		{"env-var-device-arg", "mkfs.ext4 $DISK", true},
		{"prose-no-device", "never run `mkfs` on the host", false},
		{"device-after-semicolon-separator", "Do not run mkfs; the disk is /dev/sda1 on this host", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(tc.line+"\n"))
			got := hasRule(findings, "SG030")
			if got != tc.fires {
				t.Fatalf("line %q: SG030 fired=%v, want %v; findings=%+v", tc.line, got, tc.fires, findings)
			}
		})
	}
}

// TestSG030RmColumnIsTheRmTokenItselfNotASubstringMatch verifies the column
// points at the rm command token itself, even when "rm" also appears as a substring of an earlier word (e.g. "confirm").
func TestSG030RmColumnIsTheRmTokenItselfNotASubstringMatch(t *testing.T) {
	line := "Please confirm before you rm -rf / the machine"
	findings := scan.ScanContent("AGENTS.md", scan.KindAgents, []byte(line+"\n"))
	f := findRule(t, findings, "SG030")
	if f.Column != 27 {
		t.Fatalf(`SG030 column = %d, want 27 (the "rm" command token itself; %q must not match the "rm" inside "confirm" at an earlier column)`, f.Column, line)
	}
}
