package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/privilege"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// harness is one invocation with the outside world replaced.
//
// Nothing here can reach a clock, a terminal or a file system. The written map
// stands in for the disk, so a test - and the fuzz target especially - can
// exercise every path through --out without a single file appearing anywhere.
type harness struct {
	stdout  bytes.Buffer
	stderr  bytes.Buffer
	written map[string][]byte
	code    exitcode.Code
}

func invoke(args ...string) *harness {
	return invokeAs(report.PrivilegeUnknown, args...)
}

// invokeAs is invoke with the privilege level the run reports.
//
// It exists because the report has to say something different depending on
// whether that level was established, and a test cannot elevate the process it
// runs in. The level arrives as a parameter for the same reason the clock does.
func invokeAs(level report.PrivilegeLevel, args ...string) *harness {
	h := &harness{written: map[string][]byte{}}
	h.code = guarded(context.Background(), args, environment{
		stdout: &h.stdout,
		stderr: &h.stderr,
		capability: func(bool) render.Capability {
			// A fixed answer. What a real console can render is decided by the
			// operating system, and a test that asked it would pass or fail
			// depending on where it ran.
			return render.Capability{}
		},
		now:       func() time.Time { return time.Unix(1_770_000_000, 0).UTC() },
		platform:  report.Platform{OS: "testos", Arch: "testarch"},
		privilege: level,
		writeFile: func(path string, data []byte) error {
			h.written[path] = data
			return nil
		},
	})
	return h
}

// TestOnlyASuccessfulRunWritesToStandardOutput is the channel guard.
//
// The rule is not "failures are quiet". It is that what goes to standard output
// is the DESCRIPTION of a run that happened, and a run that did not happen has
// no description. A run that could assess nothing did happen, and its report is
// a complete answer - so 5 prints in full while 2 and 3 print nothing at all.
// Reading the rule the other way would make this tool silent in precisely the
// situation it exists for.
func TestOnlyASuccessfulRunWritesToStandardOutput(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want exitcode.Code
	}{
		{"a run that assessed nothing", []string{"https://example.com"}, exitcode.Inconclusive},
		{"help", []string{"--help"}, exitcode.OK},
		{"version", []string{"--version"}, exitcode.OK},
		{"licence", []string{"--license"}, exitcode.OK},
		{"no target", nil, exitcode.Usage},
		{"unknown switch", []string{"https://example.com", "--nope"}, exitcode.Usage},
		{"target without a scheme", []string{"example.com"}, exitcode.Usage},
		{"two targets", []string{"https://a.example", "https://b.example"}, exitcode.Usage},
		{"format not built", []string{"https://example.com", "--format", "md"}, exitcode.Config},
		{"contradictory formats", []string{"https://example.com", "--json", "--format", "html"}, exitcode.Config},
		{"compare with nothing to compare", []string{"https://example.com", "--compare", "host,container"}, exitcode.Config},
		{"two places to run", []string{"https://example.com", "--in", "c", "--image", "i"}, exitcode.Config},
		{"opposite log levels", []string{"https://example.com", "--quiet", "--verbose"}, exitcode.Config},
		{"negative budget", []string{"https://example.com", "--timeout", "-1"}, exitcode.Config},
		{"budget that is not a number of seconds", []string{"https://example.com", "--timeout", "NaN"}, exitcode.Config},
		{"budget longer than a day", []string{"https://example.com", "--timeout", "1e300"}, exitcode.Config},
	}

	for _, c := range cases {
		h := invoke(c.args...)
		if h.code != c.want {
			t.Errorf("%s: ended with %s (%d), want %s (%d)\nstderr: %s",
				c.name, h.code.Name(), h.code.Int(), c.want.Name(), c.want.Int(), h.stderr.String())
			continue
		}
		printed := h.stdout.Len() > 0
		shouldPrint := c.want == exitcode.OK || c.want == exitcode.Diagnosis || c.want == exitcode.Inconclusive
		if printed != shouldPrint {
			t.Errorf("%s: ended with %s and wrote %d bytes to standard output, want %v",
				c.name, h.code.Name(), h.stdout.Len(), shouldPrint)
		}
		if !shouldPrint && h.stderr.Len() == 0 {
			t.Errorf("%s: ended with %s and said nothing anywhere", c.name, h.code.Name())
		}
	}
}

// TestASwitchAfterTheURLIsStillASwitch guards a defect that was measured rather
// than imagined.
//
// The standard library's flag package stops parsing at the first argument that
// is not a switch and reports nothing about it. Every example in this project's
// own plan puts the URL first, so without the pre-scan in splitTarget the
// command "certdoctor https://example.com --json" would print a terminal report,
// ignore --json, and say nothing about having done so. A program that looks like
// it worked is the worst thing this one can be.
func TestASwitchAfterTheURLIsStillASwitch(t *testing.T) {
	if out := invoke("https://example.com", "--json").stdout.String(); !strings.HasPrefix(out, "{") {
		t.Errorf("--json after the URL was ignored, the output starts:\n%.80s", out)
	}
	if h := invoke("https://example.com", "--format", "json"); !strings.HasPrefix(h.stdout.String(), "{") {
		t.Errorf("--format json after the URL was ignored, the output starts:\n%.80s", h.stdout.String())
	}
	// A switch taking a value must consume the value and not leave it looking
	// like a second URL.
	if h := invoke("https://example.com", "--timeout", "5"); h.code != exitcode.Inconclusive {
		t.Errorf("--timeout 5 after the URL ended with %s: %s", h.code.Name(), h.stderr.String())
	}
	// The same switch written with an equals sign takes no following argument,
	// and swallowing one would eat the URL.
	if h := invoke("--timeout=5", "https://example.com"); h.code != exitcode.Inconclusive {
		t.Errorf("--timeout=5 before the URL ended with %s: %s", h.code.Name(), h.stderr.String())
	}
}

// TestEveryEndingCarriesACodeFromTheTable is the second half of the same
// promise, and the one a pipeline actually depends on.
func TestEveryEndingCarriesACodeFromTheTable(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--help"}, {"--version"}, {"--license"}, {"https://example.com"},
		{"--"}, {"-"}, {"--out"}, {"--timeout"}, {"https://example.com", "--out", "report.json", "--json"},
	} {
		if code := invoke(args...).code; !code.Valid() {
			t.Errorf("%v ended with %d, which is not in the frozen table", args, code.Int())
		}
	}
}

// TestTheProcessCodeMatchesTheOneInsideTheReport keeps the redundancy in the
// machine readable document honest. A saved report whose exit_code disagrees
// with what the process returned is worse than one that carries no code at all.
func TestTheProcessCodeMatchesTheOneInsideTheReport(t *testing.T) {
	h := invoke("https://example.com", "--json")
	if h.code != exitcode.Inconclusive {
		t.Fatalf("the run ended with %s: %s", h.code.Name(), h.stderr.String())
	}

	var document struct {
		Verdict struct {
			ExitCode int `json:"exit_code"`
		} `json:"verdict"`
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &document); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}
	if document.Verdict.ExitCode != h.code.Int() {
		t.Errorf("the report says exit_code %d and the process returned %d",
			document.Verdict.ExitCode, h.code.Int())
	}
}

// TestTheTargetNeverCarriesACredential is the narrow, early form of the promise
// that credentials never reach a report.
//
// The masking function belongs to the next slice on purpose, so that no code
// capable of printing a password exists before it. This checks the consequence:
// until then the target is reduced to its origin, and nothing that could be a
// secret survives that.
func TestTheTargetNeverCarriesACredential(t *testing.T) {
	secrets := []string{"hunter2", "abc123token", "sessionid", "deep"}
	targets := []string{
		"https://user:hunter2@example.com/",
		"https://example.com/deep/path",
		"https://example.com/?token=abc123token",
		"https://example.com/#sessionid",
		"https://user:hunter2@example.com:8443/deep/path?token=abc123token#sessionid",
	}

	for _, target := range targets {
		for _, format := range []string{"terminal", "json"} {
			h := invoke(target, "--format", format)
			if h.code != exitcode.Inconclusive {
				t.Fatalf("%s as %s ended with %s: %s", target, format, h.code.Name(), h.stderr.String())
			}
			everything := h.stdout.String() + h.stderr.String()
			for _, secret := range secrets {
				if strings.Contains(everything, secret) {
					t.Errorf("%s as %s put %q in the output", target, format, secret)
				}
			}
		}
	}
}

// TestAReducedTargetSaysSoAndAnUntouchedOneDoesNot keeps the note above from
// becoming decoration. A note printed every time says nothing, and a note never
// printed hides that something was dropped.
func TestAReducedTargetSaysSoAndAnUntouchedOneDoesNot(t *testing.T) {
	if out := invoke("https://example.com/secret", "--json").stdout.String(); !strings.Contains(out, `"reduced"`) {
		t.Error("a target with a path was reduced and the report does not say so")
	}
	if out := invoke("https://example.com", "--json").stdout.String(); strings.Contains(out, `"reduced"`) {
		t.Error("a target with nothing to remove was reported as reduced")
	}
	if out := invoke("https://example.com/", "--json").stdout.String(); strings.Contains(out, `"reduced"`) {
		t.Error("a bare trailing slash was treated as something worth removing")
	}
}

// TestAnUndeterminedPrivilegeLevelIsAnnouncedAndAnEstablishedOneIsNot is the
// ban on silence applied to a metadata field.
//
// "unknown" is a legitimate answer here and it is also the answer that makes a
// later comparison of two reports meaningless, because certdoctor run as a user
// and as an administrator sees different trust stores. So it may never be
// quiet: a run that could not establish its level says so, in the notes and not
// only in the field.
//
// THE SECOND HALF MATTERS AS MUCH AS THE FIRST. A standing note that never goes
// away teaches people that notes are decoration, and then the one note that
// mattered is skipped with the rest. This is the shape that erodes on its own,
// because removing a note is the step nobody remembers.
func TestAnUndeterminedPrivilegeLevelIsAnnouncedAndAnEstablishedOneIsNot(t *testing.T) {
	unknown := invokeAs(report.PrivilegeUnknown, "https://example.com", "--json").stdout.String()
	if !strings.Contains(unknown, `"run.privilege_level"`) {
		t.Error("the level could not be established and the report does not say so")
	}

	for _, level := range []report.PrivilegeLevel{report.PrivilegeUser, report.PrivilegeElevated} {
		out := invokeAs(level, "https://example.com", "--json").stdout.String()
		if strings.Contains(out, `"run.privilege_level"`) {
			t.Errorf("level %q was established and the report still announces it was not", level)
		}
		if want := `"privilege_level": "` + string(level) + `"`; !strings.Contains(out, want) {
			t.Errorf("level %q is not in the document", level)
		}
	}
}

// TestTheLiveEnvironmentAsksForTheRealPrivilegeLevel pins the WIRING rather
// than the rule.
//
// Every other test here hands the level in through the harness, which is what
// makes them runnable anywhere - and it also means a build that stopped asking
// the operating system and passed a constant instead would leave all of them
// green, while every report on every machine said "unknown" for ever.
//
// ⚠️ On a machine where the question genuinely fails this compares unknown
// against unknown and proves less. That is accepted: it is a pin on one line of
// wiring, not a statement about the platform.
func TestTheLiveEnvironmentAsksForTheRealPrivilegeLevel(t *testing.T) {
	if got, want := liveEnvironment().privilege, privilege.Level(); got != want {
		t.Errorf("the wiring reports %q where the platform answers %q", got, want)
	}
}

// TestEveryLayerInTheDocumentAppearsInTheTerminalReport is the parity rule.
// Every finding has to be expressible on every surface, and the way that erodes
// is one surface quietly gaining a row the others do not have.
func TestEveryLayerInTheDocumentAppearsInTheTerminalReport(t *testing.T) {
	terminal := invoke("https://example.com").stdout.String()

	var document struct {
		Layers []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(invoke("https://example.com", "--json").stdout.Bytes(), &document); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}
	if len(document.Layers) != len(layer.All) {
		t.Fatalf("the document has %d layers, there are %d declared", len(document.Layers), len(layer.All))
	}
	for _, row := range document.Layers {
		if !strings.Contains(terminal, row.ID) {
			t.Errorf("layer %s is in the document and not in the terminal report", row.ID)
		}
		if !strings.Contains(terminal, row.Status) {
			t.Errorf("status %s appears in the document and nowhere in the terminal report", row.Status)
		}
	}
}

// TestTheSameRunProducesTheSameBytes is the determinism property. Iteration over
// a Go map is randomised, so a renderer that walked one would reorder sections
// between runs of identical input - and every test written as a single
// comparison would still pass.
func TestTheSameRunProducesTheSameBytes(t *testing.T) {
	for _, format := range []string{"terminal", "json"} {
		first := invoke("https://example.com", "--format", format).stdout.String()
		for attempt := 0; attempt < 15; attempt++ {
			again := invoke("https://example.com", "--format", format).stdout.String()
			if again != first {
				t.Fatalf("two %s runs of the same command line differ", format)
			}
		}
	}
}

// TestThePanicPathEndsInRuntimeAndPrintsNothing covers the ending that would
// otherwise be reported to a pipeline as a usage error, because the Go runtime
// exits with 2 on a panic and 2 means USAGE in this table.
func TestThePanicPathEndsInRuntimeAndPrintsNothing(t *testing.T) {
	h := &harness{written: map[string][]byte{}}
	h.code = guarded(context.Background(), []string{"https://example.com"}, environment{
		stdout:     &h.stdout,
		stderr:     &h.stderr,
		capability: func(bool) render.Capability { panic("planted defect") },
		now:        func() time.Time { return time.Unix(0, 0) },
		platform:   report.Platform{OS: "testos", Arch: "testarch"},
		privilege:  report.PrivilegeUnknown,
		writeFile:  func(string, []byte) error { return nil },
	})

	if h.code != exitcode.Runtime {
		t.Errorf("a panic ended with %s (%d), want RUNTIME", h.code.Name(), h.code.Int())
	}
	if h.stdout.Len() != 0 {
		t.Errorf("a panic left %d bytes on standard output", h.stdout.Len())
	}
	if !strings.Contains(h.stderr.String(), "planted defect") {
		t.Errorf("the failure does not say what happened: %s", h.stderr.String())
	}
}

// TestAReportGoesToTheNamedPathAndNotToStandardOutput pins the two halves of
// --out. Writing to both would put internal data somewhere the user did not ask
// for, and writing to neither would lose the report entirely.
func TestAReportGoesToTheNamedPathAndNotToStandardOutput(t *testing.T) {
	h := invoke("https://example.com", "--json", "--out", "report.json")

	if h.code != exitcode.Inconclusive {
		t.Fatalf("the run ended with %s: %s", h.code.Name(), h.stderr.String())
	}
	if h.stdout.Len() != 0 {
		t.Errorf("the report was written to a file and %d bytes still went to standard output", h.stdout.Len())
	}
	written, ok := h.written["report.json"]
	if !ok {
		t.Fatalf("nothing was written to report.json, only to %v", keysOf(h.written))
	}
	if err := render.ValidateDocument(written); err != nil {
		t.Errorf("the written document does not match the declared schema:\n%v", err)
	}
}

// TestNothingIsWrittenWhenTheReportGoesToStandardOutput is the other side. A run
// without --out must not touch the file system at all.
func TestNothingIsWrittenWhenTheReportGoesToStandardOutput(t *testing.T) {
	for _, args := range [][]string{
		{"https://example.com"},
		{"https://example.com", "--json"},
		{"https://example.com", "--out", "-"},
		{"--help"},
	} {
		if h := invoke(args...); len(h.written) != 0 {
			t.Errorf("%v wrote %v", args, keysOf(h.written))
		}
	}
}

func keysOf(m map[string][]byte) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	return names
}

// documentedSwitch matches a long switch as it is written in help.
var documentedSwitch = regexp.MustCompile(`--[a-z][a-z0-9-]*`)

// TestEveryFlagIsDocumentedAndEveryDocumentedFlagExists is the cheap guard the
// CLI rules ask for from the first flag onwards.
//
// Both directions matter and they fail differently. A switch accepted and not
// documented is a feature nobody can find. A switch documented and not accepted
// is worse: somebody types it, gets a usage error, and stops trusting the page.
//
// The declarations and the page are built from one table, so this cannot catch
// a mismatch between those two. What it catches is a switch registered straight
// onto the flag set, bypassing the table, and a name written into the page's
// prose by hand.
func TestEveryFlagIsDocumentedAndEveryDocumentedFlagExists(t *testing.T) {
	fs, _ := newFlagSet()
	page := helpText()

	registered := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		registered[f.Name] = true
		long, short := "--"+f.Name, "-"+f.Name
		if !strings.Contains(page, long) && !strings.Contains(page, short) {
			t.Errorf("the switch %s is accepted and does not appear in --help", long)
		}
	})
	if len(registered) == 0 {
		t.Fatal("no switches are registered, so this test would pass while checking nothing")
	}

	for _, mentioned := range documentedSwitch.FindAllString(page, -1) {
		name := strings.TrimPrefix(mentioned, "--")
		if !registered[name] {
			t.Errorf("--help mentions %s and nothing accepts it", mentioned)
		}
	}
}
