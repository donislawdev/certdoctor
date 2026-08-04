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
	return invokeIn(nil, level, args...)
}

// invokeIn is invokeAs with the environment L0 will read.
//
// A nil map is the ordinary case and means nothing is set. THE REAL ENVIRONMENT
// IS NEVER CONSULTED HERE, and that is not caution: the variables L0 reports are
// exactly the ones a developer machine behind a corporate proxy has set, so a
// test that read them would pass here and fail there, or worse, print somebody's
// internal proxy host into a test log.
//
// A name present with an empty value is a variable SET TO NOTHING, which is a
// different fact from absent and is one of the three states L0 has to tell
// apart.
func invokeIn(env map[string]string, level report.PrivilegeLevel, args ...string) *harness {
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
		lookupEnv: func(name string) (string, bool) {
			value, set := env[name]
			return value, set
		},
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
// NOTE: On a machine where the question genuinely fails this compares unknown
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
// THE EMPTINESS CHECK IS NOT DECORATION AND IT WAS ADDED AFTER A MEASUREMENT.
// Without it this test is satisfied by a program that prints NOTHING, because
// two empty strings are equal. That is not hypothetical: the mutation that makes
// the orchestrator walk its map instead of the registry produces rows in the
// wrong order, the report validator refuses them, and the run ends with an
// internal failure having written nothing at all. Sixteen silent runs agree
// perfectly. Measured 2026-08-04 over thirty runs of the register: the mutation
// was caught 13 times out of 30 - a guard that is a coin toss is not a guard,
// and it read as a clean pass in the summary line.
func TestTheSameRunProducesTheSameBytes(t *testing.T) {
	for _, format := range []string{"terminal", "json"} {
		first := invoke("https://example.com", "--format", format).stdout.String()
		if first == "" {
			t.Fatalf("a %s run produced no report at all, so comparing it with another proves nothing", format)
		}
		for attempt := 0; attempt < 15; attempt++ {
			again := invoke("https://example.com", "--format", format).stdout.String()
			if again == "" {
				t.Fatalf("a %s run produced no report at all, so comparing it with another proves nothing", format)
			}
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

// TestAnUnknownSwitchIsNamedRatherThanTheURLBlamed covers a message that
// pointed at the only correct part of the command line.
//
// An unregistered switch consumed nothing, so whatever followed it became the
// URL and the real URL became an "unexpected extra argument". The person with a
// typo in a flag name went looking at their address. The same typo also read
// differently before and after the URL, which is two diagnoses for one mistake.
func TestAnUnknownSwitchIsNamedRatherThanTheURLBlamed(t *testing.T) {
	orders := [][]string{
		{"--unknown-flag", "value", "https://example.com"},
		{"https://example.com", "--unknown-flag"},
		{"--unknown-flag=value", "https://example.com"},
	}
	for _, args := range orders {
		h := invoke(args...)
		if h.code != exitcode.Usage {
			t.Errorf("%v ended %d, want %d", args, h.code, exitcode.Usage)
		}
		if !strings.Contains(h.stderr.String(), "unknown-flag") {
			t.Errorf("%v: the message does not name the switch: %q", args, h.stderr.String())
		}
		if strings.Contains(h.stderr.String(), "extra argument") {
			t.Errorf("%v: the message blames the URL: %q", args, h.stderr.String())
		}
	}
}

// TestAnExplicitFormatContradictingJSONIsRefused keeps two requests for two
// different formats from being settled quietly.
//
// --format md with --json was already refused. --format terminal with --json
// was not, because the value alone cannot be told from the default, so --json
// won and the run produced a document in a form nobody had asked for in those
// words. The same contradiction had two different answers.
func TestAnExplicitFormatContradictingJSONIsRefused(t *testing.T) {
	for _, args := range [][]string{
		{"--format", "terminal", "--json", "https://example.com"},
		{"--json", "--format", "terminal", "https://example.com"},
	} {
		h := invoke(args...)
		if h.code != exitcode.Config {
			t.Errorf("%v ended %d, want %d", args, h.code, exitcode.Config)
		}
		if h.stdout.Len() != 0 {
			t.Errorf("%v printed a report over a contradiction: %q", args, h.stdout.String())
		}
	}
	// The alias on its own is not a contradiction and still has to work.
	if h := invoke("--json", "https://example.com"); !strings.Contains(h.stdout.String(), `"schema_version"`) {
		t.Errorf("--json alone stopped producing a document: %q", h.stdout.String())
	}
}

// TestTwoMetaSwitchesAreRefusedRatherThanOneBeingDropped is the ban on silence
// applied to the switches that describe the tool. Each is a complete answer, so
// two of them are two answers - and the version printed the first in a fixed
// order and dropped the rest without a word.
func TestTwoMetaSwitchesAreRefusedRatherThanOneBeingDropped(t *testing.T) {
	for _, args := range [][]string{
		{"--version", "--license"},
		{"--help", "--version"},
	} {
		h := invoke(args...)
		if h.code != exitcode.Config {
			t.Errorf("%v ended %d, want %d", args, h.code, exitcode.Config)
		}
	}
	if h := invoke("--version"); h.code != exitcode.OK || h.stdout.Len() == 0 {
		t.Errorf("--version on its own stopped working: code %d, %q", h.code, h.stdout.String())
	}
}

// TestABudgetTooShortToHonourIsRefusedRatherThanBecomingNoLimit covers the one
// value of this flag whose meaning inverted.
//
// A duration is a whole number of nanoseconds, so 1e-30 seconds truncated to
// zero - and zero is the documented way of asking for NO limit. Somebody typing
// the strictest budget they could imagine got an unlimited run, and the report
// then said the budget had not been exceeded.
func TestABudgetTooShortToHonourIsRefusedRatherThanBecomingNoLimit(t *testing.T) {
	for _, flag := range []string{"--timeout", "--probe-timeout"} {
		h := invoke("https://example.com", flag, "1e-30")
		if h.code != exitcode.Config {
			t.Errorf("%s 1e-30 ended %d, want %d: %q", flag, h.code, exitcode.Config, h.stderr.String())
		}
		// Zero still means no limit, and that has to keep working.
		if h := invoke("https://example.com", flag, "0"); h.code != exitcode.Inconclusive {
			t.Errorf("%s 0 stopped meaning no limit: %d %q", flag, h.code, h.stderr.String())
		}
	}
}

// TestTheHostIsReportedWithoutRegardToCase keeps one machine from appearing as
// two.
//
// Names in DNS are case insensitive. Left as typed, EXAMPLE.COM and example.com
// produced two different targets for one machine - two reports that do not
// compare, a difference --compare would report where nothing changed, and two
// pseudonyms under --redact for one host.
func TestTheHostIsReportedWithoutRegardToCase(t *testing.T) {
	upper := invoke("HTTPS://EXAMPLE.COM/", "--json")
	lower := invoke("https://example.com/", "--json")
	if upper.stdout.String() != lower.stdout.String() {
		t.Errorf("the same machine produced two different reports:\n  %q\n  %q",
			upper.stdout.String(), lower.stdout.String())
	}
}

// TestAnErrorMessageDoesNotReplayWhatTheUserTypedUnescaped closes a way into
// somebody's terminal.
//
// The suggestion in the scheme message pasted the raw argument back with %s.
// The URL parser refuses ASCII control characters, which is what made this look
// safe - it does not refuse the ones above them, so a bidirectional override or
// a zero width character from a URL in a ticket came out unescaped into a
// console and into a log. This tool's output is evidence in an argument about
// somebody's network, so forging how it reads is a real harm.
func TestAnErrorMessageDoesNotReplayWhatTheUserTypedUnescaped(t *testing.T) {
	// Written as numbers rather than pasted in as characters. A test carrying an
	// invisible character in its own source is a test nobody can read, and this
	// file would then be doing the thing it exists to forbid.
	invisible := []rune{
		0x202e, // right-to-left override
		0x200b, // zero width space
		0x009b, // the eight bit form of the control sequence introducer
	}
	for _, char := range invisible {
		raw := "ftp://ex" + string(char) + "mple.com"
		h := invoke(raw)
		if h.code != exitcode.Usage {
			t.Errorf("%U ended %d, want %d", char, h.code, exitcode.Usage)
		}
		if strings.ContainsRune(h.stderr.String(), char) {
			t.Errorf("%U reached the log unescaped: %q", char, h.stderr.String())
		}
	}
}

// TestWritingAReportToAPathSaysWhereItWent is the ban on silence over the only
// irreversible thing this program does. A successful --out used to produce
// nothing on either channel, so a typo in the path and a report written were
// indistinguishable until somebody went looking for the file.
func TestWritingAReportToAPathSaysWhereItWent(t *testing.T) {
	h := invoke("https://example.com", "--out", "report.json", "--json")
	if h.stdout.Len() != 0 {
		t.Errorf("a report going to a file also reached standard output: %q", h.stdout.String())
	}
	if !strings.Contains(h.stderr.String(), "report.json") {
		t.Errorf("nothing said where the report went: %q", h.stderr.String())
	}
}

// TestANumberWrittenWithACommaIsAnsweredWithTheDotItNeeds covers the wrong value
// this flag is most likely to be given.
//
// A Polish, German or French keyboard makes "1,5" the reflex, and the flag
// package answered it with `invalid value "1,5" for flag -timeout: parse error`
// - a switch named with one dash where every other line of this program uses
// two, and "parse error" as the explanation. The person who typed the comma is
// told nothing about the comma.
func TestANumberWrittenWithACommaIsAnsweredWithTheDotItNeeds(t *testing.T) {
	for _, args := range [][]string{
		{"https://example.com", "--timeout", "1,5"},
		{"https://example.com", "--timeout=1,5"},
		{"https://example.com", "--probe-timeout", "2,5"},
	} {
		h := invoke(args...)
		said := h.stderr.String()
		if h.code != exitcode.Usage {
			t.Errorf("%v ended %d, want %d", args, h.code, exitcode.Usage)
		}
		if !strings.Contains(said, "decimal point") {
			t.Errorf("%v: the message does not mention the decimal point: %q", args, said)
		}
		// The switch is named the way this program names switches everywhere
		// else, and the message says what to write instead.
		if !strings.Contains(said, "--timeout 1.5") && !strings.Contains(said, "--probe-timeout 2.5") {
			t.Errorf("%v: the message does not show the value to write: %q", args, said)
		}
	}
	// A value that is not a number for any other reason still says so, and a
	// value that IS a number still works.
	if h := invoke("https://example.com", "--timeout", "abc"); !strings.Contains(h.stderr.String(), "not a number") {
		t.Errorf("a non-numeric value was not named as such: %q", h.stderr.String())
	}
	if h := invoke("https://example.com", "--timeout", "1.5"); h.code != exitcode.Inconclusive {
		t.Errorf("a perfectly good number was refused: %d %q", h.code, h.stderr.String())
	}
}

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

// TestTheTargetIsMaskedRatherThanReducedToItsOrigin is the expiry of the rule
// that stood in for masking while masking was not wired to anything.
//
// The report used to show scheme, host and port and drop everything else, saying
// so in a note. That was strictly narrower than masking, deliberately, so that
// no code existed which could print a password. Now the whole URL is shown with
// the dangerous parts taken out by POSITION: user info replaced, every query
// value replaced with its name kept, the path reduced to one marker.
//
// The parameter NAME surviving is half the diagnosis - "your URL carries a
// token" can be said without saying the token - and it is the half a reduction
// to the origin threw away.
func TestTheTargetIsMaskedRatherThanReducedToItsOrigin(t *testing.T) {
	out := invoke("https://example.com/session/abc123?token=xyz789", "--json").stdout.String()

	for _, secret := range []string{"abc123", "xyz789", "session"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q reached the report", secret)
		}
	}
	if !strings.Contains(out, "token") {
		t.Error("the name of the query parameter was dropped, and that name is half the diagnosis")
	}
	if !strings.Contains(out, "example.com") {
		t.Error("the host was removed without --redact having been asked for")
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("nothing in the target was marked as removed:\n%s", out)
	}
}

// TestARedactedRunMasksTheTargetHostAndSaysSo is the flag doing something at
// last. It used to be accepted and announced as having changed nothing, which is
// the only honest thing to say about an option that does not work - and that
// note has to disappear the day it starts working, or notes become decoration.
func TestARedactedRunMasksTheTargetHostAndSaysSo(t *testing.T) {
	out := invoke("https://internal.corp.example/", "--redact", "--json").stdout.String()

	if strings.Contains(out, "internal.corp.example") {
		t.Error("--redact was asked for and the host is still in the report")
	}
	if !strings.Contains(out, `"redacted": true`) {
		t.Error("names were masked and the report does not say so")
	}
	if strings.Contains(out, "no_effect") {
		t.Error("--redact now changes the report and still claims it changed nothing")
	}

	// The other side: without the flag the host stays, because the floor removes
	// credentials and nothing else.
	plain := invoke("https://internal.corp.example/", "--json").stdout.String()
	if !strings.Contains(plain, "internal.corp.example") {
		t.Error("the host was masked without --redact, which is not what the floor does")
	}
	if !strings.Contains(plain, `"redacted": false`) {
		t.Error("no stronger mode was asked for and the report claims names were masked")
	}
}

// TestNoEnvironmentCredentialReachesEitherSurface is the end this whole ordering
// was built for, checked on the real command line rather than on a fixture.
//
// The masking function was written BEFORE the layer that produces values to
// mask, deliberately, so that no version of this program ever existed with code
// that printed a password. This is the test that says the arrangement worked:
// the value goes in raw at the layer, and neither surface shows it.
func TestNoEnvironmentCredentialReachesEitherSurface(t *testing.T) {
	const secret = "s3kret"
	env := map[string]string{"HTTPS_PROXY": "http://someone:" + secret + "@proxy.example:8080"}

	for _, format := range []string{"terminal", "json"} {
		h := invokeIn(env, report.PrivilegeUnknown, "https://example.com", "--format", format)
		everything := h.stdout.String() + h.stderr.String()

		if strings.Contains(everything, secret) {
			t.Errorf("%s: the password from the environment reached the output", format)
		}
		if !strings.Contains(everything, "proxy.example") {
			t.Errorf("%s: the proxy host was removed as well, and the host is the diagnosis", format)
		}
	}
}

// TestTheDisabledCertificateCheckSurvivesTheWholeWay is the other direction, and
// it is the one that has already been got wrong once.
//
// A masking rule asking whether the NAME contained a credential word answered yes
// for NODE_TLS_REJECT_UNAUTHORIZED, because "unauthorized" contains "auth". What
// it removed was the value 0 - that is, the entire finding: certificate checking
// switched off. A rule that deletes the diagnosis to protect a secret that was
// never there is worse than no rule.
func TestTheDisabledCertificateCheckSurvivesTheWholeWay(t *testing.T) {
	h := invokeIn(map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
		report.PrivilegeUnknown, "https://example.com", "--json")

	if !strings.Contains(h.stdout.String(), `"value": "0"`) {
		t.Error("the value of NODE_TLS_REJECT_UNAUTHORIZED did not survive to the report")
	}
}

// TestTheTwoSpellingsAreShownSeparately keeps the report from folding away a
// difference that decides behaviour.
//
// curl honours the http proxy variable in lower case only. On Linux the two
// spellings are separate variables, so one being set and the other not is the
// whole answer to "why does curl ignore my proxy" - and a report that merged
// them into one row would be true and useless at once.
func TestTheTwoSpellingsAreShownSeparately(t *testing.T) {
	out := invokeIn(map[string]string{"HTTP_PROXY": "http://upper.example:8080"},
		report.PrivilegeUnknown, "https://example.com").stdout.String()

	if !strings.Contains(out, "HTTP_PROXY is set") {
		t.Error("the upper case spelling was set and the report does not say so")
	}
	if !strings.Contains(out, "http_proxy is not set") {
		t.Error("the lower case spelling was not set and the report does not say so - the two were merged")
	}
}

// TestAVariableSetToNothingReadsDifferentlyFromAnAbsentOne covers the state that
// the value column cannot show, because both print nothing.
//
// An empty HTTPS_PROXY switches proxying off in some tools while an absent one
// leaves them to look elsewhere. If the report showed those identically, the
// person reading it would be told the opposite of what their machine does.
func TestAVariableSetToNothingReadsDifferentlyFromAnAbsentOne(t *testing.T) {
	out := invokeIn(map[string]string{"NO_PROXY": ""},
		report.PrivilegeUnknown, "https://example.com").stdout.String()

	if !strings.Contains(out, "NO_PROXY is set to nothing") {
		t.Error("a variable set to nothing is not distinguishable in the report")
	}
	if !strings.Contains(out, "no_proxy is not set") {
		t.Error("an absent variable stopped being reported as absent")
	}
}

// TestTheVerdictCountsTheLayersItCouldNotAssess replaces a claim with a count.
//
// The report used to carry a standing note saying no layer was implemented. That
// sentence stopped being true the day L0 started reading this machine, and a note
// kept past the arrival of the thing it announced teaches people to skip notes.
// What it said is now worked out from the rows themselves.
func TestTheVerdictCountsTheLayersItCouldNotAssess(t *testing.T) {
	h := invoke("https://example.com")
	out := h.stdout.String()

	if !strings.Contains(out, "7 of 8 diagnostic layers could not be assessed.") {
		t.Errorf("the verdict does not count the unassessed layers:\n%.400s", out)
	}
	if strings.Contains(out, "Nothing could be assessed yet.") {
		t.Error("the verdict still says nothing was assessed, and L0 assesses this machine")
	}
	if strings.Contains(out, "no diagnostic layer is implemented yet") {
		t.Error("the standing note outlived the thing it announced")
	}
	if h.code != exitcode.Inconclusive {
		t.Errorf("the run ended with %d, want %d - one layer passing does not make a run conclusive", h.code, exitcode.Inconclusive)
	}
}
