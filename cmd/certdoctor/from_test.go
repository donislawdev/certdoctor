package main

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/switches"
)

// TestASavedReportIsWrittenAgainAsTheRunWouldHaveWrittenIt is ADR121 (c) seen
// from the command line: a report saved with --json and written again with
// --from is, in every format, the bytes the run itself writes in that format.
//
// THE CODE IS THE OTHER HALF. The run ends with what it found, and writing the
// saved report again ends with OK - the owner's decision of 2026-11-09 - so a
// conversion in a script does not fail once the file is written. The verdict's
// code is still in the report.
func TestASavedReportIsWrittenAgainAsTheRunWouldHaveWrittenIt(t *testing.T) {
	for _, redacted := range []bool{false, true} {
		run := []string{"https://user:secret@example.com/path"}
		if redacted {
			run = append(run, "--redact")
		}
		for _, format := range switches.Formats {
			direct := invoke(append(append([]string{}, run...), "--format", format)...)
			saved := invoke(append(append([]string{}, run...), "--json")...).stdout.Bytes()
			again := invokeAdjusted(nil, report.PrivilegeUnknown, func(e *environment) {
				e.stdin = func() (io.Reader, error) { return bytes.NewReader(saved), nil }
			}, "--from", "-", "--format", format)

			if again.code != exitcode.OK {
				t.Fatalf("redact=%v %s: --from ended with %s: %s", redacted, format, again.code.Name(), again.stderr.String())
			}
			if direct.code == exitcode.OK {
				t.Fatalf("redact=%v %s: the run ended with OK, so the code of --from is not told apart from it", redacted, format)
			}
			if !bytes.Equal(again.stdout.Bytes(), direct.stdout.Bytes()) {
				t.Errorf("redact=%v %s: the report written again differs from the run's at byte %d", redacted,
					format, firstApart(again.stdout.Bytes(), direct.stdout.Bytes()))
			}
		}
	}
}

func firstApart(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// TestASavedReportIsWrittenWhereOutSays is --out beside --from: the file gets
// the page, standard error says where it went, standard output stays empty.
func TestASavedReportIsWrittenWhereOutSays(t *testing.T) {
	h := invoke("--from", savedPath, "--format", "html", "--out", "report.html")
	if h.code != exitcode.OK {
		t.Fatalf("ended with %s: %s", h.code.Name(), h.stderr.String())
	}
	page, written := h.written["report.html"]
	if !written || !bytes.HasPrefix(page, []byte("<!DOCTYPE html>")) {
		t.Fatalf("no page was written to report.html: %q", h.written)
	}
	if h.stdout.Len() != 0 || !strings.Contains(h.stderr.String(), "report written to report.html") {
		t.Errorf("standard output %q, standard error %q", h.stdout.String(), h.stderr.String())
	}
	direct := invoke("https://example.com", "--format", "html")
	if !bytes.Equal(page, direct.stdout.Bytes()) {
		t.Errorf("the page written from the saved report differs from the run's page")
	}
}

// TestTheWindowsSaveIsACommandLineThisProgramTakes is the command line Save
// report in the window hands this program, in the shape it hands it - every
// value after "=", the report on standard input (request.SaveArgs in
// internal/gui/request, whose test holds that side to this shape). The window
// reads the written file nowhere: exit code OK is its whole answer.
func TestTheWindowsSaveIsACommandLineThisProgramTakes(t *testing.T) {
	saved := invoke("https://example.com", "--json").stdout.Bytes()
	h := invokeAdjusted(nil, report.PrivilegeUnknown, func(e *environment) {
		e.stdin = func() (io.Reader, error) { return bytes.NewReader(saved), nil }
	}, "--from=-", "--format=md", "--out=-report.md")
	if h.code != exitcode.OK || h.stdout.Len() != 0 {
		t.Fatalf("ended with %s, writing %q to standard output: %s", h.code.Name(), h.stdout.String(), h.stderr.String())
	}
	if page := h.written["-report.md"]; !bytes.Equal(page, invoke("https://example.com", "--format", "md").stdout.Bytes()) {
		t.Errorf("the copy at -report.md is not the run's Markdown: %d bytes", len(page))
	}
}

// TestFromIsRefusedWithTheReasonAndWritesNothing is every way a command line
// with --from can fail, each ending in the code the table gives it, with a
// sentence that says what to do, and with nothing on standard output.
func TestFromIsRefusedWithTheReasonAndWritesNothing(t *testing.T) {
	failing := func(err error) func(*environment) {
		return func(e *environment) {
			e.readSaved = func(string) (io.ReadCloser, error) { return nil, err }
		}
	}
	piping := func(r io.Reader, err error) func(*environment) {
		return func(e *environment) {
			e.stdin = func() (io.Reader, error) { return r, err }
		}
	}
	for _, c := range []struct {
		name   string
		args   []string
		adjust func(*environment)
		code   exitcode.Code
		says   string
	}{
		{"no file", []string{"--from", ""}, nil, exitcode.Config, "given no file"},
		{"a URL as well", []string{"https://example.com", "--from", savedPath}, nil, exitcode.Config, "new run"},
		{"a URL after it", []string{"--from", savedPath, "https://example.com"}, nil, exitcode.Config, "new run"},
		{"redact", []string{"--from", savedPath, "--redact"}, nil, exitcode.Config, "run certdoctor against the URL again with --redact"},
		{"a limit", []string{"--from", savedPath, "--timeout", "5"}, nil, exitcode.Config, "--timeout shapes a run"},
		{"a PAC script", []string{"--from", savedPath, "--pac-url", "http://x/p.pac"}, nil, exitcode.Config, "--pac-url shapes a run"},
		{"two formats", []string{"--from", savedPath, "--json", "--format", "md"}, nil, exitcode.Config, "two different formats"},
		{"an unknown format", []string{"--from", savedPath, "--format", "pdf"}, nil, exitcode.Usage, "unknown format"},
		{"quiet and verbose", []string{"--from", savedPath, "--quiet", "--verbose"}, nil, exitcode.Config, "opposite"},
		{"an empty out", []string{"--from", savedPath, "--out", ""}, nil, exitcode.Config, "--out was given no path"},
		{"nothing there", []string{"--from", "gone.json"}, nil, exitcode.Config, "nothing is there"},
		{"too large", []string{"--from", "x.json"}, failing(&file.TooLarge{Path: "x.json", Limit: 1}), exitcode.Config, "larger than 32 MiB"},
		{"on another machine", []string{"--from", `\\server\share\r.json`}, failing(&file.RemotePath{Path: `\\server\share\r.json`}), exitcode.Config, "Copy the report to this machine"},
		{"led to another machine", []string{"--from", "r.json"}, failing(&file.RemotePath{Path: "r.json", Via: `\\server\r.json`}), exitcode.Config, `leads to \\server\r.json`},
		{"a folder", []string{"--from", "reports"}, failing(&file.NotRegular{Path: "reports", Mode: fs.ModeDir}), exitcode.Config, "which is a folder"},
		{"a pipe", []string{"--from", "fifo"}, failing(&file.NotRegular{Path: "fifo", Mode: fs.ModeNamedPipe}), exitcode.Config, "could wait for ever"},
		{"no permission", []string{"--from", "r.json"}, failing(fs.ErrPermission), exitcode.Config, "could not be read"},
		{"no file port", []string{"--from", "r.json"}, func(e *environment) { e.readSaved = nil }, exitcode.Runtime, "no way to read a file"},
		{"a terminal on standard input", []string{"--from", "-"}, nil, exitcode.Config, "Pipe one in, as in certdoctor --from - < report.json"},
		{"standard input that breaks", []string{"--from", "-"}, piping(nil, errors.New("closed")), exitcode.Config, "could not be read: closed"},
		{"standard input that breaks while read", []string{"--from", "-"}, piping(io.MultiReader(strings.NewReader("{"), failingReader{}), nil), exitcode.Config, "could not be read"},
		{"standard input too large", []string{"--from", "-"}, piping(io.LimitReader(endless{}, switches.MaxReport+1), nil), exitcode.Config, "more than 32 MiB"},
		{"no standard input port", []string{"--from", "-"}, func(e *environment) { e.stdin = nil }, exitcode.Runtime, "no standard input"},
		{"not a report", []string{"--from", "-"}, piping(strings.NewReader(`{"schema_version": "1.0"}`), nil), exitcode.Config, `standard input is not a report certdoctor can write again: it was written with report schema "1.0"`},
	} {
		h := invokeAdjusted(nil, report.PrivilegeUnknown, c.adjust, c.args...)
		if h.code != c.code {
			t.Errorf("%s: ended with %s, want %s: %s", c.name, h.code.Name(), c.code.Name(), h.stderr.String())
		}
		if !strings.Contains(h.stderr.String(), c.says) {
			t.Errorf("%s: standard error does not say %q: %s", c.name, c.says, h.stderr.String())
		}
		if h.stdout.Len() != 0 || len(h.written) != 0 {
			t.Errorf("%s: wrote %d bytes and %d file(s) while refusing", c.name, h.stdout.Len(), len(h.written))
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the pipe broke") }

type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

// TestEverySwitchIsAcceptedOrRefusedBesideFrom holds alongsideFrom to the
// whole declared surface: each switch either works beside --from or is
// refused by name, and a switch declared tomorrow is refused until somebody
// decides otherwise.
func TestEverySwitchIsAcceptedOrRefusedBesideFrom(t *testing.T) {
	values := map[string]string{"format": "md", "out": "r.md", "timeout": "5", "probe-timeout": "5"}
	for _, s := range switches.All {
		if s.Name == "from" {
			continue
		}
		args := []string{"--from", savedPath, "--" + s.Name}
		if s.TakesValue() {
			value, named := values[s.Name]
			if !named {
				value = "x"
			}
			args = append(args, value)
		}
		h := invoke(args...)
		if alongsideFrom[s.Name] {
			if h.code != exitcode.OK {
				t.Errorf("--%s beside --from ended with %s: %s", s.Name, h.code.Name(), h.stderr.String())
			}
			continue
		}
		if h.code != exitcode.Config || !strings.Contains(h.stderr.String(), "--"+s.Name) {
			t.Errorf("--%s beside --from ended with %s and did not name it: %s", s.Name, h.code.Name(), h.stderr.String())
		}
	}
	for name := range alongsideFrom {
		if _, declared := switches.Named(name); !declared {
			t.Errorf("%q is accepted beside --from and is not a declared switch", name)
		}
	}
}
