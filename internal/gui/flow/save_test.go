package flow

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

var html, md = request.SaveFormats[0], request.SaveFormats[1]

// began is a run that began at 14:30:05 in Warsaw in winter - 13:30:05 UTC.
var began = time.Date(2026, 11, 10, 14, 30, 5, 0, time.FixedZone("CET", 3600))

// TestASuggestedNameIsOneEverySystemTakes - the host stays readable where it
// can, and anything a file name cannot hold, or a person would not type,
// becomes a dash.
func TestASuggestedNameIsOneEverySystemTakes(t *testing.T) {
	long := strings.Repeat("a", 300) + ".example"
	for _, c := range []struct {
		target string
		f      request.Format
		want   string
	}{
		{"https://example.com/a/path?token=x", html, "certdoctor-example.com-20261110T133005Z.html"},
		{"https://example.com:8443", md, "certdoctor-example.com-20261110T133005Z.md"},
		{"https://[2001:db8::1]:8443/", html, "certdoctor-2001-db8-1-20261110T133005Z.html"},
		{"https://b\xc3\xbccher.example/", html, "certdoctor-b\xc3\xbccher.example-20261110T133005Z.html"},
		{"http://a_b..example/", html, "certdoctor-a-b..example-20261110T133005Z.html"},
		{"https://-x-.example./", html, "certdoctor-x-.example-20261110T133005Z.html"},
		{"", html, "certdoctor-20261110T133005Z.html"},
		{"https://exa mple.com", html, "certdoctor-20261110T133005Z.html"},
		{"https://" + long, html, "certdoctor-" + long[:maxHost] + "-20261110T133005Z.html"},
	} {
		got := SuggestedName(c.target, c.f, began)
		if got != c.want {
			t.Errorf("%q is suggested as %q, want %q", c.target, got, c.want)
		}
		if strings.ContainsFunc(got, forbidden) {
			t.Errorf("the name suggested for %q holds a character Windows keeps for itself: %q", c.target, got)
		}
	}
}

// TestAFolderAndANameBecomeAPathOrASentence - what the dialog refuses before
// anything runs, and what it lets through to the command line.
func TestAFolderAndANameBecomeAPathOrASentence(t *testing.T) {
	folder := t.TempDir()
	device := func(name string) string { return fmt.Sprintf(words.T(words.SaveDevice), name) }
	for _, c := range []struct {
		folder, name string
		want, said   string
	}{
		{folder, "report", filepath.Join(folder, "report.html"), ""},
		{"  " + folder + "  ", "  report  ", filepath.Join(folder, "report.html"), ""},
		{folder, "report.HTML", filepath.Join(folder, "report.HTML"), ""},
		{folder, "report.md", filepath.Join(folder, "report.md.html"), ""},
		{folder, "COM10", filepath.Join(folder, "COM10.html"), ""},
		{folder, "console", filepath.Join(folder, "console.html"), ""},
		{folder, "nul-report", filepath.Join(folder, "nul-report.html"), ""},
		{"", "report", "", words.T(words.SaveNoFolder)},
		{"reports", "report", "", words.T(words.SaveNotWhole)},
		{folder, " ", "", words.T(words.SaveNoName)},
		{folder, "a/b", "", words.T(words.SaveForbidden)},
		{folder, `a\b`, "", words.T(words.SaveForbidden)},
		{folder, "a:b", "", words.T(words.SaveForbidden)},
		{folder, "a?b", "", words.T(words.SaveForbidden)},
		{folder, "a\x01b", "", words.T(words.SaveForbidden)},
		{folder, "NUL", "", device("NUL.html")},
		{folder, "con.html", "", device("con.html")},
		{folder, "Com1.report", "", device("Com1.report.html")},
		{folder, "LPT9", "", device("LPT9.html")},
		{folder, "COM\xc2\xb9", "", device("COM\xc2\xb9.html")},
		{folder, "aux .txt", "", device("aux .txt.html")},
	} {
		if got, said := target(c.folder, c.name, html); got != c.want || said != c.said {
			t.Errorf("%q in %q went to %q, saying %q - want %q, saying %q", c.name, c.folder, got, said, c.want, c.said)
		}
	}
}

// TestASaveGoesFromTheFormToTheFile walks a copy through every step: a file in
// the way, the answer to replace it, the run, and what came of it - and the
// presses and answers that come when they mean nothing.
func TestASaveGoesFromTheFormToTheFile(t *testing.T) {
	folder := t.TempDir()
	there := map[string]bool{filepath.Join(folder, "taken.html"): true}
	present := func(p string) bool { return there[p] }

	s := NewSave(html)
	if s.Press("", "report", present) != nil || s.Step() != SaveUnusable || s.Said() != words.T(words.SaveNoFolder) {
		t.Fatalf("no folder left the copy at %d saying %q", s.Step(), s.Said())
	}
	s.Changed()
	if s.Step() != SaveAsking || s.Said() != "" {
		t.Fatalf("typing again left the copy at %d saying %q", s.Step(), s.Said())
	}

	if s.Press(folder, "taken", present) != nil || s.Step() != SaveTaken || s.Path() != filepath.Join(folder, "taken.html") {
		t.Fatalf("a file in the way left the copy at %d for %q", s.Step(), s.Path())
	}
	s.Changed()
	if s.Step() != SaveAsking || s.Press(folder, "taken", present) != nil || s.Step() != SaveTaken {
		t.Fatal("a name typed again after a file was in the way was taken as the answer to replace it")
	}
	there[filepath.Join(folder, "other.html")] = true
	if s.Press(folder, "other", present) != nil || s.Step() != SaveTaken || s.Path() != filepath.Join(folder, "other.html") {
		t.Fatalf("Replace pressed for another file in the way than the one shown went on to %d for %q", s.Step(), s.Path())
	}
	args := s.Press(folder, "other", present)
	if want := request.SaveArgs(html, filepath.Join(folder, "other.html")); !slices.Equal(args, want) || s.Step() != SaveWriting {
		t.Fatalf("Replace ran %q at %d, want %q", args, s.Step(), want)
	}
	s.Changed()
	if s.Press(folder, "other", present) != nil || s.Step() != SaveWriting {
		t.Fatal("a press or a change while the copy was being written did something")
	}
	s.Finish(Process{Code: 0})
	if s.Step() != SaveDone || s.Path() != filepath.Join(folder, "other.html") {
		t.Fatalf("the copy written is at %d for %q", s.Step(), s.Path())
	}
	s.Finish(Process{Code: 6})
	s.Changed()
	if s.Press(folder, "new", present) != nil || s.Step() != SaveDone {
		t.Fatal("a copy that is written went on to something else")
	}

	s = NewSave(md)
	s.Finish(Process{Code: 0})
	if s.Step() != SaveAsking {
		t.Fatal("an answer before any press was taken")
	}
	s.Press(folder, "report", present)
	s.Finish(Process{Code: int(exitcode.IO), Printed: []byte("certdoctor: the disk is full\n")})
	if s.Step() != SaveFailed || s.Said() != "The disk is full." {
		t.Fatalf("a failed copy is at %d saying %q", s.Step(), s.Said())
	}
	s.Changed()
	if args := s.Press(folder, "report", present); args == nil || s.Step() != SaveWriting {
		t.Fatalf("a copy that failed cannot be tried again: %q at %d", args, s.Step())
	}
}

// windowsSays is the system's words the way Windows ends them, with a full
// stop the sentence around them supplies itself.
var windowsSays = "permission denied."

// TestAFailedCopySaysWhy - the command line's own sentence when it gave one,
// and what the window knows when it did not. Exit code 0 is a copy in place,
// even when the window's deadline passed a moment after.
func TestAFailedCopySaysWhy(t *testing.T) {
	for _, c := range []struct {
		name string
		p    Process
		want string
	}{
		{"written", Process{Code: 0}, ""},
		{"written as the deadline passed", Process{Code: 0, Stopped: context.DeadlineExceeded}, ""},
		{"missing", Process{Missing: true, Program: "/opt/certdoctor"}, fmt.Sprintf(words.T(words.MissingWhat), "/opt/certdoctor")},
		{"not started", Process{Program: "/opt/certdoctor", StartFailed: errors.New(windowsSays)},
			fmt.Sprintf(words.T(words.NotStartedWhat), "/opt/certdoctor", "permission denied")},
		{"stopped", Process{Code: -1, Stopped: context.DeadlineExceeded}, fmt.Sprintf(words.T(words.SaveStopped), "30")},
		{"refused", Process{Code: 6, Printed: []byte("certdoctor: moving the finished report to C:\\r.html: Access is denied.\r\n")},
			"Moving the finished report to C:\\r.html: Access is denied."},
		{"refused after blank lines", Process{Code: 3, Printed: []byte("\n  \ncertdoctor:   x is a directory\nmore\n")}, "x is a directory."},
		{"a path first", Process{Code: 6, Printed: []byte("certdoctor: c:\\r is a directory")}, "c:\\r is a directory."},
		{"a capital first", Process{Code: 6, Printed: []byte("certdoctor: Access is denied")}, "Access is denied."},
		{"panicked", Process{Code: 2, Printed: []byte("panic: runtime error\n\ngoroutine 1")}, "Panic: runtime error."},
		{"broken words", Process{Code: 1, Printed: []byte("certdoctor: bad \xff byte")}, "Bad " + string(utf8.RuneError) + " byte."},
		{"silent", Process{Code: 1}, fmt.Sprintf(words.T(words.SaveEndedCode), 1, exitcode.Code(1).Name())},
		{"ended by the system", Process{Code: -1}, words.T(words.SaveEnded)},
	} {
		if got := notWritten(c.p); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSaveWaitsForAFolderAndAName - the one primary action of the dialog
// cannot be pressed with nothing to save under.
func TestSaveWaitsForAFolderAndAName(t *testing.T) {
	for _, c := range []struct {
		folder, name string
		want         bool
	}{{"/r", "x", true}, {"", "x", false}, {"/r", "  ", false}, {" ", "x", false}} {
		if got := SaveReady(c.folder, c.name); got != c.want {
			t.Errorf("folder %q and name %q: ready %v", c.folder, c.name, got)
		}
	}
}
