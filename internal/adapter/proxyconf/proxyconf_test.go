package proxyconf

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
)

// recorder is the command port, remembering what it was asked to run.
//
// WHAT IT ANSWERS WITH IS A ONE KEY DICTIONARY AND NOT THE MEASURED MAC OUTPUT,
// which lives beside the parser in internal/core/proxy and is tested there.
// Copying a fixture into a second package gives two things that can drift; this
// test is about whether stdout reaches the parser at all, and one key proves
// that as well as fourteen would.
type recorder struct {
	calls     [][]string
	stdout    string
	exitCode  int
	truncated bool
	err       error
}

func (r *recorder) run(_ context.Context, executable string, args ...string) (string, int, bool, error) {
	r.calls = append(r.calls, append([]string{executable}, args...))
	return r.stdout, r.exitCode, r.truncated, r.err
}

func TestTheMacQuestionGoesToAnAbsolutePathWithOurOwnArgument(t *testing.T) {
	spy := &recorder{stdout: "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n}"}

	lens := askSCUtil(context.Background(), spy.run)

	if len(spy.calls) != 1 {
		t.Fatalf("the command was run %d times, want once: %v", len(spy.calls), spy.calls)
	}
	// ADR49's first two narrowing rules, checked rather than promised: an
	// absolute path so that nobody else's PATH picks the program, and an
	// argument that is a constant of this program.
	if got := spy.calls[0]; got[0] != proxy.SCUtilPath || len(got) != 2 || got[1] != proxy.SCUtilArg {
		t.Errorf("the command was run as %v, want %q %q", got, proxy.SCUtilPath, proxy.SCUtilArg)
	}
	if !lens.Read {
		t.Fatalf("the command answered and the lens says the stack could not be read: %+v", lens)
	}
	if lens.Stack != proxy.StackMacSystem || lens.Source != proxy.SourceSCUtil {
		t.Errorf("the lens lost track of where it came from: %+v", lens)
	}
	if !lens.BypassSet || lens.Bypass != "*.local" {
		t.Errorf("bypass is %q (set %v), so what the command printed did not reach the parser", lens.Bypass, lens.BypassSet)
	}
}

// TestAMacStackThatCouldNotBeAskedIsNeverAMacWithoutAProxy walks every way this
// can fail. All four have to end as a lens that says it was not read, because
// the alternative is our own failure arriving in a report as a fact about
// somebody's machine.
func TestAMacStackThatCouldNotBeAskedIsNeverAMacWithoutAProxy(t *testing.T) {
	cases := []struct {
		name    string
		port    Command
		mustSay string
	}{
		{
			name:    "no way to run anything was supplied",
			port:    nil,
			mustSay: proxy.SCUtilPath,
		},
		{
			name:    "the command could not be started",
			port:    (&recorder{err: errors.New("no such file")}).run,
			mustSay: "no such file",
		},
		{
			name:    "the command ran and refused",
			port:    (&recorder{exitCode: 3}).run,
			mustSay: "3",
		},
		{
			name:    "the output was longer than this program keeps",
			port:    (&recorder{stdout: "<dictionary> {", truncated: true}).run,
			mustSay: "whole",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lens := askSCUtil(context.Background(), c.port)

			if lens.Read {
				t.Fatalf("this stack was not read and the lens says it was: %+v", lens)
			}
			if lens.Servers != nil {
				t.Errorf("Servers is %+v, and an empty list would say this machine names no proxy", lens.Servers)
			}
			if lens.Stack != proxy.StackMacSystem || lens.Source != proxy.SourceSCUtil {
				t.Errorf("a refused reading lost track of which stack it was about: %+v", lens)
			}
			if !strings.Contains(lens.Detail, c.mustSay) {
				t.Errorf("detail is %q and does not mention %q, so a reader cannot tell what went wrong",
					lens.Detail, c.mustSay)
			}
		})
	}
}

// TestTruncatedOutputIsRefusedRatherThanParsed is the one failure that would
// otherwise look like success: a dictionary cut in half parses cleanly into an
// answer with keys missing.
func TestTruncatedOutputIsRefusedRatherThanParsed(t *testing.T) {
	whole := "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n}"

	full := askSCUtil(context.Background(), (&recorder{stdout: whole}).run)
	if !full.Read || !full.BypassSet {
		t.Fatalf("the whole output did not produce a read lens: %+v", full)
	}

	cut := askSCUtil(context.Background(), (&recorder{stdout: whole, truncated: true}).run)
	if cut.Read {
		t.Error("output the program itself cut short was parsed as though it were the whole answer")
	}
}

// TestAFalseFromTheInternetSettingsCallIsOnlyAnAnswerForOneErrorCode is the one
// judgement on the Windows path, and it lives in a file every platform compiles
// so that it can be checked on this machine and aimed at by the register.
func TestAFalseFromTheInternetSettingsCallIsOnlyAnAnswerForOneErrorCode(t *testing.T) {
	// ERROR_FILE_NOT_FOUND, written out here rather than taken from the constant
	// under test - a test whose oracle is the value it checks agrees with it
	// whatever it says, which is OBS48 and which the register caught once
	// already in this slice.
	const wireErrorFileNotFound = 2

	if !ieSettingsAbsent(wireErrorFileNotFound) {
		t.Error("the code meaning \"no Internet Explorer proxy settings can be found\" is being read as a reading that failed")
	}
	for _, other := range []uintptr{0, 1, 5, 8, 12002} {
		if ieSettingsAbsent(other) {
			t.Errorf("error code %d is being read as \"this user has no proxy settings\", and only one code means that", other)
		}
	}
}
