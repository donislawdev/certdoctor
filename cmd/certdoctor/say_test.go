package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// refusingOutput is a standard output that takes nothing, the way a full disk
// or a closed pipe does.
type refusingOutput struct{}

func (refusingOutput) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// aboutTheProgram are the command lines that answer with a text about this
// program rather than about a machine.
var aboutTheProgram = [][]string{
	{"--help"},
	{"--version"},
	{"--license"},
	{"tool"},
	{"tool", "jwt", "--help"},
}

// TestATextAboutTheProgramThatCannotBeWrittenSaysSo holds OBS255: help,
// version, licence and the tools' help went to standard output with the
// write's error dropped, so `certdoctor --license > file` on a full disk ended
// 0 with half a file. Each now ends IO and says why on standard error, and
// standard error is the only place it says anything.
func TestATextAboutTheProgramThatCannotBeWrittenSaysSo(t *testing.T) {
	for _, args := range aboutTheProgram {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			// The reverse canary first: with an output that works, the same
			// command line ends OK and writes its text, so a failure below is
			// about the write and nothing else.
			if h := invoke(args...); h.code != exitcode.OK || h.stdout.Len() == 0 {
				t.Fatalf("with a working output: code %d and %d bytes, want OK and the text", h.code, h.stdout.Len())
			}
			h := invokeAdjusted(nil, report.PrivilegeUnknown, func(e *environment) { e.stdout = refusingOutput{} }, args...)
			if h.code != exitcode.IO {
				t.Errorf("code %d with an output that takes nothing, want IO (%d)", h.code, exitcode.IO)
			}
			if !strings.Contains(h.stderr.String(), "standard output could not be written: no space left on device") {
				t.Errorf("standard error does not say what failed: %q", h.stderr.String())
			}
		})
	}
}
