//go:build windows

package render

import (
	"os"
	"path/filepath"
	"testing"
)

// TestADestinationThatCannotBeAskedGetsNoColour covers the question that was
// missing until probe S6 asked it.
//
// Being a character device used to be enough to switch colour on. A console
// measured on the owner's machine on 2026-08-03 reported mode 0x0003 - no
// virtual terminal processing - and prints an escape sequence verbatim, so the
// report arrives looking corrupted rather than coloured.
//
// The true branch needs a console with the flag set and cannot be reached from a
// test binary whose output is a pipe. What IS reachable is the direction that
// matters: anything that is not a console, or that refuses the question, must
// answer no. Every default in this package leans that way, and this pins it.
func TestADestinationThatCannotBeAskedGetsNoColour(t *testing.T) {
	if consoleUnderstandsSequences(nil) {
		t.Error("a missing destination was treated as a console that renders colour")
	}

	file, err := os.Create(filepath.Join(t.TempDir(), "report.txt"))
	if err != nil {
		t.Fatalf("the fixture could not be created: %v", err)
	}
	defer file.Close()

	if consoleUnderstandsSequences(file) {
		t.Error("a regular file was treated as a console that renders colour")
	}
	// The whole detection agrees with it, so nothing can switch colour on behind
	// this answer's back.
	if got := DetectCapability(file, nil, false); got.Color != ColorOff {
		t.Errorf("a file was given colour: %+v", got)
	}
}
