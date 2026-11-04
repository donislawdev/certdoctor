package main

import (
	"os"
	"slices"
	"testing"
)

// childVariable asks the test binary to be something other than the tests: the
// window itself (childWindow - see TestAWindowWithNoDisplayIsRefusedRatherThanLeftWaiting)
// or a second process that reports what it was started with (childAgain - see
// TestASecondStartHandsOverTheFlagTheDriverAndTheCode).
const childVariable = "CERTDOCTOR_GUI_TEST_CHILD"

const (
	childWindow = "1"
	childAgain  = "again"
)

// The exit codes of a childAgain process: started the way startAgain has to
// start it, or not. Neither is a code the window itself gives, so the test can
// tell an answer passed through from one made up on the way.
const (
	childStartedRight = 7
	childStartedWrong = 8
)

// childAgainArgs are what the test starts the second process with.
var childAgainArgs = []string{"an-argument-of-the-first-process", softwareFlag}

// TestMain is the child when the variable asks for one. Run from here rather
// than from a test because the toolkit's loop belongs to the main goroutine,
// and TestMain is the only code of a test binary that runs there.
func TestMain(m *testing.M) {
	switch os.Getenv(childVariable) {
	case childWindow:
		os.Exit(run(nil, os.Stderr))
	case childAgain:
		if os.Getenv(softwareDriver) == softwareLLVMPipe && slices.Equal(os.Args[1:], childAgainArgs) {
			os.Exit(childStartedRight)
		}
		os.Exit(childStartedWrong)
	}
	os.Exit(m.Run())
}
