package main

import (
	"testing"
)

// TestASecondStartHandsOverTheFlagTheDriverAndTheCode starts this test binary
// for real, the way the window starts itself again: the child is TestMain in
// childAgain mode, which exits childStartedRight only when it was handed the
// arguments it was given plus the flag and the driver variable in its
// environment. Its code has to come back as the answer, because a second
// process that refused has said so already and its code is the window's.
func TestASecondStartHandsOverTheFlagTheDriverAndTheCode(t *testing.T) {
	t.Setenv(childVariable, childAgain)
	t.Setenv(softwareDriver, "")
	code, err := startAgain(childAgainArgs)
	if err != nil {
		t.Fatalf("starting this program again failed: %v", err)
	}
	if code != childStartedRight {
		t.Errorf("the second process answered %d - want %d, which it gives only when it was started with %q and %s=%s "+
			"(%d means it was started some other way)", code, childStartedRight, childAgainArgs, softwareDriver,
			softwareLLVMPipe, childStartedWrong)
	}
}
