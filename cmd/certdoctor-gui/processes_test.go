package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
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

// What the childCommandLine process does, chosen by the address it is handed -
// the last argument, after "--", the way the window hands it.
const (
	answerReport = "report"
	answerFlood  = "flood"
	answerWait   = "wait"
)

// actAsCommandLine is the test binary standing in for certdoctor beside the
// window: it writes what it was asked on standard output, a sentence on
// standard error and ends with DIAGNOSIS - or writes more than the window
// keeps, or waits until it is stopped.
func actAsCommandLine(args []string) int {
	switch args[len(args)-1] {
	case answerFlood:
		chunk := strings.Repeat("x", 1<<20)
		for written := 0; written <= flow.MaxDocument; written += len(chunk) {
			fmt.Fprint(os.Stdout, chunk)
		}
		return 4
	case answerWait:
		time.Sleep(time.Minute)
		return 4
	}
	fmt.Fprint(os.Stdout, strings.Join(args, " "))
	fmt.Fprint(os.Stderr, "a note\n")
	return 4
}

// portAnswer is what a childPort process found, written for the test to read.
type portAnswer struct {
	Program, StartFailed, Out, Printed, Stopped string
	Missing, OutTooLong                         bool
	OutLength, Code                             int
	TookMS                                      int64
}

// actAsWindow is the test binary standing in for the window: it runs the
// command line beside itself through the real port, the way the window does,
// and writes what came of it. A run asked to wait is cancelled after a moment.
// The command line it starts is the test binary again, standing in for
// certdoctor.
func actAsWindow(args []string) int {
	if err := os.Setenv(childVariable, childCommandLine); err != nil {
		return 1
	}
	ctx := context.Background()
	if args[len(args)-1] == answerWait {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		time.AfterFunc(200*time.Millisecond, cancel)
	}
	began := time.Now()
	p := (commandLinePort{}).Run(ctx, args)
	a := portAnswer{Program: p.Program, Missing: p.Missing, Printed: string(p.Printed), OutLength: len(p.Out),
		OutTooLong: p.OutTooLong, Code: p.Code, TookMS: time.Since(began).Milliseconds()}
	if len(p.Out) < 200 {
		a.Out = string(p.Out)
	}
	if p.StartFailed != nil {
		a.StartFailed = p.StartFailed.Error()
	}
	if p.Stopped != nil {
		a.Stopped = p.Stopped.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(a); err != nil {
		return 1
	}
	return 0
}

// TestTheCommandLineBesideTheWindowIsRun starts the command line the way the
// window does, for real. A copy of the test binary in a temporary directory
// stands for the window, so the program it looks for is looked for there:
// nothing there is the program that is missing, and a second copy under the
// command line's name is run with the arguments, kept to the window's limits,
// given its exit code, and stopped when its run is cancelled.
func TestTheCommandLineBesideTheWindowIsRun(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	window := filepath.Join(dir, "window"+filepath.Ext(exe))
	copyFile(t, exe, window)
	ask := func(args ...string) portAnswer {
		t.Helper()
		cmd := exec.Command(window, args...)
		cmd.Env = append(os.Environ(), childVariable+"="+childPort)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("the window standing in for the real one failed: %v", err)
		}
		var a portAnswer
		if err := json.Unmarshal(out, &a); err != nil {
			t.Fatalf("the window standing in for the real one wrote %q: %v", out, err)
		}
		return a
	}

	program := filepath.Join(dir, commandLineFile)
	if a := ask("--json", "--", answerReport); !a.Missing || a.Program != program || a.StartFailed != "" {
		t.Fatalf("nothing beside the window was answered as %+v, want the program %s missing", a, program)
	}

	copyFile(t, exe, program)
	if a := ask("--json", "--timeout=5", "--", answerReport); a.Out != "--json --timeout=5 -- report" ||
		a.Printed != "a note\n" || a.Code != 4 || a.OutTooLong || a.Stopped != "" || a.Program != program {
		t.Errorf("the run left %+v", a)
	}
	if a := ask("--json", "--", answerFlood); !a.OutTooLong || a.OutLength != flow.MaxDocument || a.Code != 4 {
		t.Errorf("a run writing more than the window keeps left %+v", a)
	}
	a := ask("--json", "--", answerWait)
	if a.Stopped != context.Canceled.Error() || time.Duration(a.TookMS)*time.Millisecond > stopWait+10*time.Second {
		t.Errorf("a cancelled run left %+v", a)
	}
}

// copyFile copies from to to, for a program that has to stand beside another.
func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o755); err != nil {
		t.Fatal(err)
	}
}
