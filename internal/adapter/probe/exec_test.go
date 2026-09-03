package probe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is not a test. It is the program the tests below run, which
// is the standard way to exercise os/exec without depending on a binary that
// happens to exist on the machine - and this package must work on Windows,
// Linux and macOS, where no single tool is guaranteed.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("CERTDOCTOR_HELPER") != "1" {
		return
	}
	switch os.Getenv("CERTDOCTOR_HELPER_MODE") {
	case "loud":
		os.Stdout.WriteString("on stdout\n")
		os.Stderr.WriteString("on stderr\n")
		os.Exit(0)
	case "refuse":
		os.Stderr.WriteString("no\n")
		os.Exit(3)
	case "sleep":
		// Longer than any budget a test here sets, so what ends this process is
		// always the caller's deadline and never its own patience.
		time.Sleep(15 * time.Second)
		os.Exit(0)
	case "spawn":
		// A GRANDCHILD THAT INHERITS THIS PROCESS'S STDOUT - which is the pipe
		// Run created - AND OUTLIVES IT. That is the state os/exec documents:
		// Wait waits for end-of-file on the pipes, and end-of-file does not
		// arrive while an orphan still holds the descriptor.
		grand := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
		// The mode has to be overridden rather than inherited, or the grandchild
		// would spawn one of its own for ever. exec keeps the LAST value of a
		// duplicated name, which is why appending is enough.
		grand.Env = append(os.Environ(), "CERTDOCTOR_HELPER_MODE=hold")
		grand.Stdout = os.Stdout
		grand.Stderr = os.Stderr
		if err := grand.Start(); err != nil {
			os.Stderr.WriteString("no grandchild: " + err.Error())
			os.Exit(9)
		}
		os.Exit(0)
	case "hold":
		// HOLDS THE INHERITED PIPE UNTIL THE OTHER END GOES AWAY, THEN STOPS,
		// and that is not tidiness - it is what keeps this test from breaking
		// the build. A grandchild sleeping a fixed time outlives the test that
		// owns it, and on Windows a running binary cannot be deleted, so go test
		// fails REMOVING ITS OWN TEST EXECUTABLE: measured here 2026-09-03,
		// "unlinkat ...\\probe.test.exe: Access is denied". Writing tells this
		// process when Run has closed its side; the ceiling below is a
		// backstop for the case where it never does.
		stop := time.Now().Add(30 * time.Second)
		for time.Now().Before(stop) {
			if _, err := os.Stdout.Write([]byte(".")); err != nil {
				os.Exit(0)
			}
			time.Sleep(20 * time.Millisecond)
		}
		os.Exit(0)
	case "readstdin":
		buf := make([]byte, 8)
		n, err := os.Stdin.Read(buf)
		if err != nil {
			// End of file is the ANSWER this test wants: a probe never feeds a
			// child, so a child that waits for input must not hang the run.
			os.Stdout.WriteString("eof")
			os.Exit(0)
		}
		os.Stdout.WriteString("read " + string(buf[:n]))
		os.Exit(0)
	}
	os.Exit(0)
}

func self(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Skipf("this platform will not say where the test binary is: %v", err)
	}
	return path
}

func helper(t *testing.T, mode string) {
	t.Helper()
	t.Setenv("CERTDOCTOR_HELPER", "1")
	t.Setenv("CERTDOCTOR_HELPER_MODE", mode)
}

// A BARE NAME IS REFUSED, and this is the rule with the most teeth in ADR49: a
// name is resolved by somebody else's PATH, so the thing that runs is chosen by
// configuration this program never read and cannot show in the report. Measured
// on this machine: two curl.exe on PATH and six Java installs, so "whichever one
// PATH picks" is never the whole answer anyway.
func TestABareNameIsRefusedBeforeAnythingRuns(t *testing.T) {
	_, err := Run(context.Background(), "curl", "--version")
	if !errors.Is(err, ErrNotAbsolute) {
		t.Fatalf("a bare name produced %v, want ErrNotAbsolute", err)
	}
}

func TestOutputComesBackFromBothStreams(t *testing.T) {
	helper(t, "loud")
	out, err := Run(context.Background(), self(t), "-test.run=TestHelperProcess")
	if err != nil {
		t.Fatalf("the helper would not run: %v", err)
	}
	if !strings.Contains(out.Stdout, "on stdout") {
		t.Errorf("stdout was lost: %q", out.Stdout)
	}
	if !strings.Contains(out.Stderr, "on stderr") {
		t.Errorf("stderr was lost: %q", out.Stderr)
	}
	if out.ExitCode != 0 {
		t.Errorf("exit code %d, want 0", out.ExitCode)
	}
}

// A NON-ZERO EXIT IS AN ANSWER, NOT AN ERROR, and often the interesting one:
// keytool refusing a keystore is exactly the fact the matrix needs.
func TestARefusalIsAnAnswerRatherThanAnError(t *testing.T) {
	helper(t, "refuse")
	out, err := Run(context.Background(), self(t), "-test.run=TestHelperProcess")
	if err != nil {
		t.Fatalf("a non-zero exit came back as an error: %v", err)
	}
	if out.ExitCode != 3 {
		t.Errorf("exit code %d, want 3 - the number is the fact, never the message", out.ExitCode)
	}
}

// NOTHING IS WRITTEN TO THE CHILD, so a program that decides to prompt gets end
// of file and exits rather than hanging this run for ever.
func TestTheChildGetsNoInput(t *testing.T) {
	helper(t, "readstdin")
	out, err := Run(context.Background(), self(t), "-test.run=TestHelperProcess")
	if err != nil {
		t.Fatalf("the helper would not run: %v", err)
	}
	if !strings.Contains(out.Stdout, "eof") {
		t.Errorf("the child read something from stdin: %q", out.Stdout)
	}
}

func TestAProgramThatIsNotThereIsAnError(t *testing.T) {
	missing := self(t) + ".not-here"
	if _, err := Run(context.Background(), missing, "-test.run=TestHelperProcess"); err == nil {
		t.Fatal("running a program that does not exist reported success")
	}
}

func TestACancelledContextStopsTheRun(t *testing.T) {
	helper(t, "loud")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, self(t), "-test.run=TestHelperProcess"); err == nil {
		t.Fatal("a cancelled run reported success")
	}
}

// TestOurOwnBudgetIsNeverTheChildsAnswer is #1 of the external review, and the
// assertion is written against the measurement rather than against the recipe.
//
// THE RECIPE THE REVIEW PROPOSED - gate on ProcessState.Exited() - WOULD PASS
// THIS TEST ON LINUX AND FAIL IT ON WINDOWS. Measured 2026-09-03 on both:
// killing the child leaves ExitCode -1 with Exited() false on Linux, and
// ExitCode 1 with Exited() TRUE on Windows, where 1 is also what a program that
// ran and refused would say. errors.Is(err, context.DeadlineExceeded) is false
// on both, because os/exec drops the context error once it already has an
// ExitError. The context is the only witness left.
//
// WHAT A READER MET BEFORE THIS: "the trust store could not be read: keytool
// exited with 1", about a keytool that answered nothing because certdoctor
// stopped it.
func TestOurOwnBudgetIsNeverTheChildsAnswer(t *testing.T) {
	helper(t, "sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	out, err := Run(ctx, self(t), "-test.run=TestHelperProcess")
	if err == nil {
		t.Fatalf("a child stopped by our own deadline came back as an answer, exit code %d", out.ExitCode)
	}
	// The caller has to be able to ask WHOSE limit this was, and the layer above
	// counts timeouts by asking exactly this question.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the error is %v, so errors.Is(err, context.DeadlineExceeded) answers false", err)
	}
	if out.ExitCode != 0 {
		t.Errorf("an exit code of %d travelled beside the error, so a caller could still read it as an answer", out.ExitCode)
	}
}

// TestOutputHeldOpenByAGrandchildDoesNotOutlastTheBudget is #3, and the number
// it defends is in waitDelay's own paragraph.
//
// MEASURED ON BOTH PLATFORMS 2026-09-03: with WaitDelay left at zero, a 300 ms
// budget produced a 30 s call - and no error at all, so a hundredfold overrun
// arrived looking like an answer. The orchestrator checks the context BETWEEN
// layers, so nothing above this would have noticed.
func TestOutputHeldOpenByAGrandchildDoesNotOutlastTheBudget(t *testing.T) {
	helper(t, "spawn")
	// THE BUDGET IS LONG ON PURPOSE AND THE FIRST VERSION WAS NOT - measured on
	// the CI Windows runner 2026-09-03, where it failed while passing on three
	// machines here. With a 100 ms budget the child had to start, spawn a
	// grandchild and exit inside 100 ms, which a loaded runner under coverage
	// instrumentation does not manage: the deadline killed the child first,
	// nothing ever held the pipe, and the run came back in a tenth of a second.
	// A budget nothing reaches makes the child's own exit the event that starts
	// waitDelay, which is the state this test is about.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	started := time.Now()
	out, err := Run(ctx, self(t), "-test.run=TestHelperProcess")
	elapsed := time.Since(started)

	if err == nil {
		t.Fatalf("a run whose output was held open by an orphan came back as an answer after %v", elapsed)
	}
	// The child exits at once, so what ends this run is waitDelay and nothing
	// else - which makes the error deterministic on every machine.
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Errorf("output held open by an orphan came back as %v after %v", err, elapsed)
	}
	// The grandchild holds the pipe for up to thirty seconds. Anything near that
	// is Wait sitting on an end-of-file that was never going to arrive.
	if elapsed > 8*time.Second {
		t.Errorf("Run took %v, so nothing bounded the wait", elapsed)
	}
	// AND THE LOWER BOUND IS WHAT STOPS THIS TEST PASSING ON NOTHING - OBS56.
	// Without it a run where the grandchild never started would look identical:
	// an error, quickly, and no proof that anything ever held the pipe. Waiting
	// past a second can only happen because waitDelay was being served.
	if elapsed < time.Second {
		t.Errorf("Run came back in %v, so nothing held the pipe open and this test established nothing", elapsed)
	}
	// NOTHING PARTIAL TRAVELS AS AN ANSWER. What arrived before the delay ran
	// out is not the whole of what the child had to say, and a caller reading
	// Output would have no way to tell.
	if out.Stdout != "" || out.ExitCode != 0 {
		t.Errorf("a partial answer travelled beside the error: %q, exit %d", out.Stdout, out.ExitCode)
	}
}

func TestOutputIsCapped(t *testing.T) {
	// cappedWriter is exercised directly: making a helper produce a megabyte
	// would slow this suite down for no extra proof.
	var one cappedWriter
	one.Write(make([]byte, OutputLimit+10))
	if got := len(one.kept); got != OutputLimit {
		t.Errorf("a single oversized write kept %d bytes, want %d", got, OutputLimit)
	}
	if !one.over {
		t.Error("a single oversized write did not record that output was dropped")
	}

	var small cappedWriter
	small.Write([]byte("short"))
	if got := string(small.kept); got != "short" {
		t.Errorf("output that was already short came back as %q", got)
	}
	if small.over {
		t.Error("output that fitted was reported as truncated")
	}
}

// TestOutputIsCappedAsItArrives is the half the old shape could not have.
//
// A bytes.Buffer trimmed after the child exits gives the same STRING as this
// and holds everything the child sent while it is running - which is the whole
// defect, because the size of that is decided by somebody else's program. Many
// small writes are what a real pipe delivers, so the cap has to hold across
// them rather than at the end.
func TestOutputIsCappedAsItArrives(t *testing.T) {
	var w cappedWriter
	chunk := make([]byte, 4096)
	for written := 0; written < OutputLimit+len(chunk)*4; written += len(chunk) {
		n, err := w.Write(chunk)
		// A SHORT COUNT WOULD BE READ BY os/exec AS io.ErrShortWrite, turning a
		// probe that answered at length into one that could not be asked at all.
		if n != len(chunk) || err != nil {
			t.Fatalf("Write reported %d, %v, want %d, nil", n, err, len(chunk))
		}
	}
	if got := len(w.kept); got != OutputLimit {
		t.Errorf("kept %d bytes across many writes, want %d", got, OutputLimit)
	}
	if !w.over {
		t.Error("output dropped across many writes was not recorded as truncated")
	}
}
