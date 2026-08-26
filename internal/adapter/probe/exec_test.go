package probe

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
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
