//go:build !windows

package probe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestHelperWrapper is not a test either. It is the wrapper and the program the
// test below runs, kept apart from TestHelperProcess because only this file
// writes - the beat lands under the temporary directory its test takes.
func TestHelperWrapper(t *testing.T) {
	if os.Getenv("CERTDOCTOR_HELPER") != "1" {
		return
	}
	switch os.Getenv("CERTDOCTOR_HELPER_MODE") {
	case "parent":
		// A WRAPPER: it starts the real program as its own child, without exec,
		// and waits past any budget a test sets - ADR114 point 6.
		child := exec.Command(os.Args[0], "-test.run=TestHelperWrapper")
		child.Env = append(os.Environ(), "CERTDOCTOR_HELPER_MODE=beat")
		if err := child.Start(); err != nil {
			os.Exit(9)
		}
		time.Sleep(15 * time.Second)
		os.Exit(0)
	case "beat":
		// Appends to a file while it lives, so a test can see whether it still
		// does - a pid would outlive it as a zombie under an init that does not
		// reap, and a file does not. The ceiling is a backstop.
		stop := time.Now().Add(30 * time.Second)
		for time.Now().Before(stop) {
			beat, err := os.OpenFile(os.Getenv("CERTDOCTOR_BEAT_FILE"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				os.Exit(8)
			}
			_, _ = beat.WriteString(".")
			_ = beat.Close()
			time.Sleep(20 * time.Millisecond)
		}
		os.Exit(0)
	}
}

// A WRAPPER'S CHILD ENDS WITH THE RUN - ADR114 point 6. The run starts a
// wrapper, the wrapper starts the program and waits, and the budget ends the
// run: before process groups the program went on beating after Run returned.
func TestACancelledRunEndsTheChildrenOfWhatItStarted(t *testing.T) {
	helper(t, "parent")
	beat := filepath.Join(t.TempDir(), "beat")
	t.Setenv("CERTDOCTOR_BEAT_FILE", beat)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := Run(ctx, self(t), "-test.run=TestHelperWrapper"); err == nil {
		t.Fatal("a wrapper stopped by the budget came back as an answer")
	}

	time.Sleep(300 * time.Millisecond)
	before := sizeOf(t, beat)
	time.Sleep(500 * time.Millisecond)
	after := sizeOf(t, beat)
	// AND THE PROGRAM DID START - OBS56: a beat file that never grew would pass
	// the check below on nothing.
	if before == 0 {
		t.Fatal("the wrapper's child never beat, so this test established nothing")
	}
	if after != before {
		t.Errorf("the wrapper's child kept running after the run ended: %d bytes, then %d", before, after)
	}
}

func sizeOf(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
