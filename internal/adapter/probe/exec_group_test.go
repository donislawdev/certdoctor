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
	switch mode := os.Getenv("CERTDOCTOR_HELPER_MODE"); mode {
	case "parent", "grandparent":
		// A WRAPPER: it starts the real program as its own child, without exec,
		// and waits past any budget a test sets - ADR114 point 6. A grandparent
		// starts a wrapper instead, so the program is two levels down.
		next := "beat"
		if mode == "grandparent" {
			next = "parent"
		}
		child := exec.Command(os.Args[0], "-test.run=TestHelperWrapper")
		child.Env = append(os.Environ(), "CERTDOCTOR_HELPER_MODE="+next)
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

// A WRAPPER'S CHILD ENDS WITH THE RUN - ADR114 point 6 on Linux and macOS,
// ADR150 on Windows. The run starts a wrapper, the wrapper starts the program
// and waits, and the budget ends the run: before process groups the program
// went on beating after Run returned, and on Windows it did until OBS197 was
// closed - measured 2026-10-27 with Chocolatey's shim, whose child lived on.
//
// TWO LEVELS AS WELL AS ONE, because a fix that ended only the wrapper's own
// children would pass the first and leave a wrapper started by a wrapper - a
// version manager calling a shim - running the program.
func TestACancelledRunEndsTheChildrenOfWhatItStarted(t *testing.T) {
	for _, mode := range []string{"parent", "grandparent"} {
		helper(t, mode)
		beat := filepath.Join(t.TempDir(), "beat")
		t.Setenv("CERTDOCTOR_BEAT_FILE", beat)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if _, err := Run(ctx, self(t), "-test.run=TestHelperWrapper"); err == nil {
			t.Fatalf("%s: a wrapper stopped by the budget came back as an answer", mode)
		}
		cancel()

		time.Sleep(300 * time.Millisecond)
		before := sizeOf(t, beat)
		time.Sleep(500 * time.Millisecond)
		after := sizeOf(t, beat)
		// AND THE PROGRAM DID START - OBS56: a beat file that never grew would
		// pass the check below on nothing.
		if before == 0 {
			t.Fatalf("%s: the wrapper's child never beat, so this test established nothing", mode)
		}
		if after != before {
			t.Errorf("%s: the program kept running after the run ended: %d bytes, then %d", mode, before, after)
		}
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
