//go:build !windows

package probe

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A WRAPPER'S CHILD ENDS WITH THE RUN - ADR114 point 6. The run starts a
// wrapper, the wrapper starts the program and waits, and the budget ends the
// run: before process groups the program went on beating after Run returned.
func TestACancelledRunEndsTheChildrenOfWhatItStarted(t *testing.T) {
	helper(t, "parent")
	beat := filepath.Join(t.TempDir(), "beat")
	t.Setenv("CERTDOCTOR_BEAT_FILE", beat)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := Run(ctx, self(t), "-test.run=TestHelperProcess"); err == nil {
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
