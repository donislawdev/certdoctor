//go:build !windows

package file

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// NOTHING OUTSIDE WINDOWS IS AN APP EXECUTION ALIAS, so the port refuses every
// path without touching it.
func TestTheLiveAliasPortRefusesEverythingOutsideWindows(t *testing.T) {
	if _, err := LiveAppAlias()("/usr/bin/python3"); !errors.Is(err, ErrNotAnAppAlias) {
		t.Errorf("got %v", err)
	}
}

// A PIPE NOBODY WRITES TO IS REFUSED WITHOUT WAITING - ADR114. Opened the
// ordinary way, the open itself blocks until a writer comes, and none will.
func TestAPipeNobodyWritesToIsRefusedAtOnce(t *testing.T) {
	pipe := filepath.Join(t.TempDir(), "bundle.pem")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatalf("making the pipe: %v", err)
	}
	started := time.Now()
	_, err := liveSource(pipe)
	var refused *NotRegular
	if !errors.As(err, &refused) {
		t.Errorf("a pipe was opened for reading: %v", err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Errorf("refusing the pipe took %v", waited)
	}
}
