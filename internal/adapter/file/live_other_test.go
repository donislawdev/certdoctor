//go:build !windows

package file

import (
	"errors"
	"testing"
)

// NOTHING OUTSIDE WINDOWS IS AN APP EXECUTION ALIAS, so the port refuses every
// path without touching it.
func TestTheLiveAliasPortRefusesEverythingOutsideWindows(t *testing.T) {
	if _, err := LiveAppAlias()("/usr/bin/python3"); !errors.Is(err, ErrNotAnAppAlias) {
		t.Errorf("got %v", err)
	}
}
