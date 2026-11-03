//go:build !cgo

package main

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TestABuildWithNoWindowSaysSoAndFails - one sentence on standard error and the
// code of a refusal, whatever the arguments.
func TestABuildWithNoWindowSaysSoAndFails(t *testing.T) {
	var out strings.Builder
	if code := run([]string{"--anything"}, &out); code != 1 {
		t.Errorf("a build with no window gave code %d, want 1", code)
	}
	if got := strings.TrimSpace(out.String()); got != words.T(words.NoWindowInThisBuild) {
		t.Errorf("a build with no window said %q", got)
	}
}
