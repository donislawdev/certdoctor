package main

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
)

// TestTheLicenceSwitchPrintsTheNoticesAfterTheGPL pins what --license answers
// and in which order. The GPL comes first because it is this program's licence,
// and the notices follow whole, because a binary copied on its own into an image
// has nowhere else to carry them - ADR116. Until 2026-10-28 the switch printed
// the GPL alone, and the MIT and BSD notices of the code it links went nowhere.
//
// What the notices must say is not checked here. internal/guard asks the build
// what it links and holds THIRD-PARTY-NOTICES.md to that.
func TestTheLicenceSwitchPrintsTheNoticesAfterTheGPL(t *testing.T) {
	h := invoke("--license")
	if h.code != exitcode.OK {
		t.Fatalf("--license ended %d: %q", h.code, h.stderr.String())
	}
	if got, want := h.stdout.String(), certdoctor.License+"\n"+certdoctor.Notices; got != want {
		t.Errorf("--license printed %d bytes, want the GPL and then the notices, %d bytes", len(got), len(want))
	}
	if !strings.HasPrefix(certdoctor.Notices, "# Third party notices\n") {
		t.Errorf("the embedded notices do not open with their heading: %.60q", certdoctor.Notices)
	}
}
