package main

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/switches"
)

// TestTheGroupTheHelpCallsNotBuiltIsRefused holds the note on a help group to
// what the program does with that group's switches, in both directions.
//
// The note is prose, and prose outlives the code it describes. The day
// container diagnosis works, a switch under "Not built in this release" stops
// being refused and this goes red until the note comes off. The other way, a
// switch refused as not built that sits in a group with no note is one the help
// page presents as working, which is what the note was added to stop.
func TestTheGroupTheHelpCallsNotBuiltIsRefused(t *testing.T) {
	notes := map[string]string{}
	for _, group := range switches.Groups {
		notes[group.Name] = group.Note
	}

	page := helpText()
	noted := 0
	for _, s := range switches.All {
		if !s.TakesValue() || s.Numeric {
			continue
		}
		h := invoke("https://example.com", "--"+s.Name, "x")
		refusedAsNotBuilt := strings.Contains(h.stderr.String(), "not built")
		note := notes[s.Group]

		if note == "" {
			if refusedAsNotBuilt {
				t.Errorf("--%s is refused as not built, and its group in --help carries no note saying so: %q",
					s.Name, h.stderr.String())
			}
			continue
		}
		noted++
		if !strings.Contains(page, note) {
			t.Errorf("the note on the group of --%s is not on the help page", s.Name)
		}
		if h.code != exitcode.Config {
			t.Errorf("--%s sits under %q and ended %d rather than being refused: %q",
				s.Name, note, h.code, h.stderr.String())
		}
	}
	if noted == 0 {
		t.Fatal("no help group carries a note, so this test checks nothing - delete it with the last note")
	}
}
