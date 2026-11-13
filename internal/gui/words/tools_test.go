package words

import (
	"sort"
	"strings"
	"testing"
)

// TestAnInputTooLongSaysHowMuchFitsAndWhereMoreGoes - the numbers are the
// limits handed in, the command named is the tool's with its switch, and a
// box that takes as much as the command line does sends nobody there.
func TestAnInputTooLongSaysHowMuchFitsAndWhereMoreGoes(t *testing.T) {
	more := InputTooLong(32<<10, 256<<10, "jwt", "file")
	for _, want := range []string{"at most 32 KiB", "up to 256 KiB", "certdoctor tool jwt --file <file>"} {
		if !strings.Contains(more, want) {
			t.Errorf("%q does not say %q", more, want)
		}
	}
	if strings.Contains(more, "%!") {
		t.Errorf("%q has a number it could not place", more)
	}
	if as := InputTooLong(32<<10, 32<<10, "jwt", "file"); !strings.Contains(as, "at most 32 KiB") ||
		strings.Contains(as, "certdoctor tool") {
		t.Errorf("a box taking all the command line takes says %q", as)
	}
}

// TestEveryToolsWordsAreThereAndComplete - every tool the window has words
// for has all of them, the ids come back sorted so a list of them reads the
// same every time, and a tool or a category the window cannot name is said as
// the contract spells it rather than as nothing. That the ids are the
// contract's own is held in the screens, which see both lists.
func TestEveryToolsWordsAreThereAndComplete(t *testing.T) {
	ids := ToolIDs()
	if len(ids) == 0 || !sort.StringsAreSorted(ids) {
		t.Fatalf("ids %v - want at least one, sorted", ids)
	}
	for _, id := range ids {
		w, ok := Tool(id)
		if !ok || w.Title == "" || w.Summary == "" || w.Action == "" || w.Ready == "" || len(w.Inputs) == 0 {
			t.Errorf("%s: %+v", id, w)
		}
		for name, in := range w.Inputs {
			if in.Label == "" || in.Hint == "" || in.Example == "" {
				t.Errorf("%s: input %s: %+v", id, name, in)
			}
		}
	}
	if _, ok := Tool("no-such-tool"); ok {
		t.Error("words were found for a tool there is not")
	}
	if Category("tokens") != "Tokens" || Category("no-such-category") != "no-such-category" {
		t.Error("a category is not named, or one the window cannot name is not shown as spelled")
	}
}
