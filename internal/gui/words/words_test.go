package words

import (
	"strings"
	"testing"
)

// TestAKeyWithNoTextCannotPassForASentence - a key nobody wrote comes back in
// angle brackets, and every key that was written has words.
func TestAKeyWithNoTextCannotPassForASentence(t *testing.T) {
	if got := T("no.such.key"); got != "<no.such.key>" {
		t.Errorf("a missing key reads %q", got)
	}
	for _, m := range []map[Key]string{english, catalogue} {
		for k, s := range m {
			if strings.TrimSpace(s) == "" {
				t.Errorf("%s has no words", k)
			}
			if got := T(k); got != s {
				t.Errorf("%s reads %q, want %q", k, got, s)
			}
		}
	}
}

// TestTheToolkitsWordsAreACopy - Toolkit hands every word of the toolkit with
// English for it, and a caller that changes what it was handed does not
// change what the next one is given. That the identifiers are the toolkit's
// own is held against its module in cmd/certdoctor-gui, which links it.
func TestTheToolkitsWordsAreACopy(t *testing.T) {
	first := Toolkit()
	if len(first) != len(toolkit) || first["Cut"] != "Cut" || first["file.name"] != "Name" {
		t.Fatalf("Toolkit handed %d words, Cut as %q and file.name as %q", len(first), first["Cut"], first["file.name"])
	}
	for id, text := range first {
		if strings.TrimSpace(text) == "" {
			t.Errorf("%q has no English", id)
		}
	}
	first["Cut"] = "changed"
	delete(first, "Copy")
	if again := Toolkit(); again["Cut"] != "Cut" || again["Copy"] != "Copy" {
		t.Errorf("a change to one copy reached the next: Cut %q, Copy %q", again["Cut"], again["Copy"])
	}
}

// TestAKindAndAReasonTheWindowCannotNameAreShownAsTheReportSpellsThem - an
// unknown value is shown, never dropped.
func TestAKindAndAReasonTheWindowCannotNameAreShownAsTheReportSpellsThem(t *testing.T) {
	if Kind("trust_store") != "Trust store" || Reason("timeout") != "Time limit reached" {
		t.Error("a known value is not named")
	}
	if Kind("a_new_kind") != "a_new_kind" || Reason("a_new_reason") != "a_new_reason" {
		t.Error("an unknown value is not shown as it is spelled")
	}
}
