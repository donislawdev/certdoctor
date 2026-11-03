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
