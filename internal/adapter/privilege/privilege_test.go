package privilege

import (
	"errors"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// TestAFailedQuestionIsUnknownRatherThanAGuess is the one rule in this package
// that could never be exercised for real, which is exactly why it is tested
// through a seam.
//
// A process cannot be made to fail at reading its own token on demand, so
// without this the failure branch would ship unexecuted. And the wrong answer
// here is the quiet kind: reporting "user" because the question failed puts a
// measurement nobody took into the field that decides whether two reports may
// be compared at all.
func TestAFailedQuestionIsUnknownRatherThanAGuess(t *testing.T) {
	refused := errors.New("the operating system refused to answer")

	// Both directions, because a failed question says nothing about which
	// answer it would have given.
	if got := levelFrom(false, refused); got != report.PrivilegeUnknown {
		t.Errorf("a failed question answered %q, want unknown", got)
	}
	if got := levelFrom(true, refused); got != report.PrivilegeUnknown {
		t.Errorf("a failed question answered %q even though the flag was set, want unknown", got)
	}
}

// TestAnAnsweredQuestionIsReportedFaithfully is the other side. A rule that
// degraded everything to unknown would pass the test above and be useless.
func TestAnAnsweredQuestionIsReportedFaithfully(t *testing.T) {
	if got := levelFrom(true, nil); got != report.PrivilegeElevated {
		t.Errorf("an elevated token was reported as %q", got)
	}
	if got := levelFrom(false, nil); got != report.PrivilegeUser {
		t.Errorf("an ordinary token was reported as %q", got)
	}
}

// TestEveryAnswerIsInsideTheDeclaredSet closes the gap between this package and
// report.Validate, which rejects a level outside the three.
//
// The zero value of the type is the empty string and it is not a level, so a
// path that returned it would produce a report that fails its own checks at
// runtime - an internal failure rather than a diagnosis.
func TestEveryAnswerIsInsideTheDeclaredSet(t *testing.T) {
	answers := []report.PrivilegeLevel{
		levelFrom(true, nil),
		levelFrom(false, nil),
		levelFrom(false, errors.New("refused")),
		// The real machine this runs on, whatever it happens to be.
		Level(),
	}
	for _, answer := range answers {
		if answer == "" {
			t.Fatal("a level came back empty, which report.Validate rejects")
		}
		if !answer.Valid() {
			t.Errorf("%q is not one of the declared levels", answer)
		}
	}
}
