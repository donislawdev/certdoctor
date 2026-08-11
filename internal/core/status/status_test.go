package status

import (
	"sort"
	"testing"
)

// This file is a registry test. It does not check behaviour of one function - it
// checks that the registry is complete and internally consistent, which is the
// cheapest guard available and the one that catches the most likely mistake:
// a value added in one place and forgotten in another.

// TestStatusListIsClosedAtFour guards the product's headline promise. Unknown is
// the only escape hatch for "could not assess", and that only holds while the
// list stays closed. A fifth value must be an owner's decision, so this test is
// expected to fail loudly when someone adds one.
func TestStatusListIsClosedAtFour(t *testing.T) {
	if len(All) != 4 {
		t.Fatalf("status vocabulary must contain exactly 4 values, got %d: %v", len(All), All)
	}
	want := map[Status]bool{Fail: true, Warn: true, Unknown: true, Pass: true}
	for _, s := range All {
		if !want[s] {
			t.Errorf("unexpected status in All: %q", s)
		}
		delete(want, s)
	}
	for s := range want {
		t.Errorf("status missing from All: %q", s)
	}
}

// TestEverySeverityIsDeclaredExactlyOnce catches the half-added entry: a status
// listed in All but never given a rank, or two statuses sharing a rank, which
// would make report ordering depend on map iteration.
func TestEverySeverityIsDeclaredExactlyOnce(t *testing.T) {
	if len(severity) != len(All) {
		t.Fatalf("severity table has %d entries, All has %d - an entry was added in one place only", len(severity), len(All))
	}
	seen := map[int]Status{}
	for _, s := range All {
		rank, ok := severity[s]
		if !ok {
			t.Fatalf("status %q has no severity", s)
		}
		if other, dup := seen[rank]; dup {
			t.Errorf("statuses %q and %q share severity %d - report order would be non-deterministic", other, s, rank)
		}
		seen[rank] = s
	}
	ranks := make([]int, 0, len(seen))
	for r := range seen {
		ranks = append(ranks, r)
	}
	sort.Ints(ranks)
	for i, r := range ranks {
		if r != i+1 {
			t.Errorf("severities must be contiguous starting at 1, got %v", ranks)
			break
		}
	}
}

// TestAllIsOrderedMostSevereFirst pins the documented order. Callers are allowed
// to range over All and render in that order without sorting.
func TestAllIsOrderedMostSevereFirst(t *testing.T) {
	for i := 1; i < len(All); i++ {
		if All[i-1].Severity() >= All[i].Severity() {
			t.Fatalf("All is not ordered most severe first: %q (%d) before %q (%d)",
				All[i-1], All[i-1].Severity(), All[i], All[i].Severity())
		}
	}
}

// TestZeroValueIsInvalid is the guard against a forgotten assignment silently
// becoming a success. An unset Status must never look like Pass.
func TestZeroValueIsInvalid(t *testing.T) {
	var zero Status
	if zero.Valid() {
		t.Fatal("the zero Status must be invalid, otherwise a forgotten assignment reads as a real verdict")
	}
	if zero == Pass {
		t.Fatal("the zero Status must not equal Pass")
	}
}

func TestValidRejectsAnythingOutsideTheVocabulary(t *testing.T) {
	for _, s := range []Status{"", "pass", "Pass", "SKIPPED", "N/A", "OK", "ERROR"} {
		if s.Valid() {
			t.Errorf("Valid() accepted %q, which is not part of the vocabulary", s)
		}
	}
	for _, s := range All {
		if !s.Valid() {
			t.Errorf("Valid() rejected %q, which is part of the vocabulary", s)
		}
	}
}

// TestOnlyUnknownNeedsAReasonAndEverythingButPassNeedsASentence encodes the ban
// on silence, split into the two questions it turned out to be.
//
// IT USED TO SAY "anything but PASS needs a reason" AND THAT WAS MEASURED WRONG,
// not merely worded loosely. The reason vocabulary answers "why could this not
// be assessed" - timeout, refusal, unreadable output, a budget spent. A layer
// that DID assess something and found it wrong has no honest value in that list,
// so requiring one meant every WARN and FAIL broke its contract and came back as
// UNKNOWN with probe_error. D13's entire verdict half was unreachable in the
// shipped binary because of this line.
//
// The ban on silence did not go anywhere: it moved to RequiresDetail, which is
// the half a reader actually reads, and this test pins both halves so that
// narrowing one cannot quietly drop the other.
func TestOnlyUnknownNeedsAReasonAndEverythingButPassNeedsASentence(t *testing.T) {
	for _, s := range []Status{Pass, Warn, Fail} {
		if s.RequiresReason() {
			t.Errorf("%q must not require a reason - that list says why something could NOT be assessed", s)
		}
	}
	if !Unknown.RequiresReason() {
		t.Error("Unknown must require a reason: an unassessed layer with no why is the silence this forbids")
	}

	if Pass.RequiresDetail() {
		t.Error("Pass must not be forced to explain itself")
	}
	for _, s := range []Status{Warn, Fail, Unknown} {
		if !s.RequiresDetail() {
			t.Errorf("%q must carry a sentence: a mark on the screen with nothing beside it cannot be acted on", s)
		}
	}
}

func TestWorst(t *testing.T) {
	cases := []struct {
		name string
		in   []Status
		want Status
	}{
		{"empty set is a pass", nil, Pass},
		{"single value", []Status{Warn}, Warn},
		{"fail dominates", []Status{Pass, Warn, Fail, Unknown}, Fail},
		{"unknown beats pass", []Status{Pass, Unknown}, Unknown},
		{"warn beats unknown", []Status{Unknown, Warn}, Warn},
		{"all passing", []Status{Pass, Pass}, Pass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Worst(c.in...); got != c.want {
				t.Errorf("Worst(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestWorstIsIndependentOfInputOrder is a property, not an example. The verdict
// must not depend on the order probes happened to finish in.
func TestWorstIsIndependentOfInputOrder(t *testing.T) {
	forward := Worst(All...)
	reversed := make([]Status, len(All))
	for i, s := range All {
		reversed[len(All)-1-i] = s
	}
	if backward := Worst(reversed...); backward != forward {
		t.Fatalf("Worst depends on input order: %q forward, %q reversed", forward, backward)
	}
}

// TestReasonListIsComplete is the same registry guard applied to reasons.
func TestReasonListIsComplete(t *testing.T) {
	if len(reasonDescriptions) != len(AllReasons) {
		t.Fatalf("description table has %d entries, AllReasons has %d - an entry was added in one place only",
			len(reasonDescriptions), len(AllReasons))
	}
	seen := map[Reason]bool{}
	for _, r := range AllReasons {
		if seen[r] {
			t.Errorf("reason %q listed twice in AllReasons", r)
		}
		seen[r] = true
		if !r.Valid() {
			t.Errorf("reason %q is in AllReasons but Valid() rejects it", r)
		}
		if r.Description() == "" {
			t.Errorf("reason %q has no description - the user would be told why in an empty sentence", r)
		}
	}
}

func TestUnknownReasonHasNoDescription(t *testing.T) {
	var r Reason = "made_up"
	if r.Valid() {
		t.Error("Valid() accepted a reason outside the vocabulary")
	}
	if r.Description() != "" {
		t.Error("an unknown reason must describe itself as nothing rather than inventing text")
	}
}
