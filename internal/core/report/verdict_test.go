package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// vocabulary is every status a layer can report. The tests below walk every
// combination of it rather than a handful of examples, because the fold is a
// total function and an example test only ever proves the example.
var vocabulary = []status.Status{status.Pass, status.Warn, status.Unknown, status.Fail}

// everyCombinationUpTo calls check once for each ordered combination of
// statuses of length zero through maxLayers. Four statuses over three layers is
// eighty-five cases, which is cheap and complete.
func everyCombinationUpTo(t *testing.T, maxLayers int, check func(statuses []status.Status)) {
	t.Helper()
	for n := 0; n <= maxLayers; n++ {
		total := 1
		for i := 0; i < n; i++ {
			total *= len(vocabulary)
		}
		for c := 0; c < total; c++ {
			combination := make([]status.Status, n)
			remainder := c
			for i := 0; i < n; i++ {
				combination[i] = vocabulary[remainder%len(vocabulary)]
				remainder /= len(vocabulary)
			}
			check(combination)
		}
	}
}

// resultsFor turns a combination of statuses into layer rows.
func resultsFor(statuses []status.Status) []LayerResult {
	results := make([]LayerResult, 0, len(statuses))
	for i, s := range statuses {
		results = append(results, LayerResult{ID: layer.All[i], Status: s})
	}
	return results
}

func contains(statuses []status.Status, want status.Status) bool {
	for _, s := range statuses {
		if s == want {
			return true
		}
	}
	return false
}

// TestVerdictStatusIsTheWorstOfTheLayers is the product's main promise, checked
// over every combination rather than over chosen examples.
//
// The expected value is written out here in full rather than computed with the
// helper the implementation uses. A test that folds the statuses the same way
// the code does would agree with the code even when both are wrong.
func TestVerdictStatusIsTheWorstOfTheLayers(t *testing.T) {
	severityOrder := []status.Status{status.Fail, status.Warn, status.Unknown, status.Pass}

	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		want := status.Unknown
		if len(statuses) > 0 {
			for _, candidate := range severityOrder {
				if contains(statuses, candidate) {
					want = candidate
					break
				}
			}
		}
		if got := Assess(resultsFor(statuses)).Status; got != want {
			t.Errorf("layers %v folded to %s, want %s", statuses, got, want)
		}
	})
}

// TestExitCodeFollowsTheFrozenRule restates the mapping deliberately. It is the
// bridge between the status vocabulary and the exit code table, and both of
// those are public contracts.
func TestExitCodeFollowsTheFrozenRule(t *testing.T) {
	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		want := exitcode.OK
		switch {
		case contains(statuses, status.Fail):
			want = exitcode.Diagnosis
		case len(statuses) == 0 || contains(statuses, status.Unknown):
			want = exitcode.Inconclusive
		}
		got := Assess(resultsFor(statuses)).ExitCode
		if got != want {
			t.Errorf("layers %v ended with %s (%d), want %s (%d)",
				statuses, got.Name(), got.Int(), want.Name(), want.Int())
		}
		if !got.Valid() {
			t.Errorf("layers %v produced exit code %d, which is not in the frozen table", statuses, got.Int())
		}
	})
}

// TestNoFailureIsEverReportedAsSuccess is the same promise from the direction
// that costs the most when it breaks. A verdict reading as success over a
// failing row looks like a working machine and the reader stops there.
func TestNoFailureIsEverReportedAsSuccess(t *testing.T) {
	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		if !contains(statuses, status.Fail) && !contains(statuses, status.Unknown) && len(statuses) > 0 {
			return
		}
		verdict := Assess(resultsFor(statuses))
		if verdict.ExitCode == exitcode.OK {
			t.Errorf("layers %v ended with success", statuses)
		}
		if verdict.Sentence == everythingPassed {
			t.Errorf("layers %v produced the complete-success sentence", statuses)
		}
	})
}

// TestAWarningDoesNotRedenTheExitCode pins the decision that a warning alone
// keeps the code at success. Without it every machine behind a corporate proxy
// would fail a build whose connection works perfectly, and the tool would be
// switched off within a week.
func TestAWarningDoesNotRedenTheExitCode(t *testing.T) {
	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		if len(statuses) == 0 || contains(statuses, status.Fail) || contains(statuses, status.Unknown) {
			return
		}
		if got := Assess(resultsFor(statuses)).ExitCode; got != exitcode.OK {
			t.Errorf("layers %v are at worst a warning and ended with %s", statuses, got.Name())
		}
	})
}

// TestVerdictOfAnEmptyReportIsNeverSuccess covers the degenerate input that the
// fold would otherwise get wrong for a defensible reason: folding an empty set
// of statuses answers "success", which is right when combining a subset into a
// whole and wrong when the whole is empty.
func TestVerdictOfAnEmptyReportIsNeverSuccess(t *testing.T) {
	for _, results := range [][]LayerResult{nil, {}} {
		verdict := Assess(results)
		if verdict.Status != status.Unknown {
			t.Errorf("a report with no layers folded to %s", verdict.Status)
		}
		if verdict.ExitCode != exitcode.Inconclusive {
			t.Errorf("a report with no layers ended with %s", verdict.ExitCode.Name())
		}
		if verdict.Sentence != nothingAssessed {
			t.Errorf("a report with no layers said %q", verdict.Sentence)
		}
	}
}

// TestTheAllUnknownRunGetsTheSettledSentence pins the sentence this whole slice
// exists to produce, and pins that it is used only when it is true.
func TestTheAllUnknownRunGetsTheSettledSentence(t *testing.T) {
	all := make([]status.Status, len(layer.All))
	for i := range all {
		all[i] = status.Unknown
	}
	if got := Assess(resultsFor(all)).Sentence; got != "Nothing could be assessed yet." {
		t.Errorf("a run where nothing was assessed said %q", got)
	}

	mixed := append([]status.Status{status.Pass}, all[1:]...)
	if got := Assess(resultsFor(mixed)).Sentence; got == nothingAssessed {
		t.Errorf("a run where one layer did produce an answer still said %q", got)
	}
}

// TestEverySentenceSaysSomethingAndItsCountsAgree keeps the provisional
// counting sentences honest. A sentence quoting the wrong number is worse than
// no sentence at all, because the reader checks the number against the rows and
// then trusts whichever one they read first.
func TestEverySentenceSaysSomethingAndItsCountsAgree(t *testing.T) {
	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		sentence := Assess(resultsFor(statuses)).Sentence
		if sentence == "" {
			t.Fatalf("layers %v produced no sentence", statuses)
		}
		if !strings.HasSuffix(sentence, ".") {
			t.Errorf("layers %v produced %q, which does not end as a sentence", statuses, sentence)
		}

		failures := countOf(statuses, status.Fail)
		if failures == 0 {
			return
		}
		want := fmt.Sprintf("%d of %d", failures, len(statuses))
		if !strings.Contains(sentence, want) {
			t.Errorf("layers %v produced %q, which does not read %q", statuses, sentence, want)
		}
	})
}

func countOf(statuses []status.Status, want status.Status) int {
	n := 0
	for _, s := range statuses {
		if s == want {
			n++
		}
	}
	return n
}
