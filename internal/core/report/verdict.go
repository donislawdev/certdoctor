package report

import (
	"fmt"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Verdict is the one sentence at the top of the report, the status behind it
// and the code the process ends with.
//
// The exit code is carried here as well as being handed to the operating system
// on purpose. A report saved to a file keeps information the process exit status
// cannot, and a reader comparing two saved reports should not have to remember
// what each run returned.
type Verdict struct {
	Status   status.Status
	Sentence string
	ExitCode exitcode.Code
}

// nothingAssessed is the verdict of a run that could not assess a single layer.
//
// This is the one sentence in this file that is settled product text. The three
// counting sentences below are provisional: the verdicts that matter - the ones
// that name a cause, such as traffic being re-signed by a local authority -
// arrive with the layers that can establish a cause, and their wording is the
// owner's decision, not a detail of this function.
//
// The provisional three are deliberately arithmetic rather than narrative. They
// state counts, which we can prove, and claim no cause, which we cannot.
const nothingAssessed = "Nothing could be assessed yet."

// everythingPassed is the other settled one, because it is the only sentence
// that must never appear over a report containing a failure.
const everythingPassed = "Everything that mattered was assessed and passed."

// Assess folds the layer results into the verdict.
//
// This function is the product's main promise written down: the sentence at the
// top has to agree with the rows underneath it. A verdict reading "all fine"
// above four failures is the worst mistake this tool can make, because it looks
// like success and the reader stops there.
//
// It is pure, total and exhaustively tested over combinations rather than over
// examples, and it was written before any layer existed - which is the only
// moment at which it could be written without first finding the rule already
// broken somewhere.
func Assess(results []LayerResult) Verdict {
	counts := map[status.Status]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	return Verdict{
		Status:   worstOf(results),
		Sentence: sentenceFor(counts, len(results)),
		ExitCode: codeFor(counts, len(results)),
	}
}

// worstOf returns the most severe status among the results.
//
// The empty case is not a formality. status.Worst answers "success" for an empty
// set, which is right for folding a subset into a whole and wrong here: a run
// that produced no rows at all assessed nothing, and reporting that as success
// is exactly the failure this file exists to prevent.
func worstOf(results []LayerResult) status.Status {
	if len(results) == 0 {
		return status.Unknown
	}
	all := make([]status.Status, 0, len(results))
	for _, r := range results {
		all = append(all, r.Status)
	}
	return status.Worst(all...)
}

// codeFor maps the fold onto the frozen exit code table.
//
// A warning on its own keeps the code at success, deliberately: otherwise every
// machine behind a corporate proxy would redden a build whose connection works,
// and the tool would be switched off within a week. The machine-readable report
// carries the warnings for a pipeline that wants to decide differently.
func codeFor(counts map[status.Status]int, total int) exitcode.Code {
	switch {
	case counts[status.Fail] > 0:
		return exitcode.Diagnosis
	case total == 0 || counts[status.Unknown] > 0:
		return exitcode.Inconclusive
	default:
		return exitcode.OK
	}
}

// sentenceFor picks the verdict sentence.
//
// Order matters here and is not the same order as codeFor. A run where every
// layer came back unknown gets the settled sentence, because "nothing could be
// assessed" reads better than "8 of 8 could not be assessed" and says the same
// thing. A run where only some came back unknown must not use it, because then
// it would be false.
func sentenceFor(counts map[status.Status]int, total int) string {
	unknown := counts[status.Unknown]
	switch {
	case total == 0 || unknown == total:
		return nothingAssessed
	// Both numbers, because either one alone is a true sentence that leaves out
	// the other half. A run with two failures and three layers it could not look
	// at used to read "Failures in 2 of 8" and stop there - and a reader who
	// fixes those two comes back to find that three more were never assessed.
	// The verdict is the line people act on, so an omission there is the ban on
	// silence broken in the loudest place available.
	case counts[status.Fail] > 0 && unknown > 0:
		return fmt.Sprintf("Failures in %d of %d diagnostic layers, and %d could not be assessed.",
			counts[status.Fail], total, unknown)
	case counts[status.Fail] > 0:
		return fmt.Sprintf("Failures in %d of %d diagnostic layers.", counts[status.Fail], total)
	case unknown > 0:
		return fmt.Sprintf("%d of %d diagnostic layers could not be assessed.", unknown, total)
	case counts[status.Warn] > 0:
		return fmt.Sprintf("Everything assessed passed. Warnings in %d of %d diagnostic layers.", counts[status.Warn], total)
	default:
		return everythingPassed
	}
}
