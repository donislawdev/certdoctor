package report

import (
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// wellFormedReport is the shape this whole slice produces: every layer present,
// every one of them honest about not being implemented, and a verdict that
// agrees with them.
func wellFormedReport() Report {
	results := make([]LayerResult, 0, len(layer.All))
	for _, id := range layer.All {
		results = append(results, LayerResult{
			ID:     id,
			Status: status.Unknown,
			Reason: status.ReasonProbeError,
			Detail: "not implemented",
		})
	}
	return Report{
		Tool: Tool{Name: "certdoctor", Version: "0.0.0-test"},
		Run: Run{
			// A fixed moment rather than the zero time. A report that does not
			// say when it was taken is refused, so a fixture carrying the zero
			// value would be testing a shape the product cannot produce.
			StartedAt:      time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC),
			Target:         "https://example.com",
			PrivilegeLevel: PrivilegeUnknown,
			Platform:       Platform{OS: "testos", Arch: "testarch", Container: NotDetermined},
		},
		Verdict: Assess(results),
		Layers:  results,
		Notes: []Note{{
			Kind:   NoteNotImplemented,
			Detail: "no diagnostic layer is implemented yet",
		}},
	}
}

func requireRejected(t *testing.T, r Report, want string) {
	t.Helper()
	err := Validate(r)
	if err == nil {
		t.Fatalf("Validate accepted a report it should have refused, expected a complaint about %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("Validate complained about something else:\n%v\nexpected a mention of %q", err, want)
	}
}

func TestValidateAcceptsAWellFormedReport(t *testing.T) {
	if err := Validate(wellFormedReport()); err != nil {
		t.Fatalf("a well formed report was refused: %v", err)
	}
}

// TestValidateRejectsAVerdictSentenceThatDisagreesWithItsLayers closes the hole
// in the check this project calls the product's main promise.
//
// The status and the exit code were compared against a recomputed fold and the
// SENTENCE was not - so a report could carry a line claiming failures over rows
// that all passed, and as long as the two machine readable fields agreed it
// would be printed. The sentence is the part a person reads.
func TestValidateRejectsAVerdictSentenceThatDisagreesWithItsLayers(t *testing.T) {
	r := wellFormedReport()
	r.Verdict.Sentence = "Failures in 3 of 8 diagnostic layers."
	requireRejected(t, r, "while the rows beneath it call for")
}

// TestValidateRejectsAReportThatDoesNotSayWhenItWasTaken keeps a report from
// carrying a timestamp from the year one, which reads as a real moment to
// anything that parses it.
func TestValidateRejectsAReportThatDoesNotSayWhenItWasTaken(t *testing.T) {
	r := wellFormedReport()
	r.Run.StartedAt = time.Time{}
	requireRejected(t, r, "when the run started")
}

// TestValidateRejectsAContainerFieldOutsideTheThreeValues covers the one field
// whose invalid value is invisible downstream: anything outside the three
// renders as null, and null is the legitimate way of saying "nothing
// established this". An out of range value would quietly become an answer.
func TestValidateRejectsAContainerFieldOutsideTheThreeValues(t *testing.T) {
	r := wellFormedReport()
	r.Run.Platform.Container = Tristate(7)
	requireRejected(t, r, "not one of the three declared values")
}

// TestValidateRejectsAVerdictThatDisagreesWithItsLayers is the main promise
// enforced at run time rather than only in a test. This is the shape of the
// worst mistake this tool can make.
//
// ONLY THE STATUS IS WRONG HERE, and that is not tidiness. The first version of
// this test broke a layer instead, which put both the status and the exit code
// out of agreement at once - so the exit code check caught it and the status
// check could be deleted with the test still passing. A mutation run found that
// in the first pass. Each of the two checks now has a case that only it can
// catch.
func TestValidateRejectsAVerdictThatDisagreesWithItsLayers(t *testing.T) {
	r := wellFormedReport()
	r.Verdict.Status = status.Pass
	requireRejected(t, r, "while the rows beneath it are worst")
}

// TestValidateRejectsAVerdictWhoseCodeDisagreesWithItsLayers is the other half.
// A report whose exit code says success over rows that could not be assessed
// would end a pipeline green for the one reason this tool exists to report.
func TestValidateRejectsAVerdictWhoseCodeDisagreesWithItsLayers(t *testing.T) {
	r := wellFormedReport()
	r.Verdict.ExitCode = exitcode.OK
	requireRejected(t, r, "call for")
}

// TestValidateRejectsASuccessSentenceOverFailingRows covers the same promise
// from the side a reader would notice: the words, not the machine fields.
func TestValidateRejectsASuccessSentenceOverFailingRows(t *testing.T) {
	r := wellFormedReport()
	r.Layers[0].Status = status.Fail
	r.Layers[0].Reason = status.ReasonUnparseable
	r.Layers[0].Detail = "something failed"
	r.Verdict = Assess(r.Layers)
	r.Verdict.Sentence = everythingPassed
	requireRejected(t, r, "reads as complete success")
}

// TestValidateRejectsAMissingLayerRow pins the ban on silence in its quietest
// form. A layer with no row cannot be told apart from a layer that passed.
func TestValidateRejectsAMissingLayerRow(t *testing.T) {
	r := wellFormedReport()
	r.Layers = r.Layers[:len(r.Layers)-1]
	r.Verdict = Assess(r.Layers)
	requireRejected(t, r, "every layer needs a row")
}

func TestValidateRejectsLayersOutOfReportOrder(t *testing.T) {
	r := wellFormedReport()
	r.Layers[0], r.Layers[1] = r.Layers[1], r.Layers[0]
	requireRejected(t, r, "report order puts")
}

func TestValidateRejectsAProblemWithoutAReason(t *testing.T) {
	r := wellFormedReport()
	r.Layers[2].Reason = ""
	requireRejected(t, r, "without a reason")
}

func TestValidateRejectsAProblemWithoutADetail(t *testing.T) {
	r := wellFormedReport()
	r.Layers[2].Detail = ""
	requireRejected(t, r, "without a detail line")
}

// TestValidateRejectsASuccessCarryingAReason is the other side of the same
// rule. A row that passed and still explains itself means somebody assembled it
// from two different code paths.
func TestValidateRejectsASuccessCarryingAReason(t *testing.T) {
	r := wellFormedReport()
	r.Layers[2].Status = status.Pass
	r.Layers[2].Detail = ""
	r.Verdict = Assess(r.Layers)
	requireRejected(t, r, "passed and still carries the reason")
}

func TestValidateRejectsAReasonOutsideTheClosedList(t *testing.T) {
	r := wellFormedReport()
	r.Layers[1].Reason = status.Reason("because")
	requireRejected(t, r, "outside the closed list")
}

// TestValidateRejectsAMalformedFinding is the union rule checked once more, on
// the assembled report rather than on the answer a layer handed over.
//
// Both checks are needed and they fail differently on purpose. The orchestrator
// catches this first and degrades that one layer. This is what stands there if a
// finding ever reaches a report some other way, and it refuses to print at all -
// which is the right answer for a report nobody can account for.
func TestValidateRejectsAMalformedFinding(t *testing.T) {
	r := wellFormedReport()
	r.Layers[0].Findings = []Finding{{
		Kind:    FindingEnvironmentVariable,
		Summary: "HTTPS_PROXY is set",
		Source:  SourceDetected,
	}}
	requireRejected(t, r, "carries no body of that kind")
}

// TestValidateNamesTheLayerAndThePositionOfABadFinding matters because a layer
// carrying twenty findings is the ordinary case for L0. "One of them is wrong"
// would send a reader through the whole list.
func TestValidateNamesTheLayerAndThePositionOfABadFinding(t *testing.T) {
	r := wellFormedReport()
	sound := Finding{
		Kind:                FindingEnvironmentVariable,
		Summary:             "HTTPS_PROXY is set",
		Source:              SourceDetected,
		EnvironmentVariable: &EnvironmentVariable{Name: "HTTPS_PROXY", Value: "http://proxy:8080", Set: true},
	}
	broken := sound
	broken.Source = Source("guessed")
	r.Layers[1].Findings = []Finding{sound, broken}

	requireRejected(t, r, "layer L1 finding 1")
}

// TestValidateAcceptsALayerThatLookedAndFoundNothing pins the empty list as a
// legitimate answer rather than an oversight. It is the claim "we looked and
// there was nothing", and refusing it would leave a layer no way to say so.
func TestValidateAcceptsALayerThatLookedAndFoundNothing(t *testing.T) {
	r := wellFormedReport()
	r.Layers[0].Findings = []Finding{}

	if err := Validate(r); err != nil {
		t.Fatalf("a layer that looked and found nothing was refused: %v", err)
	}
}

func TestValidateRejectsANoteWithoutADetail(t *testing.T) {
	r := wellFormedReport()
	r.Notes[0].Detail = ""
	requireRejected(t, r, "and not what")
}

func TestValidateRejectsANoteKindOutsideTheClosedList(t *testing.T) {
	r := wellFormedReport()
	r.Notes[0].Kind = NoteKind("fyi")
	requireRejected(t, r, "outside the closed list")
}

// TestValidateRejectsABudgetExceededRunThatDroppedNothing keeps the budget flag
// from becoming decoration. A run that says it ran out of time and lists nothing
// it gave up on is claiming a shortfall without naming it.
func TestValidateRejectsABudgetExceededRunThatDroppedNothing(t *testing.T) {
	r := wellFormedReport()
	r.Run.BudgetExceeded = true
	requireRejected(t, r, "no note says what it dropped")
}

func TestValidateRejectsAPrivilegeLevelOutsideTheSet(t *testing.T) {
	r := wellFormedReport()
	r.Run.PrivilegeLevel = PrivilegeLevel("root")
	requireRejected(t, r, "privilege level")
}

func TestValidateRejectsAReportThatDoesNotSayWhatProducedIt(t *testing.T) {
	r := wellFormedReport()
	r.Tool.Version = ""
	requireRejected(t, r, "tool version")
}

// TestValidateReportsEveryProblemRatherThanTheFirst matters because the caller
// turns this into one internal failure. Stopping at the first violation would
// make fixing a broken report a sequence of runs instead of one reading.
func TestValidateReportsEveryProblemRatherThanTheFirst(t *testing.T) {
	r := wellFormedReport()
	r.Tool.Name = ""
	r.Tool.Version = ""
	r.Run.Target = ""
	r.Notes[0].Detail = ""

	err := Validate(r)
	if err == nil {
		t.Fatal("Validate accepted a report with four separate problems")
	}
	if got := strings.Count(err.Error(), "\n") + 1; got < 4 {
		t.Errorf("Validate reported %d problems, want at least 4:\n%v", got, err)
	}
}
