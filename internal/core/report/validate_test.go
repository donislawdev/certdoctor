package report

import (
	"strings"
	"testing"

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
