package run

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// fakeClock makes the budget testable without waiting for real time. The walk
// is sequential, so no locking is needed here and none is pretended.
type fakeClock struct{ at time.Time }

func (c *fakeClock) now() time.Time          { return c.at }
func (c *fakeClock) advance(d time.Duration) { c.at = c.at.Add(d) }

// newClock starts at a fixed moment that is deliberately NOT time.Time's zero
// value. The validator refuses a report with no start time, so a fixture built
// on the zero clock would be exercising a shape the product is not allowed to
// produce.
func newClock() *fakeClock {
	return &fakeClock{at: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)}
}

func baseOptions(clock *fakeClock) Options {
	return Options{
		Tool:      report.Tool{Name: "certdoctor", Version: "0.0.0-test"},
		Target:    "https://example.com",
		Platform:  report.Platform{OS: "testos", Arch: "testarch"},
		Privilege: report.PrivilegeUnknown,
		Now:       clock.now,
		Layers:    NotImplemented(),
		Notes: []report.Note{{
			Kind:   report.NoteNotImplemented,
			Detail: "no diagnostic layer is implemented yet",
		}},
	}
}

// TestALayerThatBreaksItsContractDegradesAloneRatherThanEndingTheRun is the
// rule that one probe cannot take the report down with it, checked against the
// shapes a layer can actually get wrong.
//
// This used to be a panic and nothing said so. Folding the statuses asks each
// one for its severity, and severity refuses a value outside the four - so a
// layer returning a zero Answer ended the run with no report at all. Seven
// working layers, the verdict and every note were thrown away because the
// eighth forgot a field, and the process exited claiming certdoctor itself had
// broken.
func TestALayerThatBreaksItsContractDegradesAloneRatherThanEndingTheRun(t *testing.T) {
	breaches := []struct {
		name   string
		answer Answer
	}{
		{"nothing filled in at all", Answer{}},
		{"a status outside the vocabulary", Answer{Status: status.Status("BROKEN"), Reason: status.ReasonTimeout, Detail: "x"}},
		{"a problem with a reason outside the closed list", Answer{Status: status.Fail, Reason: status.Reason("made_up"), Detail: "x"}},
		{"a pass still carrying a reason", Answer{Status: status.Pass, Reason: status.ReasonTimeout}},
		{"a problem with no detail line", Answer{Status: status.Fail, Reason: status.ReasonTimeout}},
		// A finding is checked here rather than only in the report validator, and
		// that is the difference between losing one layer and losing the run: a
		// malformed finding reaching the validator fails the whole report, so the
		// process ends with an internal error and prints nothing at all.
		{"a finding with no body", Answer{
			Status: status.Pass,
			Findings: []report.Finding{{
				Kind:    report.FindingEnvironmentVariable,
				Summary: "HTTPS_PROXY is set",
				Source:  report.SourceDetected,
			}},
		}},
		{"a finding that does not say how strongly it is known", Answer{
			Status: status.Pass,
			Findings: []report.Finding{{
				Kind:                report.FindingEnvironmentVariable,
				Summary:             "HTTPS_PROXY is set",
				EnvironmentVariable: &report.EnvironmentVariable{Name: "HTTPS_PROXY", Set: true},
			}},
		}},
	}

	for _, breach := range breaches {
		o := baseOptions(newClock())
		o.Layers[layer.TLS] = func(context.Context) Answer { return breach.answer }

		r, err := Execute(context.Background(), o)
		if err != nil {
			t.Fatalf("%s: one broken layer ended the whole walk: %v", breach.name, err)
		}
		if err := report.Validate(r); err != nil {
			t.Fatalf("%s: the resulting report is not valid:\n%v", breach.name, err)
		}
		if len(r.Layers) != len(layer.All) {
			t.Errorf("%s: %d rows, want %d", breach.name, len(r.Layers), len(layer.All))
		}

		broken := rowFor(t, r, layer.TLS)
		if broken.Status != status.Unknown || broken.Reason != status.ReasonProbeError {
			t.Errorf("%s: the broken layer reads %s/%s, want unknown with a probe error",
				breach.name, broken.Status, broken.Reason)
		}
		// The layers either side of it are untouched, which is the whole point.
		if intact := rowFor(t, r, layer.TCP); intact.Detail != notImplementedDetail {
			t.Errorf("%s: a working layer was disturbed: %+v", breach.name, intact)
		}
		if !noteNames(r.Notes, layer.TLS) {
			t.Errorf("%s: the layer was degraded and no note says which one or why", breach.name)
		}
	}
}

func rowFor(t *testing.T, r report.Report, id layer.ID) report.LayerResult {
	t.Helper()
	for _, row := range r.Layers {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("no row for layer %s", id)
	return report.LayerResult{}
}

func noteNames(notes []report.Note, id layer.ID) bool {
	for _, note := range notes {
		if note.Kind == report.NoteDegraded && note.Layer == id {
			return true
		}
	}
	return false
}

// TestEveryDeclaredLayerGetsARowInRegistryOrder is the ban on silence at the
// level of the whole report. A layer with no row cannot be told apart from a
// layer that passed.
func TestEveryDeclaredLayerGetsARowInRegistryOrder(t *testing.T) {
	r, err := Execute(context.Background(), baseOptions(newClock()))
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if len(r.Layers) != len(layer.All) {
		t.Fatalf("the report has %d rows, there are %d declared layers", len(r.Layers), len(layer.All))
	}
	for i, want := range layer.All {
		if r.Layers[i].ID != want {
			t.Errorf("row %d is %s, report order puts %s there", i, r.Layers[i].ID, want)
		}
	}
}

// TestTheRowOrderComesFromTheRegistryAndNotFromTheMap is the guard against the
// one defect a single run cannot show: iteration over a Go map is randomised, so
// a walk that ranged over Layers would reorder the report between runs of the
// same input and every single-comparison test would still pass.
func TestTheRowOrderComesFromTheRegistryAndNotFromTheMap(t *testing.T) {
	var first []layer.ID
	for attempt := 0; attempt < 20; attempt++ {
		r, err := Execute(context.Background(), baseOptions(newClock()))
		if err != nil {
			t.Fatalf("the walk failed: %v", err)
		}
		order := make([]layer.ID, 0, len(r.Layers))
		for _, row := range r.Layers {
			order = append(order, row.ID)
		}
		if first == nil {
			first = order
			continue
		}
		for i := range order {
			if order[i] != first[i] {
				t.Fatalf("run %d ordered the rows %v, the first run ordered them %v", attempt, order, first)
			}
		}
	}
}

// TestTheSkeletonIsHonestAboutItself is the pair from the plan: every layer
// unknown with a reason, the settled verdict, and the code that means "could not
// assess".
func TestTheSkeletonIsHonestAboutItself(t *testing.T) {
	r, err := Execute(context.Background(), baseOptions(newClock()))
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	for _, row := range r.Layers {
		if row.Status != status.Unknown {
			t.Errorf("layer %s reported %s before anything was implemented", row.ID, row.Status)
		}
		if row.Reason != status.ReasonProbeError {
			t.Errorf("layer %s reported reason %q, want %q", row.ID, row.Reason, status.ReasonProbeError)
		}
		if row.Detail != notImplementedDetail {
			t.Errorf("layer %s said %q, want %q", row.ID, row.Detail, notImplementedDetail)
		}
	}
	if r.Verdict.ExitCode != exitcode.Inconclusive {
		t.Errorf("the run ended with %s, want INCONCLUSIVE", r.Verdict.ExitCode.Name())
	}
	if r.Verdict.Sentence != "Nothing could be assessed yet." {
		t.Errorf("the verdict reads %q", r.Verdict.Sentence)
	}
}

// TestTheAssembledReportPassesValidation ties the walk to the invariants. If the
// orchestrator ever assembles something the core would refuse, this is where it
// shows up rather than in front of a user.
func TestTheAssembledReportPassesValidation(t *testing.T) {
	r, err := Execute(context.Background(), baseOptions(newClock()))
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if err := report.Validate(r); err != nil {
		t.Fatalf("the walk assembled a report the core refuses:\n%v", err)
	}
}

// TestAMissingLayerFunctionIsALoudFailure covers the defect that would
// otherwise produce a report with a hole in it.
func TestAMissingLayerFunctionIsALoudFailure(t *testing.T) {
	o := baseOptions(newClock())
	delete(o.Layers, layer.TLS)

	if _, err := Execute(context.Background(), o); err == nil {
		t.Fatal("a layer with no function produced a report anyway")
	} else if !strings.Contains(err.Error(), string(layer.TLS)) {
		t.Errorf("the failure does not name the layer: %v", err)
	}
}

func TestAWalkWithNoClockIsALoudFailure(t *testing.T) {
	o := baseOptions(newClock())
	o.Now = nil
	if _, err := Execute(context.Background(), o); err == nil {
		t.Fatal("a walk with no clock produced a report anyway")
	}
}

// TestACancelledRunProducesNoReport pins the teardown state. An interrupted run
// must not hand back something that looks complete.
func TestACancelledRunProducesNoReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r, err := Execute(ctx, baseOptions(newClock()))
	if err == nil {
		t.Fatal("a cancelled run returned a report")
	}
	if len(r.Layers) != 0 {
		t.Errorf("a cancelled run returned %d rows alongside its error", len(r.Layers))
	}
}

// TestTheWalkDoesNotWriteIntoTheCallersBackingArray keeps the walk from
// scribbling on memory it was only lent.
//
// THE OBVIOUS VERSION OF THIS TEST DOES NOT WORK, and a mutation run is what
// showed it. Comparing the caller's slice length before and after passes
// whether or not the walk copies, because appending to a copy of a slice header
// cannot change the original's length. The hazard is the other one: a slice
// handed in with spare capacity has its unused elements overwritten, and the
// caller who reuses that array gets someone else's notes in it.
//
// So the caller here deliberately passes room to spare, and the check is that
// the room is still empty afterwards.
func TestTheWalkDoesNotWriteIntoTheCallersBackingArray(t *testing.T) {
	clock := &fakeClock{at: time.Unix(0, 0)}
	o := baseOptions(clock)
	o.Budget = 10 * time.Second
	o.Layers = spendingLayers(clock, 4*time.Second)

	lent := make([]report.Note, 1, 16)
	lent[0] = report.Note{Kind: report.NoteNotImplemented, Detail: "no diagnostic layer is implemented yet"}
	o.Notes = lent

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if len(r.Notes) <= len(lent) {
		t.Fatalf("the walk appended nothing, so this test would pass while checking nothing")
	}

	spare := lent[:cap(lent)]
	for i := len(lent); i < len(spare); i++ {
		if spare[i].Kind != "" || spare[i].Detail != "" {
			t.Fatalf("the walk wrote %+v into the caller's spare capacity at index %d", spare[i], i)
		}
	}
}

// TestALayerThatNeverLookedIsNotTurnedIntoOneThatFoundNothing is the one
// property of the findings list that a length comparison cannot see.
//
// Nil and a slice of length zero are two different claims - "nobody looked" and
// "we looked and there was nothing" - and the ordinary way of copying a slice
// turns the first into the second. Every layer that is not written yet hands
// back nil, so getting this wrong would put a false claim under seven rows of
// every report this build produces, and every test counting findings would still
// pass.
func TestALayerThatNeverLookedIsNotTurnedIntoOneThatFoundNothing(t *testing.T) {
	o := baseOptions(newClock())
	o.Layers[layer.Context] = func(context.Context) Answer {
		return Answer{Status: status.Pass, Findings: []report.Finding{}}
	}

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if looked := rowFor(t, r, layer.Context); looked.Findings == nil {
		t.Error("a layer that looked and found nothing came back as one that never looked")
	}
	if never := rowFor(t, r, layer.TCP); never.Findings != nil {
		t.Errorf("a layer that never looked came back claiming it found nothing: %#v", never.Findings)
	}
}

// TestTheWalkDoesNotHandBackTheLayersOwnFindings keeps the assembly path from
// rewriting a slice the layer still holds.
//
// It costs nothing today and it is the reason masking can rewrite these values
// in place tomorrow: masking runs here, after the layers have answered, and a
// layer that kept its own slice would find its evidence altered underneath it.
func TestTheWalkDoesNotHandBackTheLayersOwnFindings(t *testing.T) {
	kept := []report.Finding{{
		Kind:                report.FindingEnvironmentVariable,
		Summary:             "HTTPS_PROXY is set",
		Source:              report.SourceDetected,
		EnvironmentVariable: &report.EnvironmentVariable{Name: "HTTPS_PROXY", Value: "http://proxy:8080", Set: true},
	}}

	o := baseOptions(newClock())
	o.Layers[layer.Context] = func(context.Context) Answer {
		return Answer{Status: status.Pass, Findings: kept}
	}

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}

	row := rowFor(t, r, layer.Context)
	if len(row.Findings) != 1 {
		t.Fatalf("the finding did not survive the walk: %#v", row.Findings)
	}
	row.Findings[0].Summary = "rewritten on the assembly path"
	if kept[0].Summary != "HTTPS_PROXY is set" {
		t.Error("the report and the layer share one array, so masking the report would alter the layer's evidence")
	}
}

// spendingLayers answers like the skeleton does but moves the clock forward,
// so the budget can be exhausted without waiting.
func spendingLayers(clock *fakeClock, cost time.Duration) Layers {
	layers := make(Layers, len(layer.All))
	for _, id := range layer.All {
		layers[id] = func(context.Context) Answer {
			clock.advance(cost)
			return Answer{Status: status.Pass}
		}
	}
	return layers
}

// TestTheRunStopsAtItsDeadline is the budget guard. A run that quietly kept
// going would be the one thing worse than a run that gave up: the user walked
// away at sixty seconds either way, and only one of the two says so.
func TestTheRunStopsAtItsDeadline(t *testing.T) {
	clock := &fakeClock{at: time.Unix(0, 0)}
	o := baseOptions(clock)
	o.Budget = 10 * time.Second
	o.Layers = spendingLayers(clock, 4*time.Second)

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if !r.Run.BudgetExceeded {
		t.Fatal("the run spent more than its budget and does not say so")
	}
	if len(r.Layers) != len(layer.All) {
		t.Fatalf("the run dropped %d rows instead of reporting them as skipped", len(layer.All)-len(r.Layers))
	}

	skipped := 0
	for _, row := range r.Layers {
		if row.Reason == status.ReasonSkippedBudget {
			skipped++
			if row.Status != status.Unknown {
				t.Errorf("layer %s was skipped and reports %s", row.ID, row.Status)
			}
		}
	}
	if skipped == 0 {
		t.Fatal("the budget was exhausted and no layer says it was skipped")
	}
	if noted := countNotes(r.Notes, report.NoteSkipped); noted != skipped {
		t.Errorf("%d layers were skipped and %d notes say so", skipped, noted)
	}
	if err := report.Validate(r); err != nil {
		t.Fatalf("the report of an exhausted run does not validate:\n%v", err)
	}
}

// TestAnUnlimitedBudgetSkipsNothing is the other side of the same guard. A
// budget of zero documents itself as "no limit", and a walk that treated it as
// "no time at all" would skip every layer while looking like it ran.
func TestAnUnlimitedBudgetSkipsNothing(t *testing.T) {
	clock := &fakeClock{at: time.Unix(0, 0)}
	o := baseOptions(clock)
	o.Budget = 0
	o.Layers = spendingLayers(clock, time.Hour)

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if r.Run.BudgetExceeded {
		t.Error("a run with no budget reported that it exceeded one")
	}
	if noted := countNotes(r.Notes, report.NoteSkipped); noted != 0 {
		t.Errorf("a run with no budget skipped %d layers", noted)
	}
}

func countNotes(notes []report.Note, kind report.NoteKind) int {
	n := 0
	for _, note := range notes {
		if note.Kind == kind {
			n++
		}
	}
	return n
}

// TestEffectiveLimitTakesTheTighterDeadline is the budget arithmetic on its own.
// Driving it through a real clock would test it loosely, and this is the
// calculation that decides whether a layer can spend the run's remaining time.
func TestEffectiveLimitTakesTheTighterDeadline(t *testing.T) {
	const unlimited = -1 * time.Nanosecond

	cases := []struct {
		name        string
		layerBudget time.Duration
		remaining   time.Duration
		want        time.Duration
	}{
		{"layer budget is tighter", 2 * time.Second, 9 * time.Second, 2 * time.Second},
		{"what is left is tighter", 9 * time.Second, 2 * time.Second, 2 * time.Second},
		{"equal", 5 * time.Second, 5 * time.Second, 5 * time.Second},
		{"no overall budget", 3 * time.Second, unlimited, 3 * time.Second},
		{"no layer budget", 0, 4 * time.Second, 4 * time.Second},
		{"neither budget", 0, unlimited, 0},
		{"nothing left", 3 * time.Second, 0, 0},
	}
	for _, c := range cases {
		if got := effectiveLimit(c.layerBudget, c.remaining); got != c.want {
			t.Errorf("%s: layer %s with %s left gave %s, want %s", c.name, c.layerBudget, c.remaining, got, c.want)
		}
	}
}

// TestALayerReceivesTheDeadlineItWasGiven checks the arithmetic is actually
// wired to the context, not only computed. The tolerance is wide because the
// deadline is set from the real clock while the budget is measured on the fake
// one - the assertion is which of the two budgets won, not how many
// milliseconds elapsed.
func TestALayerReceivesTheDeadlineItWasGiven(t *testing.T) {
	clock := &fakeClock{at: time.Unix(0, 0)}
	o := baseOptions(clock)
	o.Budget = 2 * time.Second
	o.LayerBudget = time.Hour

	var seen []time.Duration
	layers := make(Layers, len(layer.All))
	for _, id := range layer.All {
		layers[id] = func(ctx context.Context) Answer {
			if deadline, ok := ctx.Deadline(); ok {
				seen = append(seen, time.Until(deadline))
			}
			return Answer{Status: status.Pass}
		}
	}
	o.Layers = layers

	if _, err := Execute(context.Background(), o); err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if len(seen) != len(layer.All) {
		t.Fatalf("%d of %d layers received a deadline", len(seen), len(layer.All))
	}
	for i, d := range seen {
		if d > 10*time.Minute {
			t.Errorf("layer %d was given %s, so the hour long layer budget beat the two second run budget", i, d)
		}
	}
}

// proxyFinding is a layer answer carrying the shape this whole slice exists for:
// an environment variable whose ordinary corporate value holds a password.
func proxyFinding(value string) Answer {
	return Answer{
		Status: status.Pass,
		Findings: []report.Finding{{
			Kind:    report.FindingEnvironmentVariable,
			Summary: "HTTPS_PROXY is set",
			Source:  report.SourceDetected,
			EnvironmentVariable: &report.EnvironmentVariable{
				Name:  "HTTPS_PROXY",
				Value: value,
				Set:   true,
			},
		}},
	}
}

// TestTheOrchestratorMasksTheEvidenceALayerHandsBack is the promise that
// credentials never reach a report, finally enforced rather than merely
// available.
//
// The masking function has existed with a full set of property tests and two
// fuzz targets since before any layer could produce a thing to mask, and for all
// that time NOTHING CALLED IT. This is the test that makes the difference
// between "the tool exists" and "the rule is enforced".
//
// The options carry no redaction at all, on purpose: a forgotten assignment has
// to mask less, never nothing.
func TestTheOrchestratorMasksTheEvidenceALayerHandsBack(t *testing.T) {
	o := baseOptions(newClock())
	if o.Redaction != nil {
		t.Fatal("this test is meant to run with no redaction supplied")
	}
	o.Layers[layer.Context] = func(context.Context) Answer {
		return proxyFinding("http://user:hunter2@proxy.corp:8080")
	}

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}

	row := rowFor(t, r, layer.Context)
	if len(row.Findings) != 1 {
		t.Fatalf("the finding did not survive the walk: %#v", row.Findings)
	}
	variable := row.Findings[0].EnvironmentVariable
	if strings.Contains(variable.Value, "hunter2") {
		t.Errorf("a password reached the report: %q", variable.Value)
	}
	if !variable.CarriedCredentials {
		t.Error("a credential was removed and the finding does not record that there was one")
	}
	// The floor removes credentials and leaves names alone, so the host stays.
	// Without this the test would also pass against a redaction that deleted
	// everything, which is not the behaviour anybody wants.
	if !strings.Contains(variable.Value, "proxy.corp") {
		t.Errorf("the host was removed under the floor mode: %q", variable.Value)
	}
	if r.Run.Redacted {
		t.Error("the report claims names were masked and no stronger mode was asked for")
	}
}

// TestTheStrongerModeReachesTheEvidenceAndIsAnnounced is the other half. The
// flag in the report has to describe what actually happened to the evidence,
// because the two are read together by whoever compares two reports.
func TestTheStrongerModeReachesTheEvidenceAndIsAnnounced(t *testing.T) {
	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Everything)
	o.Layers[layer.Context] = func(context.Context) Answer {
		return proxyFinding("http://proxy.corp:8080")
	}

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}

	variable := rowFor(t, r, layer.Context).Findings[0].EnvironmentVariable
	if strings.Contains(variable.Value, "proxy.corp") {
		t.Errorf("the stronger mode did not reach the evidence: %q", variable.Value)
	}
	if variable.CarriedCredentials {
		t.Error("pseudonymising a host was recorded as removing a credential")
	}
	if !r.Run.Redacted {
		t.Error("names were masked and the report does not say so")
	}
}

// TestALayerKeepsTheEvidenceItHandedOver closes the defect that copying the
// findings slice does NOT close.
//
// Copying a slice copies the pointers in it, so the body a layer handed over is
// the same object the report holds. Masking through that pointer rewrites the
// layer's own evidence underneath it. It is harmless while every layer is
// stateless and it is a defect the moment one is not - and by then it would look
// like the masking was wrong rather than the aliasing.
func TestALayerKeepsTheEvidenceItHandedOver(t *testing.T) {
	const raw = "http://user:hunter2@proxy.corp:8080"
	answer := proxyFinding(raw)

	o := baseOptions(newClock())
	o.Layers[layer.Context] = func(context.Context) Answer { return answer }

	if _, err := Execute(context.Background(), o); err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if got := answer.Findings[0].EnvironmentVariable.Value; got != raw {
		t.Errorf("the assembly path rewrote the layer's own evidence: %q", got)
	}
}

// TestMaskingReachesTheDetailLineAndTheNotes covers the two pieces of free text
// that are not findings. Neither carries evidence today, and the first one that
// quotes a host will be written by somebody who is not thinking about masking.
func TestMaskingReachesTheDetailLineAndTheNotes(t *testing.T) {
	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Everything)
	o.Notes = []report.Note{{
		Kind:   report.NoteNotImplemented,
		Detail: "nothing reads https://proxy.corp:8080 yet",
	}}
	o.Layers[layer.Context] = func(context.Context) Answer {
		return Answer{
			Status: status.Warn,
			Reason: status.ReasonAccessDenied,
			Detail: "could not read https://proxy.corp:8080",
		}
	}

	r, err := Execute(context.Background(), o)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if detail := rowFor(t, r, layer.Context).Detail; strings.Contains(detail, "proxy.corp") {
		t.Errorf("a host survived in a detail line: %q", detail)
	}
	if strings.Contains(r.Notes[0].Detail, "proxy.corp") {
		t.Errorf("a host survived in a note: %q", r.Notes[0].Detail)
	}
}

// TestMaskingAFindingWithNoEnvironmentBodyDoesNotReachIntoIt covers a branch
// that CANNOT be reached through Execute today, and says why it is there.
//
// A finding of the one declared kind must carry its body - the orchestrator
// refuses it otherwise, before masking ever sees it. So this guard is for the
// second kind: a certificate finding in L4 will have no environment variable in
// it, and without the check masking would dereference nil and take the whole run
// down. Reaching it needs the function called directly, which is why this test
// does that rather than pretending a walk could produce it.
func TestMaskingAFindingWithNoEnvironmentBodyDoesNotReachIntoIt(t *testing.T) {
	o := baseOptions(newClock())
	o.Redaction = redact.New(redact.Credentials)

	finding := report.Finding{
		Kind:    report.FindingKind("certificate"),
		Summary: "the chain was signed by a CA local to https://proxy.corp:8080",
		Source:  report.SourceDetected,
	}
	o.maskFinding(&finding)

	if finding.EnvironmentVariable != nil {
		t.Error("masking invented a body for a finding that had none")
	}
	// The envelope is still masked, because the summary is what every surface
	// renders without knowing the kind.
	if strings.Contains(finding.Summary, "proxy.corp") && o.Redaction.Mode() == redact.Everything {
		t.Errorf("the summary was left unmasked: %q", finding.Summary)
	}
}
