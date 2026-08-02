package run

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// fakeClock makes the budget testable without waiting for real time. The walk
// is sequential, so no locking is needed here and none is pretended.
type fakeClock struct{ at time.Time }

func (c *fakeClock) now() time.Time          { return c.at }
func (c *fakeClock) advance(d time.Duration) { c.at = c.at.Add(d) }

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

// TestEveryDeclaredLayerGetsARowInRegistryOrder is the ban on silence at the
// level of the whole report. A layer with no row cannot be told apart from a
// layer that passed.
func TestEveryDeclaredLayerGetsARowInRegistryOrder(t *testing.T) {
	r, err := Execute(context.Background(), baseOptions(&fakeClock{}))
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
		r, err := Execute(context.Background(), baseOptions(&fakeClock{}))
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
	r, err := Execute(context.Background(), baseOptions(&fakeClock{}))
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
	r, err := Execute(context.Background(), baseOptions(&fakeClock{}))
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
	o := baseOptions(&fakeClock{})
	delete(o.Layers, layer.TLS)

	if _, err := Execute(context.Background(), o); err == nil {
		t.Fatal("a layer with no function produced a report anyway")
	} else if !strings.Contains(err.Error(), string(layer.TLS)) {
		t.Errorf("the failure does not name the layer: %v", err)
	}
}

func TestAWalkWithNoClockIsALoudFailure(t *testing.T) {
	o := baseOptions(&fakeClock{})
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

	r, err := Execute(ctx, baseOptions(&fakeClock{}))
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
