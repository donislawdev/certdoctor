//go:build cgo

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// held is a port that keeps each run it is handed, so a test answers it when
// it chooses - or never, for a run that is cancelled.
type held struct {
	runs []heldRun
}

type heldRun struct {
	ctx  context.Context
	args []string
	done func(flow.Process)
}

func (h *held) wait(ctx context.Context, _ flow.Port, args []string, done func(flow.Process)) {
	h.runs = append(h.runs, heldRun{ctx, args, done})
}

func (h *held) Run(context.Context, []string) flow.Process { return flow.Process{} }

// testWindow is the window wired over a held port, with a clock the test moves.
func testWindow(t *testing.T) (*window, *held, *time.Time) {
	t.Helper()
	a := test.NewTempApp(t)
	a.Settings().SetTheme(look.Theme())
	w := test.NewTempWindow(t, nil)
	h := &held{}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	win := newWindow(w, nil, "0.1.0", false, h)
	win.wait = h.wait
	win.now = func() time.Time { return now }
	win.showStart()
	return win, h, &now
}

// exampleReport is the example.com report of model's test data - 0.1.0,
// schema 2.4, exit code 4, a verdict about L5.
func exampleReport(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "gui", "model", "testdata", "example-com.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDiagnoseWaitsForAnAddress - the one primary action cannot start a run
// with nothing to diagnose, by the button or by Enter.
func TestDiagnoseWaitsForAnAddress(t *testing.T) {
	win, h, _ := testWindow(t)
	if !win.form.Diagnose.Disabled() {
		t.Error("Diagnose can be pressed with no address")
	}
	win.form.Address.OnSubmitted("")
	win.diagnose()
	if len(h.runs) != 0 {
		t.Fatalf("%d run(s) started with no address", len(h.runs))
	}
	test.Type(win.form.Address, "example.com")
	if win.form.Diagnose.Disabled() {
		t.Error("Diagnose cannot be pressed with an address typed")
	}
	win.form.Address.SetText("  ")
	if !win.form.Diagnose.Disabled() {
		t.Error("Diagnose can be pressed with only space typed")
	}
}

// TestARunGoesFromTheFormToItsReportAndBack drives the window the way a
// person does: type, press Diagnose, see the time, get the report, run it
// again, and go back to the form with what was typed still there.
func TestARunGoesFromTheFormToItsReportAndBack(t *testing.T) {
	win, h, now := testWindow(t)
	if win.form.Options.Open() {
		t.Error("the window opens with the options out - most runs need only the address")
	}
	win.form.Options.Tapped(nil)
	win.form.Address.SetText("https://example.com")
	win.form.Address.OnSubmitted("https://example.com")
	if len(h.runs) != 1 || win.flow.Phase() != flow.Running {
		t.Fatalf("Enter in the address started %d run(s), the window is on %d", len(h.runs), win.flow.Phase())
	}
	if want := []string{"--json", "--", "https://example.com"}; !slices.Equal(h.runs[0].args, want) {
		t.Errorf("the run was asked %q, want %q", h.runs[0].args, want)
	}
	if deadline, ok := h.runs[0].ctx.Deadline(); !ok || !deadline.Equal(now.Add(60*time.Second+flow.Grace)) {
		t.Errorf("a run with the default limit ends at %v (%v)", deadline, ok)
	}
	win.form.Diagnose.OnTapped()
	if len(h.runs) != 1 {
		t.Fatal("a second run started while one was running")
	}
	*now = now.Add(12 * time.Second)
	win.tick()
	if got := win.running.Words(); got != "12 s of the 60 s limit" {
		t.Errorf("the running screen says %q", got)
	}

	h.runs[0].done(flow.Process{Out: exampleReport(t), Code: 4})
	if win.flow.Phase() != flow.Reported || win.clock != nil || h.runs[0].ctx.Err() == nil {
		t.Fatalf("the answer left the window on %d, the clock %v, the run's context %v", win.flow.Phase(), win.clock, h.runs[0].ctx.Err())
	}
	if o := win.flow.Outcome(); o.Open != 5 {
		t.Errorf("the report opens on layer %d, want L5 - the one its verdict is about", o.Open)
	}

	win.again()
	if len(h.runs) != 2 || !slices.Equal(h.runs[1].args, h.runs[0].args) || win.flow.Phase() != flow.Running {
		t.Fatalf("Run again started %d run(s) with %q", len(h.runs), h.runs[len(h.runs)-1].args)
	}
	h.runs[1].done(flow.Process{Code: 2, Printed: []byte("certdoctor: not a URL")})
	if win.flow.Phase() != flow.Troubled {
		t.Fatalf("a refusal left the window on %d", win.flow.Phase())
	}
	win.back()
	if win.flow.Phase() != flow.Starting || win.form.Address.Text != "https://example.com" || !win.form.Options.Open() {
		t.Errorf("Back is on %d with the address %q, options open %v - the form has to be as it was left",
			win.flow.Phase(), win.form.Address.Text, win.form.Options.Open())
	}
}

// TestCancelLeavesTheRunAndDropsItsAnswer - Cancel ends the run's context,
// goes back to the form, and the answer that comes after is not drawn.
func TestCancelLeavesTheRunAndDropsItsAnswer(t *testing.T) {
	win, h, _ := testWindow(t)
	win.form.Address.SetText("https://example.com")
	win.diagnose()
	if got := win.running.Words(); got != "0 s of the 60 s limit" {
		t.Errorf("a run that has just begun says %q", got)
	}
	win.running.Cancel.OnTapped()
	if win.flow.Phase() != flow.Starting || h.runs[0].ctx.Err() == nil || win.clock != nil {
		t.Fatalf("Cancel left the window on %d with the run's context %v", win.flow.Phase(), h.runs[0].ctx.Err())
	}
	h.runs[0].done(flow.Process{Out: exampleReport(t), Code: 4})
	if win.flow.Phase() != flow.Starting {
		t.Errorf("the answer of a cancelled run was drawn: the window is on %d", win.flow.Phase())
	}
	win.cancel()
	if win.flow.Phase() != flow.Starting {
		t.Error("Cancel with no run running moved the window")
	}
}

// TestClosingTheWindowEndsTheRun - a run left going would write into a window
// that is gone.
//
// On a window the test closes itself: the toolkit's temporary test window is
// closed again when the test ends, and closing a test window twice panics in
// the toolkit's test driver.
func TestClosingTheWindowEndsTheRun(t *testing.T) {
	test.NewTempApp(t)
	h := &held{}
	win := newWindow(test.NewWindow(nil), nil, "0.1.0", false, h)
	win.wait = h.wait
	win.form.Address.SetText("https://example.com")
	win.diagnose()
	win.w.Close()
	if h.runs[0].ctx.Err() == nil || win.clock != nil {
		t.Errorf("closing the window left the run's context %v and the clock %v", h.runs[0].ctx.Err(), win.clock)
	}
}

// TestTheContentStaysNoSmallerThanTheWindowMayBe - every screen is shown held
// at the smallest size the window may be made (GUI rule 21).
func TestTheContentStaysNoSmallerThanTheWindowMayBe(t *testing.T) {
	win, _, _ := testWindow(t)
	if min := win.w.Content().MinSize(); min.Width < look.WindowMinWidth || min.Height < look.WindowMinHeight {
		t.Errorf("the start screen may be made %v", min)
	}
	win.form.Address.SetText("https://example.com")
	win.diagnose()
	if min := win.w.Content().MinSize(); min.Width < look.WindowMinWidth || min.Height < look.WindowMinHeight {
		t.Errorf("the running screen may be made %v", min)
	}
}
