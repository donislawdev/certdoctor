//go:build cgo

package main

import (
	"context"
	"time"

	"fyne.io/fyne/v2"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/screens"
)

// window is the window between runs: the screen it shows and which button
// leads where. Wiring only - the state and its rules are flow's, which knows
// no toolkit and is checked without a window (GUI rule 15).
type window struct {
	w       fyne.Window
	icon    fyne.Resource
	version string
	flow    *flow.Flow
	port    flow.Port
	// wait runs a request beside the toolkit's loop and hands its answer back
	// on the loop - waitFor in the program, a call in place in a test.
	wait func(ctx context.Context, port flow.Port, args []string, done func(flow.Process))
	now  func() time.Time

	// The start screen is built once and shown again, so what was typed in it
	// stays through a run, a report and a trouble (GUI rule 3).
	start fyne.CanvasObject
	form  *screens.StartForm

	// While a run is running: how to end it, the clock that moves its time
	// on the screen, and that screen.
	stop    context.CancelFunc
	clock   *fyne.Animation
	running *screens.RunningView
}

// newWindow wires the window of version into w. software says it is drawn by
// the software renderer shipped beside it (ADR125 point 2).
func newWindow(w fyne.Window, icon fyne.Resource, version string, software bool, port flow.Port) *window {
	win := &window{w: w, icon: icon, version: version, flow: flow.New(version), port: port, wait: waitFor, now: time.Now}
	// The options put away: most runs need only the address, and the fold
	// says in one line what is in it.
	win.start, win.form = screens.Start(icon, version, false, software)
	win.form.Diagnose.OnTapped = win.diagnose
	win.form.Address.OnSubmitted = func(string) { win.diagnose() }
	win.form.Address.OnChanged = func(string) { win.ready() }
	win.ready()
	w.SetOnClosed(win.quiet)
	return win
}

// ready lets Diagnose be pressed only when there is an address to diagnose.
func (win *window) ready() {
	if win.form.Request().Ready() {
		win.form.Diagnose.Enable()
		return
	}
	win.form.Diagnose.Disable()
}

// show puts a screen in the window, held no smaller than the window may be
// made (GUI rule 21).
func (win *window) show(o fyne.CanvasObject) {
	win.w.SetContent(parts.AtLeast(look.WindowMinWidth, look.WindowMinHeight, o))
}

// showStart shows the form as it was left, with the address ready to type in.
func (win *window) showStart() {
	win.show(win.start)
	win.w.Canvas().Focus(win.form.Address)
}

// diagnose starts a run of what the form says, when there is an address and
// no run is running.
func (win *window) diagnose() {
	r := win.form.Request()
	if !r.Ready() || win.flow.Phase() == flow.Running {
		return
	}
	win.begin(win.flow.Begin(r, win.now()))
}

// again runs the last request again, as it was asked for.
func (win *window) again() { win.begin(win.flow.Again(win.now())) }

// begin shows the running screen and hands the run to the command line. The
// run ends at its deadline when it has one: the window's own, after the
// limit and flow.Grace, for a program beside it that does not end.
func (win *window) begin(run flow.Run) {
	ctx, stop := context.WithCancel(context.Background())
	if !run.Deadline.IsZero() {
		ctx, stop = context.WithDeadline(context.Background(), run.Deadline)
	}
	win.stop = stop
	page, view := screens.Running(win.icon, win.version, win.flow.Request().Address)
	view.Cancel.OnTapped = win.cancel
	win.running = view
	win.tick()
	// Ticked by the toolkit from its own loop before each frame, so the clock
	// needs no goroutine of ours (fyne v2.8.2, internal/driver/glfw/loop.go,
	// TickAnimations) - and what it sets changes once a second.
	win.clock = &fyne.Animation{Duration: time.Second, RepeatCount: fyne.AnimationRepeatForever, Tick: func(float32) { win.tick() }}
	win.clock.Start()
	win.show(page)
	win.wait(ctx, win.port, run.Args, func(p flow.Process) { win.finish(run.ID, p) })
}

// tick sets the time the running run has taken.
func (win *window) tick() {
	p := win.flow.Progress(win.now())
	win.running.Show(p.Text, p.Share, p.Bounded)
}

// finish shows what came of run id: its report, or the trouble that stood in
// the way. The answer of a run that is no longer the one running is dropped.
func (win *window) finish(id int, p flow.Process) {
	if !win.flow.Finish(id, p) {
		return
	}
	win.quiet()
	o := win.flow.Outcome()
	if o.Trouble != nil {
		s := o.Trouble.Sentences()
		page, back := screens.Trouble(win.icon, win.version, s.Title, s.What, s.Todo, s.Printed)
		back.OnTapped = win.back
		win.show(page)
		return
	}
	page, act := screens.Report(win.icon, o.Report, o.Open, -1)
	act.New.OnTapped = win.back
	act.Again.OnTapped = win.again
	// Saving goes through the command line (ADR121 (c)), which does not read
	// a saved report yet - so the button says it is not there yet rather than
	// doing nothing when pressed.
	act.Save.Disable()
	win.show(page)
}

// cancel ends the running run and goes back to the form as it was.
func (win *window) cancel() {
	if win.flow.Cancel() {
		win.quiet()
		win.showStart()
	}
}

// back leaves a report or a trouble for the form.
func (win *window) back() {
	win.flow.Back()
	win.showStart()
}

// quiet stops the clock and ends the run's context - which stops the command
// line when it is still running, and releases the deadline when it is not.
// Also what closing the window does, so a run is not left writing into a
// window that is gone.
func (win *window) quiet() {
	if win.clock != nil {
		win.clock.Stop()
		win.clock = nil
	}
	if win.stop != nil {
		win.stop()
		win.stop = nil
	}
}
