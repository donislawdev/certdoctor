// Package flow is the window's run of the command line, from the request to
// the answer, without the toolkit (GUI rule 15): what the window asks the
// command line, which screen it is on, and what came of a run - a report to
// draw, or the trouble that stood in the way - so all of it can be read and
// checked without a window.
//
// It knows the document only through model, the request only through request,
// and the command line's exit codes through their frozen table (ADR3) - the
// third contract of the command line the window may name, by the owner's
// decision of 2026-11-09, so that a refusal of the options and a run that
// broke are told apart without a second copy of the codes.
package flow

import (
	"context"
	"time"

	"github.com/donislawdev/certdoctor/internal/gui/request"
)

// Port runs the command line with args and answers what came of it (ADR121
// point 2). The one implementation today starts certdoctor beside the window
// as a child process (cmd/certdoctor-gui/processes.go). An engine run inside
// the window would be a second implementation of this, not a change to the
// screens.
type Port interface {
	Run(ctx context.Context, args []string) Process
}

// Process is what one run left behind.
type Process struct {
	// Program is the path that was run.
	Program string
	// Missing says nothing is at Program.
	Missing bool
	// StartFailed is why the system did not start Program, when something is
	// there and it was not started.
	StartFailed error
	// Out is standard output, at most MaxDocument bytes - and OutTooLong says
	// there was more.
	Out        []byte
	OutTooLong bool
	// Printed is standard error, at most MaxPrinted bytes - and PrintedTooLong
	// says there was more.
	Printed        []byte
	PrintedTooLong bool
	// Code is the exit code, negative when the process was ended by a signal
	// and gave none.
	Code int
	// Stopped is why the run's context ended before the process did: the
	// window's own deadline, or Cancel.
	Stopped error
}

// The most the window keeps of what the command line writes. A report is tens
// of kilobytes - the three in model/testdata are 50 to 60 - so 32 MiB is room
// for a machine with hundreds of stores and still a bound on memory for a
// program beside the window that writes without end. It is the command line's
// own bound on a saved report it reads with --from, declared once with the
// switches, so a report the window drew is one Save report can hand back.
// Standard error carries a sentence, or a stack when something panicked, and
// the window shows its first lines only.
const (
	MaxDocument = request.MaxReport
	MaxPrinted  = 64 << 10
)

// Grace is how long after its own limit a run is left before the window stops
// it. The command line ends its layers within the limit and then only renders
// and writes, so a run still going half a minute later is not going to end -
// and without this a run whose limit was typed as an hour would hold the
// window for ever if the program beside it hung. A judgement, not a
// measurement: the time the command line takes after its limit has not been
// measured.
const Grace = 30 * time.Second

// Phase is the screen the window is on.
type Phase int

// The four screens of a run.
const (
	Starting Phase = iota
	Running
	Reported
	Troubled
)

// Run is one run as the window starts it.
type Run struct {
	// ID tells this run's answer from the answer of one cancelled before it.
	ID   int
	Args []string
	// Deadline is when the window stops the run itself, or zero when the run
	// has no limit.
	Deadline time.Time
}

// Flow is the window's state between runs.
type Flow struct {
	version string
	phase   Phase
	id      int
	began   time.Time
	request request.Request
	outcome Outcome
}

// New is the flow of a window of version, the version a report has to carry
// to be drawn (ADR121 point 1).
func New(version string) *Flow { return &Flow{version: version} }

// Phase is the screen the window is on.
func (f *Flow) Phase() Phase { return f.phase }

// Request is what the last run was asked for.
func (f *Flow) Request() request.Request { return f.request }

// Outcome is what came of the last run that ended.
func (f *Flow) Outcome() Outcome { return f.outcome }

// Limit is the time the running run is drawn against, in seconds - zero for
// no limit.
func (f *Flow) Limit() float64 { return f.request.Limit() }

// Elapsed is the time the running run has taken, in seconds.
func (f *Flow) Elapsed(now time.Time) float64 { return now.Sub(f.began).Seconds() }

// Begin starts a run of r.
func (f *Flow) Begin(r request.Request, now time.Time) Run {
	f.id++
	f.phase, f.began, f.request, f.outcome = Running, now, r, Outcome{}
	run := Run{ID: f.id, Args: r.Args()}
	if limit := r.Limit(); limit > 0 {
		run.Deadline = now.Add(time.Duration(limit*float64(time.Second)) + Grace)
	}
	return run
}

// Again starts the last run again, as it was asked for.
func (f *Flow) Again(now time.Time) Run { return f.Begin(f.request, now) }

// Finish takes the answer of run id. An answer of a run that is no longer the
// one running - cancelled, or followed by another - is dropped, and Finish
// says whether it was taken.
func (f *Flow) Finish(id int, p Process) bool {
	if f.phase != Running || id != f.id {
		return false
	}
	f.outcome = judge(p, f.version, f.request.Limit())
	f.phase = Reported
	if f.outcome.Trouble != nil {
		f.phase = Troubled
	}
	return true
}

// Cancel leaves the running run for the start screen, with the form as it
// was. Its answer, when it comes, is dropped. It says whether there was a run
// to leave.
func (f *Flow) Cancel() bool {
	if f.phase != Running {
		return false
	}
	f.phase = Starting
	return true
}

// Back leaves a report or a trouble for the start screen.
func (f *Flow) Back() {
	if f.phase == Reported || f.phase == Troubled {
		f.phase = Starting
	}
}
