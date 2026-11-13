//go:build cgo

package main

import (
	"runtime/metrics"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
)

// Giving memory back once the window is left alone (ADR145).
//
// # Why there is anything to give back
//
// Measured in the real window on 2026-11-12: 84 MB of private memory at the
// start, 250 MB after work with a tool, and the same 250 MB after ninety
// seconds of nobody touching it. Two things hold it, and neither is ours to
// change:
//
//   - The toolkit destroys the renderer of an object that left the window a
//     minute ago only in the clean that follows a painted frame (fyne v2.8.2,
//     internal/cache/base.go Clean, called by drawSingleFrame in
//     internal/driver/glfw/loop.go). A window nobody touches paints nothing,
//     so they stay.
//   - Go keeps the pages a collection has freed, up to about twice what is
//     alive, and gives them back slowly.
//
// # How the window knows it is left alone
//
// By what it allocates rather than by what its screens report, so a screen
// added years from now is covered the day it exists, with nothing to remember.
// A run is covered the same way: its screen moves the bar on every frame. A
// field holding the keyboard counts as use too - its caret fades in and out,
// and the toolkit repaints the whole window on every frame of the fade
// (widget/entry_cursor_anim.go) - until the person goes to another program,
// which takes the keyboard and stops the caret. Those frames let the
// renderers go anyway, so what stays then is only what Go holds.
//
// # What happens, in order
//
// Once a whole tidyQuiet has gone by with under tidyBudget allocated, one frame
// is asked for, by marking for redrawing an object that is not in the window:
// nothing in it is touched. Redrawing the root instead walks every object the
// window has, hidden ones included, and makes renderers for widgets that had
// none (internal/driver/common/canvas.go, freeObject) - and measured on this
// toolkit version against the root, an object outside the window left the
// same renderers and gave back the same memory. tidySettle later the memory
// goes back, off the window's thread (releaseBeside). Then the window waits to
// be used again, so one left open for a day is tidied once.
//
// # Why the clock needs no goroutine
//
// The toolkit's loop ticks every animation sixty times a second whether or not
// anything is drawn (loop.go, TickAnimations), the way it ticks the running
// screen's clock. So the wait for quiet is an animation that never ends, on the
// window's own thread, and the frame it asks for needs no fyne.Do. A tick reads
// the clock and, once in tidyLook, one counter of the runtime: neither
// allocates nor marks anything for drawing.
//
// # What it does not do
//
// A minimised window paints no frames either, so there the renderers stay and
// only what Go holds goes back. Memory the toolkit keeps for good - parsed
// fonts, textures still drawn - is not released by any of this.

const (
	// tidyLook is how often the counter is read.
	tidyLook = 5 * time.Second
	// tidyQuiet is how long nothing has to happen. Past the minute the toolkit
	// keeps a renderer (cache.ValidDuration), so the renderers that left the
	// window with the last change have expired by the frame.
	tidyQuiet = 70 * time.Second
	// tidySettle is how long after the frame the memory goes back. The toolkit
	// cleans at most once in ten seconds, and a clean refused for coming too
	// soon is carried to the next one, at most ten seconds later.
	tidySettle = 12 * time.Second
	// tidyBudget is what the window may allocate across a whole quiet and
	// still be quiet. Measured on this toolkit version in another window: left
	// alone, at most 0.3 MB in any seventy seconds, the toolkit's own sparse
	// jumps included, and a fading caret 18 MB or more - neither near it.
	//
	// Counted over the quiet rather than per look, because a release allocates
	// 0.5 to 0.8 MB itself and a per-look budget took that for somebody using
	// the window, tidying every ninety seconds for as long as it stood alone.
	// Over the quiet, a trickle never adds up to use however long it goes on.
	tidyBudget = 2 << 20
)

// step is what one look asks of the window.
type step int

const (
	stepNothing step = iota
	// stepFrame asks the toolkit for one frame.
	stepFrame
	// stepRelease gives the memory back.
	stepRelease
)

// reading is one look: when, and every byte allocated so far.
type reading struct {
	at        time.Time
	allocated uint64
}

// tidy is the one quiet being waited out, for the whole window. It is only
// ever reached from the window's thread, through the clock below.
type tidy struct {
	// quiet is the looks since the quiet began, oldest first, trimmed to the
	// last tidyQuiet and the one look before it, so that the first and the
	// last span the whole of it.
	quiet []reading
	// used says something has happened since the memory last went back.
	used bool
	// framed is when the frame was asked for, and zero while none is.
	framed time.Time
	// settling says the last look gave the memory back, so what the next one
	// sees allocated is the release's own.
	settling bool
}

// newTidy begins with the window just built, which is the most it ever
// allocates at once, so it begins used.
func newTidy(allocated uint64, now time.Time) *tidy {
	return &tidy{quiet: []reading{{at: now, allocated: allocated}}, used: true}
}

// look reads every byte allocated so far at now and answers with what the
// window should do.
func (t *tidy) look(allocated uint64, now time.Time) step {
	here := reading{at: now, allocated: allocated}
	if !t.framed.IsZero() {
		return t.settle(now)
	}
	if t.settling {
		// The release collects, and what it lets go of allocates on its way
		// out. The quiet starts after that, from here.
		t.settling = false
		t.quiet = append(t.quiet[:0], here)
		return stepNothing
	}
	began := t.since(here)
	if allocated-began.allocated >= tidyBudget {
		t.used = true
		t.quiet = append(t.quiet[:0], here)
		return stepNothing
	}
	if t.used && now.Sub(began.at) >= tidyQuiet {
		t.framed = now
		return stepFrame
	}
	return stepNothing
}

// settle waits tidySettle out after the frame, and then gives the memory back.
// What is allocated in between is the frame itself, not somebody using the
// window - and somebody coming back in those seconds has the memory given back
// from under them, which costs the pages faulted in again and nothing else.
func (t *tidy) settle(now time.Time) step {
	if now.Sub(t.framed) < tidySettle {
		return stepNothing
	}
	t.framed = time.Time{}
	t.used = false
	t.settling = true
	return stepRelease
}

// since adds here to the looks of the quiet and answers with the first of
// them, the one tidyQuiet or a little more before here.
func (t *tidy) since(here reading) reading {
	t.quiet = append(t.quiet, here)
	for len(t.quiet) > 2 && here.at.Sub(t.quiet[1].at) >= tidyQuiet {
		t.quiet = t.quiet[1:]
	}
	return t.quiet[0]
}

// tidyClock looks once in tidyLook and does what the look says. The toolkit
// calls tick on every frame of its loop.
type tidyClock struct {
	tidy *tidy
	// allocated is every byte allocated so far, now the time, frame asks the
	// toolkit for one frame and release gives the memory back - the runtime,
	// the clock, the window and releaseBeside in the program.
	allocated      func() uint64
	now            func() time.Time
	frame, release func()
	// next is when the next look is due.
	next time.Time
}

// newTidyClock begins the wait with the window as it stands.
func newTidyClock(allocated func() uint64, now func() time.Time, frame, release func()) *tidyClock {
	return &tidyClock{tidy: newTidy(allocated(), now()), allocated: allocated, now: now, frame: frame, release: release}
}

// tick looks when a look is due.
func (k *tidyClock) tick() {
	now := k.now()
	if now.Before(k.next) {
		return
	}
	k.next = now.Add(tidyLook)
	switch k.tidy.look(k.allocated(), now) {
	case stepFrame:
		k.frame()
	case stepRelease:
		k.release()
	}
}

// tidyWhenLeftAlone gives back what the window c draws no longer uses once
// nobody has used it for a while. Nothing stops it: the clock is the toolkit's
// loop, which ends with the window, and a release still on its way ends with
// the process.
func tidyWhenLeftAlone(c fyne.Canvas) {
	// Not in the window and never put there, so redrawing it is a frame that
	// touches nothing.
	nothing := canvas.NewRectangle(nil)
	k := newTidyClock(allocationCounter(), time.Now, func() { c.Refresh(nothing) }, releaseBeside)
	clock := &fyne.Animation{Duration: tidyLook, Curve: fyne.AnimationLinear,
		RepeatCount: fyne.AnimationRepeatForever, Tick: func(float32) { k.tick() }}
	clock.Start()
}

// allocationCounter reads every byte the heap has handed out since the
// process began, without stopping anything, unlike runtime.ReadMemStats - and
// into one sample made here, so that reading allocates nothing. Zero if a
// runtime ever stops counting it, and the window is then tidied once and never
// again, which is the cheap way to be wrong.
func allocationCounter() func() uint64 {
	sample := []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}
	return func() uint64 {
		metrics.Read(sample)
		if sample[0].Value.Kind() != metrics.KindUint64 {
			return 0
		}
		return sample[0].Value.Uint64()
	}
}
