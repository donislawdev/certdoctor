//go:build cgo

package main

import (
	"reflect"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

// quietRun looks every tidyLook for as long as length, the window allocating
// before each look what alloc says for the time of that look, and answers
// with when the frames and the releases came.
func quietRun(length time.Duration, alloc func(at time.Duration) uint64) (frames, releases []time.Duration) {
	began := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	counter := uint64(80 << 20)
	t := newTidy(counter, began)
	for at := tidyLook; at <= length; at += tidyLook {
		counter += alloc(at)
		switch t.look(counter, began.Add(at)) {
		case stepFrame:
			frames = append(frames, at)
		case stepRelease:
			releases = append(releases, at)
		}
	}
	return frames, releases
}

// Every steady allocation below is per look, so tidyQuiet holds fourteen of
// them: 100 KiB a look is 1.4 MiB a quiet, 150 KiB is 2.05 MiB - either side
// of tidyBudget.
const (
	trickle      = 100 << 10
	overATrickle = 150 << 10
)

// steady allocates the same at every look, and once more at the times given.
func steady(each uint64, once map[time.Duration]uint64) func(time.Duration) uint64 {
	return func(at time.Duration) uint64 { return each + once[at] }
}

// A window left alone is tidied once: a frame after a whole quiet, the memory
// back tidySettle later, and nothing more until somebody uses it - neither the
// frame's nor the release's own allocations count as use, and neither does a
// trickle that never adds up to the budget within a quiet. Allocating the
// budget within a quiet is use, however it is spread (ADR145).
func TestAWindowLeftAloneIsTidiedOnceUntilItIsUsedAgain(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		name             string
		length           time.Duration
		alloc            func(time.Duration) uint64
		frames, releases []time.Duration
	}{
		{"left alone", 10 * time.Minute, steady(trickle, nil), []time.Duration{70 * s}, []time.Duration{85 * s}},
		{"the frame's own allocations", 10 * time.Minute, steady(trickle, map[time.Duration]uint64{75 * s: 5 << 20, 80 * s: 5 << 20}),
			[]time.Duration{70 * s}, []time.Duration{85 * s}},
		{"the release's own allocations", 10 * time.Minute, steady(trickle, map[time.Duration]uint64{90 * s: 3 << 20}),
			[]time.Duration{70 * s}, []time.Duration{85 * s}},
		{"a trickle for an hour", time.Hour, steady(trickle, nil), []time.Duration{70 * s}, []time.Duration{85 * s}},
		{"used before the quiet ends", 10 * time.Minute, steady(trickle, map[time.Duration]uint64{60 * s: 3 << 20}),
			[]time.Duration{130 * s}, []time.Duration{145 * s}},
		{"used again after a tidy", 10 * time.Minute, steady(trickle, map[time.Duration]uint64{300 * s: 3 << 20}),
			[]time.Duration{70 * s, 370 * s}, []time.Duration{85 * s, 385 * s}},
		{"the budget spread over a quiet", 10 * time.Minute, steady(overATrickle, nil), nil, nil},
	} {
		frames, releases := quietRun(c.length, c.alloc)
		if !reflect.DeepEqual(frames, c.frames) || !reflect.DeepEqual(releases, c.releases) {
			t.Errorf("%s: frames at %v and releases at %v, want %v and %v", c.name, frames, releases, c.frames, c.releases)
		}
	}
}

// The toolkit ticks the clock on every frame of its loop, sixty a second: the
// counter is read once a look, and the frame and the release are asked for on
// the ticks their looks fall on.
func TestTheClockLooksOnceInALookAndActsOnWhatItSees(t *testing.T) {
	began := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	now := began
	reads, frames, releases := 0, []time.Duration{}, []time.Duration{}
	k := newTidyClock(func() uint64 { reads++; return 80 << 20 }, func() time.Time { return now },
		func() { frames = append(frames, now.Sub(began)) }, func() { releases = append(releases, now.Sub(began)) })
	for i := 0; i <= 90*60; i++ {
		now = began.Add(time.Duration(i) * time.Second / 60)
		k.tick()
	}
	// One read for the window as it stood, and one for each look at 0, 5, ... 90 s.
	if reads != 1+19 {
		t.Errorf("the counter was read %d times in 90 s of ticks, want 20", reads)
	}
	if !reflect.DeepEqual(frames, []time.Duration{70 * time.Second}) || !reflect.DeepEqual(releases, []time.Duration{85 * time.Second}) {
		t.Errorf("frames at %v and releases at %v, want [1m10s] and [1m25s]", frames, releases)
	}
}

// sink keeps what the next test allocates on the heap.
var sink []byte

// The counter the window reads is the runtime's own and grows with what is
// allocated - a name the runtime no longer knows would read zero, and the
// window would be tidied once and never again.
func TestTheAllocationCounterCountsWhatIsAllocated(t *testing.T) {
	read := allocationCounter()
	before := read()
	sink = make([]byte, 4<<20)
	after := read()
	if before == 0 || after-before < 4<<20 {
		t.Errorf("4 MiB allocated between two reads of %d and %d", before, after)
	}
}

// Started on a window, the clock leaves what it shows alone: the test
// toolkit ticks an animation once as it starts, and that first look asks for
// nothing.
func TestTidyingAWindowLeavesWhatItShowsAlone(t *testing.T) {
	test.NewTempApp(t)
	shown := widget.NewLabel("shown")
	w := test.NewWindow(shown)
	defer w.Close()
	tidyWhenLeftAlone(w.Canvas())
	if w.Content() != shown || shown.Text != "shown" {
		t.Error("starting the tidying changed what the window shows")
	}
}
