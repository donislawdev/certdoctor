package fanout

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The shared fan-out's own tests.
//
// THEY MOVED HERE WITH THE CODE AND THAT IS THE POINT OF THE MOVE. The promise
// "results land at their own index, at most AtOnce at a time, and every
// goroutine is waited for" is one promise. Tested once per layer it would be one
// promise checked in two places, and the mutation entries aimed at it would
// report SKIP rather than proving anything - OBS50. L3 keeps its own tests for
// what L3 does with the results; what the fan-out guarantees is checked here.

// TestEveryIndexRunsExactlyOnce is the promise everything else rests on.
//
// AN INDEX RUN TWICE WOULD OPEN TWO CONNECTIONS TO ONE ADDRESS and report one
// row, and an index never run would leave a zero value that reads as a row about
// a thing that never happened.
func TestEveryIndexRunsExactlyOnce(t *testing.T) {
	for _, count := range []int{1, 2, AtOnce - 1, AtOnce, AtOnce + 1, 3 * AtOnce} {
		seen := make([]atomic.Int64, count)
		Over(count, func(i int) { seen[i].Add(1) })

		for i := range seen {
			if got := seen[i].Load(); got != 1 {
				t.Errorf("with %d attempts, index %d ran %d time(s)", count, i, got)
			}
		}
	}
}

// TestResultsLandAtTheirOwnIndex is rule 2 of docs 22 section 2, checked on the
// primitive rather than through a layer.
//
// IT FORCES COMPLETION ORDER TO BE THE REVERSE OF INDEX ORDER, DETERMINISTICALLY:
// index 0 cannot finish until the last index has. Anything assembling results in
// the order attempts finish would put the last one first, and two runs of the
// same machine would then disagree about which row is which.
func TestResultsLandAtTheirOwnIndex(t *testing.T) {
	const count = 5
	out := make([]int, count)
	done := make(chan struct{})

	Over(count, func(i int) {
		switch i {
		case 0:
			// Bounded, so a sequential implementation fails this test instead of
			// hanging - a hung test says nothing to anybody.
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
		case count - 1:
			close(done)
		}
		out[i] = i * 10
	})

	for i := range out {
		if out[i] != i*10 {
			t.Errorf("index %d holds %d, and the attempt for that index wrote %d", i, out[i], i*10)
		}
	}
}

// TestTheFirstWaveTakesTheFirstIndices pins which attempts go first, and it
// exists because the mutation register proved the neighbouring test could not
// see this.
//
// THE ENTRY AIMED AT DISPATCH ORDER SURVIVED, AND THE TEST WAS THE REASON.
// Handing goroutine i the index count-1-i is a BIJECTION: every index is still
// run exactly once, and every caller closure still writes the value belonging to
// the index it was handed - so "each slot holds its own value" is true in both
// worlds and cannot tell them apart. That is the shape OBS43 describes, met here
// by a fixture rather than by a double.
//
// WHAT THE MUTANT REALLY CHANGES IS OBSERVABLE AND MATTERS: which indices land
// in the FIRST wave. Callers re-read their budget inside the attempt, so the
// addresses dispatched first are the ones that get tried when time is short, and
// the ones dispatched last are the ones that come back not_attempted. Reversing
// that silently swaps which half of a name's addresses a stretched run reports
// on.
//
// Waves are separated by a wait, so every attempt of wave one starts before any
// attempt of wave two - the order attempts START is therefore wave membership,
// and it is deterministic.
func TestTheFirstWaveTakesTheFirstIndices(t *testing.T) {
	var mu sync.Mutex
	var started []int

	Over(2*AtOnce, func(i int) {
		mu.Lock()
		started = append(started, i)
		mu.Unlock()
	})

	if len(started) != 2*AtOnce {
		t.Fatalf("%d attempts started, expected %d", len(started), 2*AtOnce)
	}

	firstWave := map[int]bool{}
	for _, i := range started[:AtOnce] {
		firstWave[i] = true
	}
	for i := 0; i < AtOnce; i++ {
		if !firstWave[i] {
			t.Errorf("index %d was not in the first wave, and the first wave holds %v - the attempts that go first are not the ones the caller listed first",
				i, started[:AtOnce])
		}
	}
}

// TestNoMoreThanEightRunAtOnce is the ceiling from ADR44.
//
// THE NUMBER IS WRITTEN OUT RATHER THAN READ FROM AtOnce, and that is the
// difference between an assertion and an echo. A test that asks the code under
// test what its ceiling is passes at every ceiling, so widening the constant to
// sixty-four would go unnoticed - the shape OBS48 names.
//
// DETERMINISTIC IN BOTH DIRECTIONS. Every attempt announces itself and then
// waits until ceiling+1 are in flight, or a short deadline passes. A capped
// fan-out can never reach that ninth arrival, so each wave waits the deadline
// out and the peak is exactly the ceiling. An uncapped one reaches it at once,
// and the peak is the whole count.
func TestNoMoreThanEightRunAtOnce(t *testing.T) {
	const ceiling = 8

	var inFlight, peak atomic.Int64
	crowded := make(chan struct{})
	var once sync.Once

	Over(2*ceiling, func(int) {
		now := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			was := peak.Load()
			if now <= was || peak.CompareAndSwap(was, now) {
				break
			}
		}
		if now > ceiling {
			once.Do(func() { close(crowded) })
		}
		select {
		case <-crowded:
		case <-time.After(250 * time.Millisecond):
		}
	})

	if got := peak.Load(); got > ceiling {
		t.Errorf("%d attempts were in flight at once and the ceiling is %d - the width of this program's burst is being chosen by whoever answered the DNS query",
			got, ceiling)
	}
	// The other side of it, so the ceiling cannot be satisfied by a fan-out that
	// went back to one attempt at a time. An upper bound alone is passed
	// perfectly by code that does nothing in parallel.
	if got := peak.Load(); got != ceiling {
		t.Errorf("the widest wave held %d attempts and the fan-out allows %d", got, ceiling)
	}
}

// TestOverWaitsForEveryGoroutine is the promise that keeps sockets from being
// left behind.
//
// A FAN-OUT THAT RETURNS EARLY WALKS AWAY FROM WORK STILL RUNNING, and the
// caller then reads results that are not there yet. Worse, a panic in an
// abandoned goroutine is not caught by the recover in the orchestrator: the
// process dies with no report and no exit code from the table.
func TestOverWaitsForEveryGoroutine(t *testing.T) {
	const count = 3 * AtOnce
	var finished atomic.Int64

	// Twenty milliseconds rather than one, so that "returned early" and "returned
	// late" cannot be told apart by scheduling luck. A fan-out that returns
	// without waiting comes back in microseconds with nothing finished; this one
	// cannot come back before three waves of twenty milliseconds have passed.
	Over(count, func(int) {
		time.Sleep(20 * time.Millisecond)
		finished.Add(1)
	})

	if got := finished.Load(); got != count {
		t.Errorf("Over returned with %d of %d attempts finished", got, count)
	}
}

// TestNoAttemptsIsNotACallersBugToDiscoverAtRunTime pins the degenerate but
// legal input - state (D) from docs/02.
//
// A name that resolved to nothing reaches a layer as an empty list, and that is
// ordinary rather than exceptional. It has to do nothing quietly, not panic and
// not spin.
func TestNoAttemptsIsNotACallersBugToDiscoverAtRunTime(t *testing.T) {
	for _, count := range []int{0, -1} {
		var ran atomic.Int64
		Over(count, func(int) { ran.Add(1) })
		if got := ran.Load(); got != 0 {
			t.Errorf("a count of %d ran %d attempt(s)", count, got)
		}
	}
}

// TestAnAttemptThatFallsOverIsCaughtRatherThanKillingTheProcess is R-1.
//
// The recover in the orchestrator runs on the goroutine that walks the layers
// and cannot see these. Before this, a panic anywhere under attempt took the
// process down with no report at all and an exit code from outside the table -
// and attempt reaches code this program does not own, net.Dialer for L3 and
// crypto/tls for L4.
func TestAnAttemptThatFallsOverIsCaughtRatherThanKillingTheProcess(t *testing.T) {
	ran := make([]bool, 4)
	err := Over(4, func(i int) {
		ran[i] = true
		if i == 2 {
			panic("somebody else's code fell over")
		}
	})

	if err == nil {
		t.Fatal("an attempt panicked and the run came back clean")
	}
	if !strings.Contains(err.Error(), "attempt 2") {
		t.Errorf("the error does not name which attempt fell over: %v", err)
	}
	if !strings.Contains(err.Error(), "somebody else's code fell over") {
		t.Errorf("the error does not carry what was thrown: %v", err)
	}
	// AND THE OTHERS STILL RAN. Walking away from the rest of a wave would leave
	// sockets being opened behind us, which is the reason there is no early
	// return in this function at all.
	for i, did := range ran {
		if !did {
			t.Errorf("attempt %d never ran because another one fell over", i)
		}
	}
}

// TestARunWhereNothingFallsOverComesBackClean is the twin, and without it the
// test above is satisfied by a function that always reports a panic.
func TestARunWhereNothingFallsOverComesBackClean(t *testing.T) {
	if err := Over(3, func(int) {}); err != nil {
		t.Errorf("nothing panicked and the run reported %v", err)
	}
	if err := Over(0, func(int) { t.Error("an attempt ran for a count of zero") }); err != nil {
		t.Errorf("a count of zero reported %v", err)
	}
}

// TestTheAttemptNamedIsTheFirstByIndexRatherThanByTiming keeps one run from
// naming a different address every time it is repeated.
func TestTheAttemptNamedIsTheFirstByIndexRatherThanByTiming(t *testing.T) {
	err := Over(4, func(i int) {
		if i == 3 {
			panic("late")
		}
		if i == 1 {
			panic("early")
		}
	})
	if err == nil {
		t.Fatal("two attempts panicked and the run came back clean")
	}
	if !strings.Contains(err.Error(), "attempt 1") {
		t.Errorf("the error names an attempt other than the first by index: %v", err)
	}
}
