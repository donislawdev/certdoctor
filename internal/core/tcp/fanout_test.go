package tcp

import (
	"context"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// The fan-out's own tests, beside the fan-out's own file.
//
// THE STABILITY RUN NEXT DOOR ALREADY COVERS LEAKS AND DEGENERATE INPUT under
// the fan-out - it was written in P5b-K1, deliberately BEFORE this code, so it
// would catch what the fan-out did rather than describe it. What is left for this
// file is the four things only the fan-out can get wrong: the order rows come
// back in, how many attempts run at once, what happens to a wave that starts with
// no budget, and whether attempts genuinely run beside each other.

// addressesFor builds n distinct documentation addresses.
func addressesFor(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "192.0.2." + strconv.Itoa(i+1)
	}
	return out
}

// TestRowsComeBackInAddressOrderNotCompletionOrder is rule 2 of docs 22 section
// 2, and it needs its own test because no existing one can see this.
//
// TestTheSameRunProducesTheSameBytes DOES NOT COVER IT: the same race can resolve
// the same way twice in a row, so a report assembled in completion order can be
// byte-identical across two runs and still be wrong. What is needed is completion
// order that differs from address order DETERMINISTICALLY, and that is what this
// builds: the first address cannot finish until the last one has, and every
// address carries a different outcome so a row read at the wrong index says so.
//
// If the rows were appended as attempts finished, row 0 would be the timeout that
// belongs to the last address - and a reader comparing two reports would be
// comparing rows about two different addresses.
func TestRowsComeBackInAddressOrderNotCompletionOrder(t *testing.T) {
	addresses := addressesFor(3)
	first, last := addresses[0], addresses[2]

	finished := make(chan struct{})
	in := workingInput(func(_ context.Context, address string, _ int) (io.Closer, error) {
		switch address {
		case first:
			// Bounded, so a layer that runs attempts one after another fails this
			// test rather than hanging - a hung test says nothing to anybody.
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
			}
			return nil, ErrRefused
		case last:
			close(finished)
			return nil, ErrTimeout
		}
		return nil, ErrUnreachable
	})
	in.Addresses = func() []string { return addresses }

	rows := rowsOf(Ask(context.Background(), in))

	if len(rows) != len(addresses) {
		t.Fatalf("%d addresses produced %d rows", len(addresses), len(rows))
	}
	for i, want := range []report.ConnectOutcome{
		report.OutcomeRefused,     // the address that finished LAST
		report.OutcomeUnreachable, //
		report.OutcomeTimeout,     // the address that finished FIRST
	} {
		if rows[i].Address != addresses[i] {
			t.Errorf("row %d is about %s, and address %d is %s - rows are coming back in the order attempts finished",
				i, rows[i].Address, i, addresses[i])
		}
		if rows[i].Outcome != want {
			t.Errorf("row %d says %q and that address ended as %q", i, rows[i].Outcome, want)
		}
	}
}

// TestNoMoreThanEightAttemptsRunAtOnce is the ceiling from ADR44.
//
// WITHOUT IT THE NUMBER OF SOCKETS THIS MACHINE OPENS AT ONCE IS DECIDED BY
// SOMEBODY ELSE'S RESOLVER, and a wide answer would make this tool look like a
// scanner to whatever is watching the network - in the environments it is
// specifically meant to be run in (O6).
//
// HOW IT IS MADE DETERMINISTIC IN BOTH DIRECTIONS. Every attempt announces itself
// and then waits until atOnce+1 attempts are in flight, or a short deadline
// passes. A capped layer can never reach that ninth arrival, so each wave waits
// the deadline out and the peak is exactly atOnce. An uncapped one reaches it
// immediately with sixteen addresses, and the peak is sixteen. The assertion is
// on the peak, and both outcomes are reached by construction rather than by
// scheduling luck.
func TestNoMoreThanEightAttemptsRunAtOnce(t *testing.T) {
	// THE NUMBER IS WRITTEN OUT HERE RATHER THAN READ FROM atOnce, and that is
	// the difference between an assertion and an echo. A test that asks the code
	// under test what the ceiling is passes at any ceiling, so widening the
	// constant to sixty-four would go unnoticed - the shape OBS48 names. This is
	// the number ADR44 decided, and changing it has to make this test red.
	const ceiling = 8

	addresses := addressesFor(2 * ceiling)

	var inFlight, peak atomic.Int64
	crowded := make(chan struct{})
	var once sync.Once

	in := workingInput(func(_ context.Context, _ string, _ int) (io.Closer, error) {
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
		return nil, ErrRefused
	})
	in.Addresses = func() []string { return addresses }

	rows := rowsOf(Ask(context.Background(), in))

	if len(rows) != len(addresses) {
		t.Fatalf("%d addresses produced %d rows", len(addresses), len(rows))
	}
	if got := peak.Load(); got > ceiling {
		t.Errorf("%d attempts were in flight at once and the ceiling is %d - the width of this program's burst is being chosen by whoever answered the DNS query",
			got, ceiling)
	}
	// The other side of it, so the ceiling cannot be satisfied by a layer that
	// went back to one attempt at a time - a test that only checks an upper bound
	// is passed perfectly by code that does nothing in parallel at all.
	if got := peak.Load(); got != ceiling {
		t.Errorf("the widest wave held %d attempts and the fan-out allows %d", got, ceiling)
	}
}

// TestAWaveThatStartsWithNoBudgetLeftIsNotAttempted keeps the not_attempted row
// from losing its producer - ADR44 promised it would not.
//
// THE BUDGET IS RE-READ INSIDE EVERY ATTEMPT, so an address in a later wave can
// find the layer's time already gone. This is an honest row about OUR budget and
// never about their network, which is the whole reason the outcome is spelled
// not_attempted and not timeout.
//
// IT IS ALSO THE PROOF THAT WAVES EXIST AT ALL. The clock is pushed past the
// deadline only once atOnce attempts have finished, and wg.Wait between waves is
// what guarantees the later addresses read it afterwards. Run without waves, all
// the addresses would ask before any had finished, and every row would carry an
// outcome instead.
func TestAWaveThatStartsWithNoBudgetLeftIsNotAttempted(t *testing.T) {
	const extra = 3
	addresses := addressesFor(atOnce + extra)

	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	deadline := base.Add(time.Minute)

	var done, spent atomic.Int64
	in := workingInput(nil)
	in.Addresses = func() []string { return addresses }
	in.PerAddress = time.Second
	// The clock is a port, so "the budget ran out" is something a test can state
	// rather than wait for - and it is stated in the layer's own axis of time,
	// which is what OBS49 says to be careful about.
	in.Now = func() time.Time {
		if spent.Load() == 1 {
			return deadline.Add(time.Second)
		}
		return base
	}
	in.Connect = func(_ context.Context, _ string, _ int) (io.Closer, error) {
		if done.Add(1) == atOnce {
			spent.Store(1)
		}
		return nil, ErrRefused
	}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	rows := rowsOf(Ask(ctx, in))

	if len(rows) != len(addresses) {
		t.Fatalf("%d addresses produced %d rows", len(addresses), len(rows))
	}
	for i, row := range rows {
		want := report.OutcomeRefused
		if i >= atOnce {
			want = report.OutcomeNotAttempted
		}
		if row.Outcome != want {
			t.Errorf("address %d of %d came out as %q, want %q", i+1, len(addresses), row.Outcome, want)
		}
		if row.Outcome == report.OutcomeNotAttempted && row.DurationMS != 0 {
			t.Errorf("an address nobody had time for reports %d ms", row.DurationMS)
		}
	}
	if asked := done.Load(); asked != atOnce {
		t.Errorf("%d attempts reached the wire and the budget ran out after %d", asked, atOnce)
	}
}

// TestASilentAddressNoLongerTakesTimeFromTheOthers is the property ADR36's
// division used to approximate, asserted directly.
//
// A name behind four addresses where one sits behind a silently dropping
// firewall is the "hangs, then works" class of fault this layer exists for. The
// old answer was arithmetic - give each address a share, so the silent one cannot
// eat the lot. The new answer is structural: the others are already running
// beside it, so there is nothing to eat.
//
// IT ASSERTS WHAT THE SILENT ATTEMPT SAW, NOT HOW LONG THE RUN TOOK. A wall clock
// threshold would be a measurement of the machine it runs on; "while this attempt
// was still waiting, both of the others had already been asked" is a statement
// about the layer and is true or false regardless of how fast anything is.
func TestASilentAddressNoLongerTakesTimeFromTheOthers(t *testing.T) {
	addresses := addressesFor(3)
	silent := addresses[0]

	asked := make(chan struct{}, len(addresses))
	var sawOthers atomic.Int64

	in := workingInput(func(_ context.Context, address string, _ int) (io.Closer, error) {
		if address != silent {
			asked <- struct{}{}
			return nil, ErrRefused
		}
		for i := 0; i < len(addresses)-1; i++ {
			select {
			case <-asked:
				sawOthers.Add(1)
			case <-time.After(5 * time.Second):
				return nil, ErrTimeout
			}
		}
		return nil, ErrTimeout
	})
	in.Addresses = func() []string { return addresses }

	got := Ask(context.Background(), in)

	if want := int64(len(addresses) - 1); sawOthers.Load() != want {
		t.Errorf("the silent address waited while %d of the other %d had been asked - it is spending time the others needed",
			sawOthers.Load(), want)
	}
	if got.Status != status.Fail {
		t.Errorf("no address accepted a connection and the layer says %s", got.Status)
	}
	rows := rowsOf(got)
	if len(rows) != len(addresses) || rows[0].Outcome != report.OutcomeTimeout {
		t.Errorf("the silent address came out as %q", rows[0].Outcome)
	}
}
