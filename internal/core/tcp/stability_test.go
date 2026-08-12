package tcp

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// The stability run docs/22 section 6a asks for, on L3's side of the seam.
//
// IT IS A DEBT FROM P5a RATHER THAN NEW WORK. The rule says the run goes in the
// same slice as the primitive that triggers it, and the primitive - the first
// thing in this tree that opens a TCP connection - arrived in P5a without one.
// It is paid here, BEFORE the fan-out, because a leak check written afterwards
// would find whatever the fan-out did and defend it, rather than catch it.
//
// FOUR CHECKS. (a) a leak counted on every path out, (b) many walks released at
// once onto uninitialised state, (c) input that is degenerate and still legal,
// (d) drift sampled in windows, because a late leak hides behind an early peak
// in a cumulative counter.
//
// WHY A STAND-IN AND NOT REAL HANDLES. Counting file descriptors is not portable
// and, where it is possible, answers a question about the operating system. What
// has to be true of OUR code is narrower and checkable everywhere: every path out
// closes what it was handed, exactly once. The same reasoning, and the same
// shape, as the run in internal/adapter/dns.

// handout hands out connections and knows how many are open right now.
//
// IT IS SAFE TO USE FROM SEVERAL GOROUTINES BEFORE ANYTHING CALLS IT FROM
// SEVERAL, which is the warning docs/22 section 2 ends with and this is its
// first application in this tree. A double that races is a flaky test, and a
// flaky test teaches retrying instead of looking.
type handout struct {
	live   atomic.Int64
	made   atomic.Int64
	closed atomic.Int64
	twice  atomic.Int64
	asked  atomic.Int64
}

type handle struct {
	owner *handout
	shut  atomic.Bool
}

// Close counts a second close as a defect rather than ignoring it. Without that,
// one path closing twice would cancel out another path not closing at all, and
// the totals would agree while both were wrong.
func (h *handle) Close() error {
	if h.shut.Swap(true) {
		h.owner.twice.Add(1)
		return nil
	}
	h.owner.live.Add(-1)
	h.owner.closed.Add(1)
	return nil
}

// connect builds the port L3 declared. behave decides, per attempt, whether a
// connection is handed back and with what error - including the shape the io
// contract permits and this project has already paid for once: a connection
// returned TOGETHER with an error.
func (h *handout) connect(behave func(n int64) (bool, error)) Connect {
	return func(context.Context, string, int) (io.Closer, error) {
		n := h.asked.Add(1)
		give, err := behave(n)
		if !give {
			return nil, err
		}
		h.made.Add(1)
		h.live.Add(1)
		return &handle{owner: h}, err
	}
}

// settled reports what the counters say once a walk is over.
func (h *handout) settled(t *testing.T, wantMade int64) {
	t.Helper()
	if live := h.live.Load(); live != 0 {
		t.Errorf("%d connection(s) are still open after the walk finished", live)
	}
	if made, closed := h.made.Load(), h.closed.Load(); made != closed {
		t.Errorf("%d connection(s) were opened and %d closed", made, closed)
	}
	if twice := h.twice.Load(); twice != 0 {
		t.Errorf("%d connection(s) were closed more than once", twice)
	}
	if made := h.made.Load(); made != wantMade {
		t.Errorf("the walk opened %d connection(s), expected %d - a counter that disagrees here is measuring its own stand-in", made, wantMade)
	}
}

// safeClock is a clock that may be read from several goroutines.
//
// It exists now rather than when the fan-out needs it, for the reason above: the
// double has to be safe BEFORE the first concurrent caller, not after the race
// detector explains it.
func safeClock() func() time.Time {
	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	var ticks atomic.Int64
	return func() time.Time {
		return base.Add(time.Duration(ticks.Add(1)) * time.Millisecond)
	}
}

func threeAddresses() []string { return []string{"192.0.2.10", "192.0.2.11", "2001:db8::10"} }

func stableInput(connect Connect) Input {
	return Input{
		Addresses:  func() []string { return threeAddresses() },
		Port:       443,
		Connect:    connect,
		Now:        safeClock(),
		PerAddress: 2 * time.Second,
	}
}

// TestEveryWayOutOfAnAttemptClosesWhatItWasHanded is check (a).
//
// THE PATHS THAT OPEN NOTHING ARE THE HALF THAT IS EASY TO GET WRONG, and they
// are asserted just as hard as the others. A stand-in that quietly opened
// something on a refusal would make every leak check below pass by measuring
// itself, which is the failure mode named in the dns run this one follows.
func TestEveryWayOutOfAnAttemptClosesWhatItWasHanded(t *testing.T) {
	unanticipated := errors.New("something no version of this code has seen")

	for _, c := range []struct {
		name     string
		behave   func(n int64) (bool, error)
		wantMade int64
	}{
		{"a connection and no error", func(int64) (bool, error) { return true, nil }, 3},
		// The shape P5a paid for: the io contract permits a connection beside an
		// error, and a caller returning early on err leaks it.
		{"a connection together with an error", func(int64) (bool, error) { return true, ErrReset }, 3},
		{"an error and no connection", func(int64) (bool, error) { return false, ErrRefused }, 0},
		{"our own rule refusing before the wire", func(int64) (bool, error) { return false, ErrRefusedByRule }, 0},
		{"a deadline with nothing behind it", func(int64) (bool, error) { return false, ErrTimeout }, 0},
		{"no route to the address", func(int64) (bool, error) { return false, ErrUnreachable }, 0},
		{"an error nobody anticipated", func(int64) (bool, error) { return false, unanticipated }, 0},
		{
			"one attempt of each shape in one walk",
			func(n int64) (bool, error) {
				switch n {
				case 1:
					return true, nil
				case 2:
					return true, ErrReset
				default:
					return false, ErrRefused
				}
			},
			2,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := &handout{}
			got := Ask(context.Background(), stableInput(h.connect(c.behave)))

			h.settled(t, c.wantMade)
			// A row per address on every one of these paths. Fewer rows reads as a
			// name with fewer addresses, which is a different diagnosis.
			if len(got.Findings) != len(threeAddresses()) {
				t.Fatalf("three addresses produced %d rows", len(got.Findings))
			}
			for _, finding := range got.Findings {
				if broken := finding.Breach(); broken != "" {
					t.Errorf("a row is refused by its own contract: %s", broken)
				}
			}
		})
	}
}

// TestThePathsThatOpenNothingAskForNothing is the other half of check (a), and
// it is about the port never being called at all.
//
// A LEAK CANNOT HAPPEN WHERE NOTHING WAS OPENED, so what has to be proven here
// is the premise rather than the leak: these paths really do stop before the
// wire. If they did not, the counts above would be describing attempts nobody
// intended to make.
func TestThePathsThatOpenNothingAskForNothing(t *testing.T) {
	t.Run("the budget was already spent", func(t *testing.T) {
		h := &handout{}
		in := stableInput(h.connect(func(int64) (bool, error) { return true, nil }))

		// A deadline in the past, read through the injected clock exactly as the
		// layer reads it.
		ctx, cancel := context.WithDeadline(context.Background(), in.Now().Add(-time.Hour))
		defer cancel()
		got := Ask(ctx, in)

		h.settled(t, 0)
		if asked := h.asked.Load(); asked != 0 {
			t.Errorf("the layer opened %d attempt(s) with no budget left", asked)
		}
		if len(got.Findings) != 3 {
			t.Fatalf("three addresses produced %d rows with no budget left", len(got.Findings))
		}
		for _, finding := range got.Findings {
			if finding.TCPConnect.Outcome != report.OutcomeNotAttempted {
				t.Errorf("an attempt that never left this machine reports %q", finding.TCPConnect.Outcome)
			}
		}
	})

	t.Run("the name resolved to nothing", func(t *testing.T) {
		h := &handout{}
		in := stableInput(h.connect(func(int64) (bool, error) { return true, nil }))
		in.Addresses = func() []string { return nil }

		got := Ask(context.Background(), in)

		h.settled(t, 0)
		if asked := h.asked.Load(); asked != 0 {
			t.Errorf("the layer made %d attempt(s) with no address to connect to", asked)
		}
		if got.Status != status.Unknown || got.Reason != status.ReasonNothingToCheck {
			t.Errorf("a name with no addresses gave %s/%s", got.Status, got.Reason)
		}
	})

	t.Run("this layer was given no way to learn the addresses", func(t *testing.T) {
		h := &handout{}
		in := stableInput(h.connect(func(int64) (bool, error) { return true, nil }))
		in.Addresses = nil

		got := Ask(context.Background(), in)

		h.settled(t, 0)
		if asked := h.asked.Load(); asked != 0 {
			t.Errorf("the layer made %d attempt(s) without knowing what to connect to", asked)
		}
		if got.Status != status.Unknown || got.Reason != status.ReasonProbeError {
			t.Errorf("a missing port gave %s/%s, and it is our defect", got.Status, got.Reason)
		}
	})
}

// TestManyWalksReleasedAtOnceLeaveNothingOpen is check (b).
//
// THIRTY-TWO WALKS LET GO BY ONE close(start), so they arrive on the same
// uninitialised state together rather than one after another. Today each walk
// builds its own Input and the only thing they share is the handout - so what
// this proves today is that nothing in the layer is package level state.
//
// ITS SECOND LIFE STARTS WITH THE FAN-OUT: once one walk runs its attempts in
// parallel, the clock and the counters inside a SINGLE walk become shared too,
// and this check is already standing when that happens.
func TestManyWalksReleasedAtOnceLeaveNothingOpen(t *testing.T) {
	const walkers = 32

	h := &handout{}
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < walkers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start

			in := stableInput(h.connect(func(n int64) (bool, error) {
				// Every third attempt fails with a connection in hand, which is the
				// path that leaks if anybody returns early.
				if n%3 == 0 {
					return true, ErrReset
				}
				return true, nil
			}))
			got := Ask(context.Background(), in)

			if len(got.Findings) != 3 {
				t.Errorf("walker %d saw %d rows for three addresses", i, len(got.Findings))
			}
		}(i)
	}

	close(start)
	wg.Wait()

	h.settled(t, walkers*3)
}

// TestDegenerateButLegalInputIsAnsweredAndClosed is check (c) - state (D) from
// docs/02: not bad data, but the input this code will really be handed.
//
// THE DUPLICATE ADDRESS IS NOT AN INVENTED CASE. L3 is fed the union of both DNS
// lenses (wire.go), which does not sift duplicates out, so the same address
// arriving twice is ordinary. It has to produce two rows, because one row would
// be this layer quietly deciding that an attempt it made did not happen.
func TestDegenerateButLegalInputIsAnsweredAndClosed(t *testing.T) {
	for _, c := range []struct {
		name      string
		addresses []string
		prepare   func(in *Input)
	}{
		{"a single address", []string{"192.0.2.10"}, nil},
		{"the same address twice", []string{"192.0.2.10", "192.0.2.10"}, nil},
		{"a link-local address carrying a zone", []string{"fe80::1%eth0"}, nil},
		{"an IPv4 address written as IPv6", []string{"::ffff:192.0.2.10"}, nil},
		{"no per-attempt cap at all", threeAddresses(), func(in *Input) { in.PerAddress = 0 }},
		{"a negative per-attempt cap", threeAddresses(), func(in *Input) { in.PerAddress = -time.Second }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := &handout{}
			in := stableInput(h.connect(func(int64) (bool, error) { return true, nil }))
			in.Addresses = func() []string { return c.addresses }
			if c.prepare != nil {
				c.prepare(&in)
			}

			got := Ask(context.Background(), in)

			if len(got.Findings) != len(c.addresses) {
				t.Fatalf("%d address(es) produced %d rows", len(c.addresses), len(got.Findings))
			}
			for _, finding := range got.Findings {
				if broken := finding.Breach(); broken != "" {
					t.Errorf("a row is refused by its own contract: %s", broken)
				}
			}
			h.settled(t, int64(len(c.addresses)))
		})
	}
}

// TestNothingDriftsAcrossRepeatedWalks is check (d).
//
// SAMPLED IN WINDOWS RATHER THAN ONCE AT THE END. A cumulative counter read only
// at the end hides a leak that starts late behind the peak of a walk that
// finished cleanly. Eight windows of twenty-five walks, with the live count read
// after each one, say WHEN the number stopped returning to zero.
func TestNothingDriftsAcrossRepeatedWalks(t *testing.T) {
	const windows, perWindow = 8, 25

	h := &handout{}
	connect := h.connect(func(n int64) (bool, error) {
		switch n % 3 {
		case 0:
			// A connection beside an error.
			return true, ErrReset
		case 1:
			return true, nil
		default:
			return false, ErrRefused
		}
	})

	for window := 1; window <= windows; window++ {
		for walk := 0; walk < perWindow; walk++ {
			Ask(context.Background(), stableInput(connect))
		}
		if live := h.live.Load(); live != 0 {
			t.Fatalf("after window %d of %d, %d connection(s) are still open - a leak that starts late is invisible in a total read once at the end",
				window, windows, live)
		}
		if twice := h.twice.Load(); twice != 0 {
			t.Fatalf("after window %d of %d, %d connection(s) had been closed more than once", window, windows, twice)
		}
	}

	// Two of every three attempts hand back a connection, so the totals are known
	// rather than merely equal to each other.
	if want := int64(windows * perWindow * 2); h.made.Load() != want {
		t.Errorf("the run opened %d connection(s) across %d walks, expected %d", h.made.Load(), windows*perWindow, want)
	}
	if h.closed.Load() != h.made.Load() {
		t.Errorf("%d connection(s) opened and %d closed across the whole run", h.made.Load(), h.closed.Load())
	}
}
