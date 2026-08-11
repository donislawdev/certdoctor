package dns

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/dial"
	"github.com/donislawdev/certdoctor/internal/core/allowed"
)

// The stability run docs/22 section 6a asks for, and this package is the first
// thing in this tree that triggers it: it holds a system resource.
//
// FOUR CHECKS, AND (a) IS THE ONE THAT WOULD BE MISSED. A socket opened and then
// refused never existed, so it cannot leak - but a socket opened and then
// abandoned because the write failed is invisible until the process runs out of
// handles, which on a diagnostic tool means on somebody else's machine.
//
// WHY A COUNTER AND NOT REAL HANDLES. Counting file descriptors is not portable,
// and where it is possible it answers a question about the operating system. What
// has to be true of OUR code is narrower and checkable everywhere: every path out
// closes what it was handed, exactly once.

// tracker is a dialler that knows how many sockets are open right now.
type tracker struct {
	open    atomic.Int64
	opened  atomic.Int64
	closed  atomic.Int64
	failAt  func(n int64) error
	failure func(conn *trackedConn)
}

type trackedConn struct {
	owner     *tracker
	closeOnce sync.Once
	writeFail error
	readFail  error
	reply     []byte
}

func (t *tracker) dial(context.Context, string) (io.ReadWriteCloser, error) {
	n := t.opened.Add(1)
	if t.failAt != nil {
		if err := t.failAt(n); err != nil {
			// Nothing was opened, so nothing can be leaked. The counter has to
			// agree with that, otherwise the leak checks below would be measuring
			// their own stand-in.
			t.opened.Add(-1)
			return nil, err
		}
	}
	conn := &trackedConn{owner: t, reply: []byte{0, 1, 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
	if t.failure != nil {
		t.failure(conn)
	}
	t.open.Add(1)
	return conn, nil
}

func (c *trackedConn) Write(p []byte) (int, error) {
	if c.writeFail != nil {
		return 0, c.writeFail
	}
	return len(p), nil
}

func (c *trackedConn) Read(p []byte) (int, error) {
	if c.readFail != nil {
		return 0, c.readFail
	}
	return copy(p, c.reply), nil
}

func (c *trackedConn) Close() error {
	// Once, so that a double close shows up as a missing count rather than
	// cancelling out against a leak somewhere else.
	c.closeOnce.Do(func() {
		c.owner.open.Add(-1)
		c.owner.closed.Add(1)
	})
	return nil
}

// TestNoPathLeavesASocketOpen is check (a), walked over every way out.
func TestNoPathLeavesASocketOpen(t *testing.T) {
	cases := []struct {
		name     string
		resolver string
		tracker  *tracker
		opens    bool
	}{
		{
			name:     "the answer came back",
			resolver: "192.0.2.53",
			tracker:  &tracker{},
			opens:    true,
		},
		{
			name:     "the write failed",
			resolver: "192.0.2.53",
			tracker:  &tracker{failure: func(c *trackedConn) { c.writeFail = errors.New("send failed") }},
			opens:    true,
		},
		{
			name:     "the read failed",
			resolver: "192.0.2.53",
			tracker:  &tracker{failure: func(c *trackedConn) { c.readFail = errors.New("receive failed") }},
			opens:    true,
		},
		{
			// Nothing is opened here, and that is the point of listing it: the
			// refusal happens in front of the dialler.
			name:     "the allowed set refused",
			resolver: "192.0.2.53",
			tracker:  &tracker{failAt: func(int64) error { return &dial.Refusal{Address: "192.0.2.53:53"} }},
		},
		{
			// Refused before the dialler is even reached, because it is not an
			// address. The earliest exit of all.
			name:     "the resolver is not an address",
			resolver: "not-an-address",
			tracker:  &tracker{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _ = Exchange(c.tracker.dial)(context.Background(), c.resolver, []byte{0, 1})

			if got := c.tracker.open.Load(); got != 0 {
				t.Errorf("%d socket(s) still open after %s", got, c.name)
			}
			if c.opens && c.tracker.closed.Load() != 1 {
				t.Errorf("%s opened a socket and closed it %d times", c.name, c.tracker.closed.Load())
			}
			if !c.opens && c.tracker.opened.Load() != 0 {
				t.Errorf("%s opened a socket where it should not have reached the dialler", c.name)
			}
		})
	}
}

// TestSocketsDoNotDriftAcrossManyExchanges is check (d).
//
// SAMPLED IN WINDOWS AND NOT ONCE AT THE END, because a cumulative counter hides
// a late leak behind an early peak: fifty clean exchanges followed by ten leaking
// ones look, in a single reading at the end, like a small constant offset.
func TestSocketsDoNotDriftAcrossManyExchanges(t *testing.T) {
	var tr tracker
	// Every third one fails on the read, so the mix of clean and failing paths
	// is what actually runs rather than one path a hundred times.
	tr.failure = func(c *trackedConn) {
		if tr.opened.Load()%3 == 0 {
			c.readFail = errors.New("receive failed")
		}
	}
	exchange := Exchange(tr.dial)

	for window := 0; window < 8; window++ {
		for i := 0; i < 25; i++ {
			_, _ = exchange(context.Background(), "192.0.2.53", []byte{0, 1})
		}
		if got := tr.open.Load(); got != 0 {
			t.Fatalf("after window %d, %d socket(s) are still open", window, got)
		}
	}
	if tr.opened.Load() != tr.closed.Load() {
		t.Errorf("%d sockets were opened and %d were closed", tr.opened.Load(), tr.closed.Load())
	}
}

// TestConcurrentExchangesDoNotShareState is check (b), the cold race.
//
// Nothing in this package is initialised lazily and no state is shared between
// calls, so this SHOULD be safe - and "should be" is exactly the claim a race
// detector exists to check. It matters because the fan-out this program is
// heading for lives inside a layer: one branch per resolver, all calling this.
func TestConcurrentExchangesDoNotShareState(t *testing.T) {
	var tr tracker
	exchange := Exchange(tr.dial)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Released together, so they arrive at uninitialised state at the
			// same moment rather than one after another.
			<-start
			_, _ = exchange(context.Background(), "192.0.2.53", []byte{0, 1})
		}()
	}
	close(start)
	wg.Wait()

	if got := tr.open.Load(); got != 0 {
		t.Errorf("%d socket(s) survived a concurrent run", got)
	}
	if tr.opened.Load() != 32 {
		t.Errorf("%d of 32 concurrent exchanges reached the dialler", tr.opened.Load())
	}
}

// TestTheGuardedDiallerIsWhatRefuses proves the composition the entry point
// builds, rather than the two halves separately.
//
// It is the arrangement that carries inviolable rule 16 at run time: a resolver
// nobody derived from the user's question never reaches a socket, and the layer
// is told which kind of failure it was so it does not report our own rule as a
// broken network.
func TestTheGuardedDiallerIsWhatRefuses(t *testing.T) {
	var tr tracker
	targets := allowed.New()
	if err := targets.Allow("192.0.2.53:53", allowed.ReasonResolver); err != nil {
		t.Fatalf("preparing the allowed set: %v", err)
	}
	exchange := Exchange(dial.Guarded(tr.dial, targets, nil))

	if _, err := exchange(context.Background(), "192.0.2.53", []byte{0, 1}); err != nil {
		t.Errorf("a resolver that was allowed could not be reached: %v", err)
	}
	if _, err := exchange(context.Background(), "203.0.113.9", []byte{0, 1}); err == nil {
		t.Error("a resolver nobody allowed was reached")
	} else if !strings.Contains(err.Error(), "not one of the places") {
		t.Errorf("the refusal reads %q and does not say why", err)
	}
	if tr.opened.Load() != 1 {
		t.Errorf("%d sockets were opened where exactly one address was allowed", tr.opened.Load())
	}
	if got := tr.open.Load(); got != 0 {
		t.Errorf("%d socket(s) left open", got)
	}
}

// TestDegenerateButLegalInputIsAnswered is check (c): state (D) from docs/02.
//
// None of these is bad data. They are what this code will really be handed on
// the day a machine has an unusual resolver or a name nobody expected, and each
// has to produce an answer rather than a panic - docs/22 row 4.
func TestDegenerateButLegalInputIsAnswered(t *testing.T) {
	cases := []struct {
		name     string
		resolver string
		query    []byte
	}{
		{"an empty query", "192.0.2.53", nil},
		{"a resolver written as IPv6", "2001:db8::53", []byte{0, 1}},
		{"a link-local resolver with a zone", "fe80::1%eth0", []byte{0, 1}},
		{"a loopback resolver", "127.0.0.1", []byte{0, 1}},
		{"an empty resolver", "", []byte{0, 1}},
		{"a resolver with a port already on it", "192.0.2.53:53", []byte{0, 1}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var tr tracker
			// No assertion on the outcome: some of these are legal and some are
			// refused, and which is which is settled by the tests above. What is
			// checked here is that none of them panics and none leaks.
			_, _ = Exchange(tr.dial)(context.Background(), c.resolver, c.query)

			if got := tr.open.Load(); got != 0 {
				t.Errorf("%s left %d socket(s) open", c.name, got)
			}
		})
	}
}

// TestAnExpiredContextDoesNotOpenASocket covers the ordering that keeps a run
// that is already out of time from starting more work.
func TestAnExpiredContextDoesNotOpenASocket(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	conn, err := Socket(ctx, "127.0.0.1:53")
	if err == nil {
		conn.Close()
		t.Fatal("a socket was opened for a context that had already expired")
	}
}
