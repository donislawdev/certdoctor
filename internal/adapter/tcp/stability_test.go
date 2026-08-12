package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	coretcp "github.com/donislawdev/certdoctor/internal/core/tcp"
)

// The stability run docs/22 section 6a asks for, on the adapter's side of the
// seam - the half that holds a real socket rather than a stand-in.
//
// WHAT IS CHECKABLE HERE IS NARROWER THAN "no descriptor leaked", and saying so
// is the point. Counting handles is not portable, so this side proves the
// property the core's unconditional close DEPENDS ON: no path ever hands back a
// connection together with an error, and no path hands back neither. If either
// were false, the core closing whatever it was given would be closing nothing
// while a socket stayed open somewhere it cannot see.
//
// SECOND REASON THIS RUN EXISTS BEFORE THE FAN-OUT. Everything below is called
// once per address today and will be called from several goroutines at once
// tomorrow. The permission rule reads a map with no writer - checked, not
// assumed: the recorder is nil at every call site in main.go - and the check
// below is what turns that reading into a measurement under the race detector.

// bench is a listener that accepts and closes, and counts what it saw.
type bench struct {
	listener net.Listener
	accepted atomic.Int64
	host     string
	port     int
}

func startBench(t *testing.T) *bench {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("NOT CHECKED: no loopback port available (%v).", err)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	number := 0
	if _, err := fmt.Sscanf(port, "%d", &number); err != nil {
		t.Fatalf("reading the port back: %v", err)
	}

	b := &bench{listener: listener, host: host, port: number}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			b.accepted.Add(1)
			conn.Close()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return b
}

// permitting is a stand-in for the permission rule that permits this bench and
// nothing else, spelled by the one function both sides of the comparison use.
//
// A STAND-IN RATHER THAN dial.Permission, AND THE GUARD IS RIGHT TO INSIST. The
// file under test takes the rule as a parameter and deliberately does not import
// dial - that is what keeps this package free of the rule and the rule free of
// the plumbing (ADR35). A test reaching for the real one would declare a sideways
// edge the product does not have, and structural declarations made for a test
// stay declared. What is checked here is Connect. The real rule's behaviour under
// several callers at once is checked where the real rule lives, in
// internal/adapter/dial.
func (b *bench) permitting(t *testing.T) func(string) error {
	t.Helper()

	target, err := Target(b.host, b.port)
	if err != nil {
		t.Fatalf("the bench address will not spell: %v", err)
	}
	return func(asked string) error {
		if asked != target {
			return fmt.Errorf("%s is not the one address this test permits", asked)
		}
		return nil
	}
}

// TestNoPathHandsBackAConnectionAndAnErrorTogether is check (a).
//
// THE CORE CLOSES WHATEVER IT IS GIVEN WITHOUT ASKING WHETHER err IS NIL, which
// is right and was paid for once. This is the same rule read from the other end:
// nothing here may hand back a socket it also calls a failure, because then the
// two sides disagree about whether anything exists.
func TestNoPathHandsBackAConnectionAndAnErrorTogether(t *testing.T) {
	b := startBench(t)
	mayReach := b.permitting(t)

	// A port nothing listens on, taken by opening one and closing it, so the
	// refusal is a real errno from this machine rather than a stand-in.
	spare, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("NOT CHECKED: no second loopback port available (%v).", err)
	}
	closedHost, closedPort, _ := net.SplitHostPort(spare.Addr().String())
	closedNumber := 0
	fmt.Sscanf(closedPort, "%d", &closedNumber)
	spare.Close()

	for _, c := range []struct {
		name     string
		rule     func(string) error
		address  string
		port     int
		wantConn bool
	}{
		{"no permission rule at all", nil, b.host, b.port, false},
		{"a name where an address belongs", mayReach, "example.com", b.port, false},
		{"a port outside the range", mayReach, b.host, 0, false},
		{"an address outside the allowed set", mayReach, "192.0.2.10", 443, false},
		{"a real refusal from a closed port", func(string) error { return nil }, closedHost, closedNumber, false},
		{"the ordinary path", mayReach, b.host, b.port, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			conn, err := Connect(c.rule)(context.Background(), c.address, c.port)

			if err != nil && conn != nil {
				conn.Close()
				t.Fatalf("a failure came back holding a connection: %v", err)
			}
			if err == nil && conn == nil {
				t.Fatal("nothing came back and nothing failed, so the caller has neither a connection nor a reason")
			}
			if got := conn != nil; got != c.wantConn {
				t.Fatalf("a connection came back: %v, expected %v (err %v)", got, c.wantConn, err)
			}
			if conn != nil {
				var _ io.Closer = conn
				if err := conn.Close(); err != nil {
					t.Errorf("closing what we opened failed: %v", err)
				}
			}
		})
	}
}

// TestManyConnectionsReleasedAtOnceAreAllClosed is check (b), and it is the one
// that rehearses tomorrow.
//
// THIRTY-TWO CALLS LET GO BY ONE close(start) hit the permission rule and the
// dialler together rather than in single file - which is exactly what the fan-out
// will do to them. Under the race detector this is what turns "Permits is a map
// read with no writer" from a reading of the code into a measurement.
func TestManyConnectionsReleasedAtOnceAreAllClosed(t *testing.T) {
	const callers = 32

	b := startBench(t)
	connect := Connect(b.permitting(t))

	var opened, closed, both atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start

			conn, err := connect(context.Background(), b.host, b.port)
			if err != nil && conn != nil {
				both.Add(1)
			}
			if conn != nil {
				opened.Add(1)
				if conn.Close() == nil {
					closed.Add(1)
				}
				return
			}
			if err == nil {
				t.Errorf("caller %d got neither a connection nor a reason", i)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	if both.Load() != 0 {
		t.Errorf("%d caller(s) were handed a connection together with an error", both.Load())
	}
	if opened.Load() != callers {
		t.Errorf("%d of %d callers reached a listening port on loopback", opened.Load(), callers)
	}
	if closed.Load() != opened.Load() {
		t.Errorf("%d connection(s) opened and %d closed cleanly", opened.Load(), closed.Load())
	}
}

// TestDegenerateButLegalAddressesAreAnswered is check (c) - state (D) from
// docs/02, and every one of these can arrive from a resolver.
//
// NONE OF THEM MAY HANG, PANIC OR COME BACK AMBIGUOUS. The answer for most of
// them is a refusal by our own rule, because the allowed set holds one spelling
// and these are others - which is correct and is the reason both sides go through
// the same Target function.
func TestDegenerateButLegalAddressesAreAnswered(t *testing.T) {
	b := startBench(t)
	connect := Connect(b.permitting(t))

	for _, address := range []string{
		"fe80::1%eth0",
		"::ffff:127.0.0.1",
		"::1",
		"0.0.0.0",
		"255.255.255.255",
		"",
	} {
		t.Run(fmt.Sprintf("%q", address), func(t *testing.T) {
			conn, err := connect(context.Background(), address, b.port)
			if conn != nil {
				conn.Close()
				t.Fatalf("%q was dialled, and it is not what the set was told to permit", address)
			}
			if err == nil {
				t.Fatalf("%q came back with neither a connection nor a reason", address)
			}
			// A refusal by our own rule is a fact about us, never about their
			// network, and the layer above tells the two apart by this sentinel.
			if err != coretcp.ErrRefusedByRule {
				t.Errorf("%q was refused as %v rather than by our own rule", address, err)
			}
		})
	}
}

// TestNothingDriftsAcrossRepeatedConnections is check (d).
//
// SAMPLED IN WINDOWS, because a machine that starts refusing after a hundred
// connections - a descriptor ceiling, a port range exhausted - looks identical to
// a healthy one in a total read once at the end.
func TestNothingDriftsAcrossRepeatedConnections(t *testing.T) {
	const windows, perWindow = 8, 25

	b := startBench(t)
	connect := Connect(b.permitting(t))

	for window := 1; window <= windows; window++ {
		for call := 0; call < perWindow; call++ {
			conn, err := connect(context.Background(), b.host, b.port)
			if err != nil {
				t.Fatalf("window %d of %d, call %d: loopback stopped accepting - %v",
					window, windows, call, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatalf("window %d of %d, call %d: closing failed - %v", window, windows, call, err)
			}
		}
	}

	// THE BENCH'S OWN COUNT IS READ AND DELIBERATELY NOT COMPARED TO THE NUMBER
	// DIALLED, because that comparison is a race in the instrument rather than a
	// fact about the code. The kernel completes the handshake into the accept
	// backlog, so a dial returns before Accept has returned on the other side -
	// measured here as 199 of 200 on the first run, which reads like a lost
	// connection and is not one. What the loop above asserts is the half that is
	// deterministic: every one of the two hundred opened and closed cleanly.
	if b.accepted.Load() == 0 {
		t.Error("the bench accepted nothing at all, so the loop above was measuring something other than a connection")
	}
}
