package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/dial"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
)

// countingConn is a socket that remembers whether it was closed.
//
// IT IS THE WHOLE POINT OF THE LEAK TESTS BELOW. Counting real handles is not
// portable and would answer a question about the operating system anyway. What
// has to be true of OUR code is that every path out closes what it was given,
// and that is what this can see.
type countingConn struct {
	closed    int
	written   []byte
	reply     []byte
	writeFail error
	readFail  error
}

func (c *countingConn) Write(p []byte) (int, error) {
	if c.writeFail != nil {
		return 0, c.writeFail
	}
	c.written = append(c.written, p...)
	return len(p), nil
}

func (c *countingConn) Read(p []byte) (int, error) {
	if c.readFail != nil {
		return 0, c.readFail
	}
	return copy(p, c.reply), io.EOF
}

func (c *countingConn) Close() error {
	c.closed++
	return nil
}

func handing(conn *countingConn) dial.Dialer {
	return func(context.Context, string) (io.ReadWriteCloser, error) { return conn, nil }
}

// TestTargetGivesTheSameStringToTheGuardAndTheDialler is the rule that stops the
// allowed set and the dialler from disagreeing.
func TestTargetGivesTheSameStringToTheGuardAndTheDialler(t *testing.T) {
	cases := []struct {
		resolver string
		want     string
	}{
		{"1.1.1.1", "1.1.1.1:53"},
		{"2001:db8::1", "[2001:db8::1]:53"},
		// A zone identifier is legitimate in resolv.conf and survives, because
		// what the file says is what the report shows.
		{"fe80::1%eth0", "[fe80::1%eth0]:53"},
	}
	for _, c := range cases {
		got, err := Target(c.resolver)
		if err != nil {
			t.Errorf("%s was refused: %v", c.resolver, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s became %q and should be %q", c.resolver, got, c.want)
		}
	}

	// A name rather than an address is refused HERE rather than handed to a
	// dialler, because resolving it would mean resolving a name in order to ask
	// how names resolve.
	if _, err := Target("dns.example.com"); err == nil {
		t.Error("a host name was accepted as a resolver address")
	}
}

// TestTheSocketIsClosedOnEveryPathOut is docs/22 section 6a point (a): the
// easiest place to leak is the one where something already went wrong.
func TestTheSocketIsClosedOnEveryPathOut(t *testing.T) {
	cases := []struct {
		name string
		conn *countingConn
	}{
		{"the answer came back", &countingConn{reply: []byte{1, 2, 3}}},
		{"the write failed", &countingConn{writeFail: errors.New("send failed")}},
		{"the read failed", &countingConn{readFail: errors.New("receive failed")}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _ = Exchange(handing(c.conn))(context.Background(), "1.1.1.1", []byte{0, 1})
			if c.conn.closed != 1 {
				t.Errorf("the socket was closed %d times where %s", c.conn.closed, c.name)
			}
		})
	}
}

// TestNothingIsOpenedWhenThereIsNothingToOpen is the other side: a path that
// never got a socket must not pretend it closed one, and must not dial at all.
func TestNothingIsOpenedWhenThereIsNothingToOpen(t *testing.T) {
	dialled := 0
	exchange := Exchange(func(context.Context, string) (io.ReadWriteCloser, error) {
		dialled++
		return nil, errors.New("the dialler should not have been reached")
	})

	if _, err := exchange(context.Background(), "not-an-address", []byte{0, 1}); err == nil {
		t.Error("a resolver that is not an address was dialled")
	}
	if dialled != 0 {
		t.Errorf("the dialler was called %d times for an address that cannot exist", dialled)
	}
}

// TestEachFailureKeepsTheMeaningTheLayerNeeds is the mapping ADR30 rests on.
//
// A refusal by our own rule, silence and an ordinary network failure send a
// person to three different places. Translating them all into one would send
// everybody to the wrong one, and the refusal is the worst of the three to get
// wrong: it would accuse a working resolver of being unreachable.
func TestEachFailureKeepsTheMeaningTheLayerNeeds(t *testing.T) {
	cases := []struct {
		name  string
		fails error
		want  error
	}{
		{"our own set refused the address", &dial.Refusal{Address: "1.1.1.1:53"}, resolve.ErrRefused},
		{"the socket deadline passed", fmt.Errorf("read udp: %w", context.DeadlineExceeded), resolve.ErrTimeout},
		{"the network failed", errors.New("network is unreachable"), nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			exchange := Exchange(func(context.Context, string) (io.ReadWriteCloser, error) { return nil, c.fails })
			_, err := exchange(context.Background(), "1.1.1.1", []byte{0, 1})
			if err == nil {
				t.Fatal("the failure was swallowed")
			}
			if c.want == nil {
				if errors.Is(err, resolve.ErrRefused) || errors.Is(err, resolve.ErrTimeout) {
					t.Errorf("an unrecognised failure was reported as one we understood: %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Errorf("%s came back as %v", c.name, err)
			}
		})
	}
}

// TestTheRefusalStillSaysWhatItWas keeps the original wording reachable. A
// sentinel that replaced the message would tell the layer which kind of failure
// it was and leave the reader with nothing to act on.
func TestTheRefusalStillSaysWhatItWas(t *testing.T) {
	refusal := &dial.Refusal{Address: "203.0.113.1:53"}
	exchange := Exchange(func(context.Context, string) (io.ReadWriteCloser, error) { return nil, refusal })

	_, err := exchange(context.Background(), "203.0.113.1", []byte{0, 1})
	if !strings.Contains(err.Error(), "203.0.113.1:53") {
		t.Errorf("the refusal lost the address it was about: %v", err)
	}
}

// TestTheQueryReachesTheSocketAndTheAnswerComesBack is the ordinary path, which
// every test above would pass without.
func TestTheQueryReachesTheSocketAndTheAnswerComesBack(t *testing.T) {
	conn := &countingConn{reply: []byte{9, 9, 9}}
	query := []byte{0, 7, 1, 0}

	answer, err := Exchange(handing(conn))(context.Background(), "1.1.1.1", query)
	if err != nil {
		t.Fatalf("an ordinary exchange failed: %v", err)
	}
	if string(conn.written) != string(query) {
		t.Errorf("the socket received %v where the query was %v", conn.written, query)
	}
	if string(answer) != string(conn.reply) {
		t.Errorf("the answer came back as %v where the socket held %v", answer, conn.reply)
	}
}

// TestAnOverlongReplyIsCutRatherThanTrusted covers the cap.
//
// Without EDNS0 the protocol caps an answer at 512 bytes, so anything this long
// is a resolver ignoring the rules - and the alternative to a cap is letting
// whoever answered on port 53 decide how much memory this program allocates.
func TestAnOverlongReplyIsCutRatherThanTrusted(t *testing.T) {
	conn := &countingConn{reply: make([]byte, answerLimit*4)}
	answer, err := Exchange(handing(conn))(context.Background(), "1.1.1.1", []byte{0, 1})
	if err != nil {
		t.Fatalf("a long reply failed instead of being cut: %v", err)
	}
	if len(answer) > answerLimit {
		t.Errorf("the reply came back as %d bytes with a cap of %d", len(answer), answerLimit)
	}
}

// TestASocketWithNoDeadlineIsRefusedRatherThanOpened covers the branch that
// exists because the port hands back an io.ReadWriteCloser.
//
// There is no SetDeadline on that interface, so cancelling the context would not
// interrupt a blocking read. A socket opened without a deadline could therefore
// outlive every budget the run has, and the one already opened is closed on the
// way out rather than left behind.
func TestASocketWithNoDeadlineIsRefusedRatherThanOpened(t *testing.T) {
	conn, err := Socket(context.Background(), "127.0.0.1:53")
	if err == nil {
		conn.Close()
		t.Fatal("a socket was opened with no deadline, so a silent resolver could hang the run")
	}
	if !strings.Contains(err.Error(), "no deadline") {
		t.Errorf("the refusal reads %q and does not say what was missing", err)
	}
}

// TestASocketWithADeadlineIsOpened is the other side, and without it the check
// above could be satisfied by a function that never opens anything.
func TestASocketWithADeadlineIsOpened(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// A connected UDP socket to the loopback sends nothing and needs nobody
	// listening, so this opens a real handle without a packet leaving.
	conn, err := Socket(ctx, "127.0.0.1:53")
	if err != nil {
		t.Fatalf("a socket with a deadline was refused: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("closing it failed: %v", err)
	}
}
