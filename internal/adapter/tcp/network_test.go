package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	coretcp "github.com/donislawdev/certdoctor/internal/core/tcp"
)

// TestTargetSpellsAnAddressTheOneWayBothSidesWillSeeIt is the pairing that cost
// a real defect: the allowed set holds strings, so the address permitted and the
// address dialled have to be identical, character for character.
//
// The first version of this layer passed a bare address to the permission rule
// while the set held address and port joined - so every connection came back
// refused_by_rule on a machine where everything works, and the guard looked like
// it was doing its job.
func TestTargetSpellsAnAddressTheOneWayBothSidesWillSeeIt(t *testing.T) {
	cases := []struct {
		address string
		port    int
		want    string
	}{
		{"192.0.2.10", 443, "192.0.2.10:443"},
		// IPv6 gets brackets, which is exactly the sort of difference two
		// separate join sites drift apart on.
		{"2001:db8::10", 443, "[2001:db8::10]:443"},
		{"192.0.2.10", 8080, "192.0.2.10:8080"},
	}
	for _, tc := range cases {
		got, err := Target(tc.address, tc.port)
		if err != nil {
			t.Errorf("%s:%d refused: %v", tc.address, tc.port, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s:%d spelled as %q, want %q", tc.address, tc.port, got, tc.want)
		}
	}

	// A name is not an address, and neither is a port outside the range. Both
	// are refused rather than joined into something nothing can dial.
	if _, err := Target("example.com", 443); err == nil {
		t.Error("a host name was accepted where an address belongs")
	}
	for _, port := range []int{0, 65536, -1} {
		if _, err := Target("192.0.2.10", port); err == nil {
			t.Errorf("port %d was accepted", port)
		}
	}
}

// TestARefusalByOurOwnRuleNeverReachesTheNetwork is inviolable rule 16 at the
// one place that can break it.
func TestARefusalByOurOwnRuleNeverReachesTheNetwork(t *testing.T) {
	asked := []string{}
	connect := Connect(func(address string) error {
		asked = append(asked, address)
		return errors.New("not in the allowed set")
	})

	conn, err := connect(context.Background(), "192.0.2.10", 443)
	if conn != nil {
		t.Error("a refused address still produced a connection")
	}
	if !errors.Is(err, coretcp.ErrRefusedByRule) {
		t.Errorf("a refusal by our own rule came back as %v, which reads as a network failure", err)
	}
	// The rule is asked about the SAME string the dialler would have used.
	if len(asked) != 1 || asked[0] != "192.0.2.10:443" {
		t.Errorf("the permission rule was asked about %v, and the dialler would use 192.0.2.10:443", asked)
	}

	// A missing rule refuses everything rather than permitting everything: a
	// forgotten wire must not widen what this program may reach.
	if _, err := Connect(nil)(context.Background(), "192.0.2.10", 443); !errors.Is(err, coretcp.ErrRefusedByRule) {
		t.Errorf("a nil rule answered %v, and it has to refuse", err)
	}

	// An address that cannot be spelled is refused too - nothing can dial it.
	if _, err := Connect(func(string) error { return nil })(context.Background(), "example.com", 443); !errors.Is(err, coretcp.ErrRefusedByRule) {
		t.Errorf("a host name reached the dialler: %v", err)
	}
}

// TestFailureNamesWhatHappenedRatherThanGuessing covers the mapping by VALUE,
// which is the whole reason it is not written against message text - inviolable
// rule 19. A localised Windows would silently stop matching a text rule, and
// every refusal would be reported as a reset.
func TestFailureNamesWhatHappenedRatherThanGuessing(t *testing.T) {
	// A real refusal from this platform, produced rather than invented: bind a
	// port, learn its number, close it, then connect to it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("NOT CHECKED: this machine would not lend a loopback port (%v), so the mapping was not exercised.", err)
	}
	closed := listener.Addr().String()
	listener.Close()

	var dialer net.Dialer
	_, dialErr := dialer.DialContext(context.Background(), "tcp", closed)
	if dialErr == nil {
		t.Skip("NOT CHECKED: something answered on a port that was just closed, so there was no refusal to map.")
	}
	if got := failure(dialErr); !errors.Is(got, coretcp.ErrRefused) {
		t.Errorf("a refused connection was mapped to %v - the commonest case in this layer, named wrongly", got)
	}

	// A deadline that has already passed, which every platform expresses the
	// same way because it never reaches the network at all.
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	_, ctxErr := dialer.DialContext(expired, "tcp", closed)
	if ctxErr != nil && failure(ctxErr) == nil {
		t.Error("a cancelled attempt mapped to nothing")
	}

	// Anything nobody wrote a case for must not claim to be a diagnosis: reset
	// says the wire did something, refused and unreachable send a person
	// somewhere specific.
	if got := failure(errors.New("something new")); !errors.Is(got, coretcp.ErrReset) {
		t.Errorf("an unrecognised failure was mapped to %v, want a reset", got)
	}
	if got := failure(context.DeadlineExceeded); !errors.Is(got, coretcp.ErrTimeout) {
		t.Errorf("a deadline was mapped to %v", got)
	}
}

// TestAConnectionThatOpensIsHandedBackClosable is the ordinary path, without
// which every check above is satisfied by a port that never connects.
func TestAConnectionThatOpensIsHandedBackClosable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("NOT CHECKED: no loopback port available (%v).", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	host, port, _ := net.SplitHostPort(listener.Addr().String())
	number := 0
	if _, err := fmt.Sscanf(port, "%d", &number); err != nil {
		t.Fatalf("reading the port back: %v", err)
	}

	conn, err := Connect(func(string) error { return nil })(context.Background(), host, number)
	if err != nil {
		t.Fatalf("a listening port refused the connection: %v", err)
	}
	if conn == nil {
		t.Fatal("the connection opened and nothing came back to close")
	}
	if err := conn.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
		t.Errorf("closing what we opened failed: %v", err)
	}
	var _ io.Closer = conn
}
