// Package dns is the plumbing behind L1: the socket a query goes out of, and
// the list of resolvers this machine is configured to use.
//
// IT HOLDS NO RULES. Where this program may connect is decided by the allowed
// set and enforced by dial.Guarded, which sits in front of the dialler below.
// How an answer is read is decided by dnsmsg, in the core, where hostile bytes
// are the normal case. What is left here is the part that has to talk to the
// operating system, and it is deliberately small enough to read in one sitting.
//
// THE NAME IS dns AND THE CORE PACKAGE IS dnsmsg, WHICH IS NOT AN ACCIDENT.
// That one encodes and decodes a message and resolves nothing. This one resolves
// nothing either - it carries bytes to a resolver and back - but it is the piece
// that owns a socket, and a package that owns a resource is worth being able to
// name in a sentence about leaks.
package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
)

// Socket opens a UDP association to one resolver.
//
// IT IS THE ONLY FUNCTION IN THIS PROGRAM THAT OPENS A CONNECTION, and this file
// is the only entry on the dial allowlist in reach_test.go. Inviolable rule 16 -
// that a diagnostic tool reading somebody's trust stores does not phone home -
// is a promise a user cannot check for themselves, and what makes it checkable
// is that the number of places able to start a connection stays countable.
//
// IT IS NOT CALLED DIRECTLY. The entry point wraps it in dial.Guarded, which
// refuses any address the run did not derive from the user's own question before
// this function is ever reached.
//
// THE DEADLINE IS SET HERE, ON THE SOCKET, BEFORE THE HANDLE IS HANDED OVER, and
// that is the whole reason this function is not one line. The port hands back an
// io.ReadWriteCloser, which has no SetDeadline - so cancelling the context would
// NOT interrupt a blocking read from the socket, and a resolver that accepts a
// packet and never answers would hang the run past every budget it has.
func Socket(ctx context.Context, address string) (io.ReadWriteCloser, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	deadline, set := ctx.Deadline()
	if !set {
		// Every caller in this program arrives with one, because the layer works
		// out how long a single query may take before it asks. A caller without
		// one gets a socket that can block, which is worse than a refusal - so it
		// is refused, and the socket that was already open is closed on the way
		// out rather than left behind.
		conn.Close()
		return nil, errNoDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		// THE LEAK PATH THAT LOOKS LIKE NOTHING. The socket exists by now, the
		// caller never sees it, and without this close it stays open until the
		// process ends - docs/22 section 6a, point (a): the easiest place to leak
		// is the one where something already went wrong.
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Target turns a resolver address into the string a dialler is given.
//
// IT EXISTS SO THAT THE ALLOWED SET AND THE DIALLER CANNOT DISAGREE. The set
// stores and compares strings, so if the entry point allowed "1.1.1.1" and this
// package dialled "1.1.1.1:53", the guard would refuse every query - and if it
// allowed the port form while something else dialled the bare one, the guard
// would pass while the connection went somewhere it was never checked against.
// One function, both callers.
//
// The bracket form for IPv6 comes from netip rather than from net.JoinHostPort
// deliberately: this is the only file allowed to import net, and a helper needed
// by the entry point should not be the reason that list grows.
func Target(resolver string) (string, error) {
	addr, err := netip.ParseAddr(resolver)
	if err != nil {
		return "", err
	}
	// A zone identifier survives - fe80::1%eth0 is a legitimate entry in
	// resolv.conf, and what the file says is what the report shows.
	return netip.AddrPortFrom(addr, dnsPort).String(), nil
}

// dnsPort is not configurable today.
//
// A resolver listening somewhere else is a real thing and this program does not
// support asking about one yet. Naming the constant rather than spelling the
// number at both call sites is the cheap half of being ready for that.
const dnsPort = 53

// errNoDeadline is refused rather than tolerated - see Socket.
var errNoDeadline = errors.New("a query was to be sent with no deadline, and a socket that can block forever " +
	"would outlive every budget this run has")

// answerLimit is how many bytes of a reply are read.
//
// WITHOUT EDNS0 THE PROTOCOL CAPS AN ANSWER AT 512 BYTES and a bigger one comes
// back with the truncation bit set, which this program reports rather than acts
// on. The buffer is larger than that on purpose: a resolver that ignores the cap
// and sends more would otherwise have its reply cut at exactly the point where
// the parser stops making sense, and "the packet is malformed" is a worse answer
// than "here is what arrived". It is still a cap, because the alternative is
// letting whoever answered on port 53 decide how much memory we allocate.
const answerLimit = 4096
