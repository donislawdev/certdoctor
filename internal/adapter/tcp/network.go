// Package tcp opens the connections layer L3 asks for.
//
// IT IS THE SECOND PLACE IN THIS PROGRAM THAT REACHES THE NETWORK, and the file
// below is on the dial allowlist for that reason. The list is short on purpose:
// the promise of inviolable rule 16 - this run reaches only what it was pointed
// at - is checkable exactly as long as the number of places that can open a
// socket stays small enough to read.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/donislawdev/certdoctor/internal/core/tcp"
)

// Connect turns the permission rule and the standard library into the port L3
// declared.
//
// THE RULE IS BORROWED, NEVER COPIED - ADR35. dial.Permission is the same
// function the DNS dialler asks, so "may this run reach that address" is decided
// in one place for the whole program. Writing the check again here would be the
// shape OBS50 measured, where a duplicated rule quietly disarmed three existing
// mutation entries by making each of them ambiguous.
//
// A NIL RULE REFUSES EVERYTHING, the same direction every other port in this
// program chose: a forgotten wire must read as a program that cannot reach
// anything, never as one with no restrictions.
func Connect(mayReach func(address string) error) tcp.Connect {
	return func(ctx context.Context, address string, port int) (io.Closer, error) {
		if mayReach == nil {
			return nil, tcp.ErrRefusedByRule
		}
		// ONE SPELLING FOR BOTH SIDES. The same function builds the string the
		// allowed set was given, so the address checked here and the address
		// dialled below cannot drift apart - the failure mode being every
		// connection refused on a machine where everything works.
		target, err := Target(address, port)
		if err != nil {
			return nil, tcp.ErrRefusedByRule
		}
		if err := mayReach(target); err != nil {
			// Deliberately not wrapped. The layer above distinguishes "we were
			// not allowed to try" from every network failure, and a refusal
			// carrying a network error inside it invites the two to be confused.
			return nil, tcp.ErrRefusedByRule
		}

		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, failure(err)
		}
		return conn, nil
	}
}

// failure maps whatever the operating system said onto the layer's sentinels.
//
// BY ERROR VALUE, NEVER BY MESSAGE TEXT - inviolable rule 19. A localised
// Windows or a future wording change would silently stop matching, and the layer
// would report every refused connection as a reset - a wrong diagnosis that
// looks exactly like a right one.
//
// THE ERRNO NAMES DIFFER PER PLATFORM AND THAT WAS MEASURED, NOT ASSUMED. The
// first version of this function compared against syscall.ECONNREFUSED alone,
// which on Windows matches NOTHING: a connection to a closed port arrives as
// WSAECONNREFUSED, and every refusal - the commonest diagnostic case there is -
// would have been reported as a reset. Measured by probe on this machine before
// the mapping was trusted, which is what inviolable rule 18 asks for and what
// this project keeps being right to ask for.
//
// THE DEFAULT IS reset RATHER THAN ANY OF THE DIAGNOSES. A failure nobody
// anticipated must not claim to be a refusal or a missing route, because both of
// those send a person somewhere specific.
func failure(err error) error {
	// The platform-specific errno names come first: they are the specific
	// diagnoses, and a timeout wrapping one of them would otherwise hide it.
	if mapped := platformFailure(err); mapped != nil {
		return mapped
	}
	var timeout net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return tcp.ErrTimeout
	case errors.As(err, &timeout) && timeout.Timeout():
		// A deadline the dialler enforced itself rather than one the context
		// carried. Both mean the same thing to a reader: we asked and nothing
		// came back in time.
		return tcp.ErrTimeout
	}
	return tcp.ErrReset
}

// Target is the address L3 will dial, spelled the one way both the allowed set
// and the dialler will see it.
//
// THE SAME STRING GOES INTO THE SET AND INTO THE DIALLER, which is the whole
// point of this function existing rather than the join happening twice. The set
// compares strings; two spellings of one address mean either a refusal on a
// working machine or a connection nothing checked. dns.Target exists for the
// same reason one layer up, and a test pins that pairing there too.
func Target(address string, port int) (string, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("%d is not a port", port)
	}
	return netip.AddrPortFrom(addr, uint16(port)).String(), nil
}
