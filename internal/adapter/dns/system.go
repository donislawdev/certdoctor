package dns

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
)

// System asks the platform to resolve a name the way any other program on this
// machine would, and reports which resolver actually did the work.
//
// IT IS THE SECOND FILE IN THIS PROGRAM ABLE TO OPEN A CONNECTION, and the
// second entry on the dial allowlist. The first is network.go, the socket L1
// sends its own queries out of. Two is still a number somebody can hold in their
// head, and that is what makes inviolable rule 16 - certdoctor connects only to
// what it derived from the user's own question - a promise that can be checked
// rather than one that has to be believed.
//
// WHY IT CANNOT GO THROUGH dial.Guarded LIKE EVERYTHING ELSE. net.Resolver takes
// a dialler of its own shape - func(ctx, network, address) (net.Conn, error) -
// and ours is func(ctx, address) (io.ReadWriteCloser, error). The two differ in
// the network parameter and in the return type. Reshaping ours would drag net
// into a package that deliberately does not import it, and would be a weakening
// of an existing guard rather than a use of it (ADR35). So this file asks the
// SAME rule instead: dial.Permission is where the refusal lives, and both
// diallers consume it rather than each carrying a copy - the shape OBS50
// measured, where a copied rule turned three mutation entries into SKIP.
//
// THE ANSWER IS NOT ALWAYS THE PLATFORM'S, AND SAYING WHICH IS THE POINT. When
// Go's own resolver does the work, our dialler is called and the row is derived
// rather than observed (ADR28). Nothing here asks the operating system what it
// is, or how this binary was built: probe S10 measured a cgo-enabled binary on
// glibc going through Go's resolver anyway, so both of those questions have
// wrong answers available.
func System(mayReach func(address string) error) resolve.SystemLookup {
	return func(ctx context.Context, name string) resolve.SystemAnswer {
		seen := &dialFacts{}
		resolver := &net.Resolver{
			// PreferGo false means "use the platform's resolver if there is one".
			// Whether there is one is not ours to decide and not knowable up
			// front - it is answered by whether the dialler below gets called.
			PreferGo: false,
			Dial:     guardedDial(seen, mayReach),
		}

		addresses, err := resolver.LookupHost(ctx, name)
		return resolve.SystemAnswer{
			Addresses:   addresses,
			ViaPlatform: seen.wentThroughThePlatform(),
			NoAnswer:    systemNoAnswer(err, seen.refusal()),
		}
	}
}

// guardedDial is the dialler net.Resolver is handed: it records that it was
// called at all, asks the shared rule, and only then opens anything.
//
// IT IS A NAMED FUNCTION RATHER THAN A CLOSURE INSIDE System, and the reason is
// that a closure there can only be reached on a machine where the platform hands
// the work to Go's resolver. Probe S10 measured that Windows never does, so the
// coverage of an inline version would depend on which system the gate ran on -
// green here, red there, and neither answer about the code. Named, it is called
// directly by a test on every platform.
func guardedDial(seen *dialFacts, mayReach func(address string) error) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// FIRST, BEFORE ANY DECISION. Being called at all is the fact that decides
		// detected against derived, and it is true whether or not the address is
		// then permitted - a refusal still happened on the path through our own
		// resolver.
		seen.ourResolverIsDoingTheWork()

		if mayReach == nil {
			// A missing rule refuses everything, exactly as a missing allowed set
			// does in dial.Guarded. A forgotten wire has to read as a program that
			// cannot connect, never as one with no restrictions.
			err := errors.New("no permission rule was supplied, so the system view was not allowed to ask anything")
			seen.refusedBy(err)
			return nil, err
		}
		if err := mayReach(address); err != nil {
			seen.refusedBy(err)
			return nil, err
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}
}

// dialFacts is what one lookup learned about itself, written by somebody else's
// goroutines.
//
// THE LOCK IS HERE BECAUSE net.Resolver CALLS OUR DIALLER IN PARALLEL, and that
// is measured rather than assumed: in alpine, three runs of three, the A and the
// AAAA query overlapped in time. This file is on the lock-only allowlist in
// internal/guard for that reason - it may hold this mutex, and it still may not
// start a goroutine, open a channel or select, which the guard goes on checking.
// Nothing in this program runs the system view in parallel. The parallelism is
// the standard library's and arrives through a callback.
type dialFacts struct {
	mu       sync.Mutex
	ourDial  bool
	refusedA error
}

func (d *dialFacts) ourResolverIsDoingTheWork() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ourDial = true
}

// refusedBy keeps the FIRST refusal. A lookup that is refused twice was refused
// once for the reader, and the first one is the one that decided the outcome.
func (d *dialFacts) refusedBy(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.refusedA == nil {
		d.refusedA = err
	}
}

// wentThroughThePlatform is the inverse of "our dialler was called", and the
// inversion is the whole measurement - probe S10 and S11.
func (d *dialFacts) wentThroughThePlatform() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.ourDial
}

func (d *dialFacts) refusal() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.refusedA
}

// systemNoAnswer maps what the platform said onto the closed list of reasons.
//
// A NAME THAT DOES NOT EXIST IS AN ANSWER AND NOT A FAILURE, which is the one
// mapping here worth arguing about. The platform told us the name does not
// resolve - it just cannot tell us whether that was NXDOMAIN or an empty record
// set, which is precisely the distinction the direct view exists to make. So the
// row carries no reason and no addresses, and reads as what it is: this view
// asked, and got nothing to point at.
func systemNoAnswer(err, refusal error) report.NoAnswer {
	if err == nil {
		return ""
	}
	if refusal != nil {
		return report.NoAnswerRefusedByRule
	}

	var resolverErr *net.DNSError
	if errors.As(err, &resolverErr) {
		switch {
		case resolverErr.IsTimeout:
			return report.NoAnswerTimeout
		case resolverErr.IsNotFound:
			return ""
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return report.NoAnswerTimeout
	}
	return report.NoAnswerTransportError
}
