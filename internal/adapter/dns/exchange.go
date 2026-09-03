package dns

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/donislawdev/certdoctor/internal/adapter/dial"
	"github.com/donislawdev/certdoctor/internal/core/dnsmsg"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
)

// Exchange sends one query and reads one answer, and owns the socket for
// exactly that long.
//
// THE WHOLE LIFETIME OF THE SOCKET IS IN THIS ONE FUNCTION, and that is what
// makes the leak testable. Every way out of here - a refusal before anything was
// opened, a write that failed, a read that timed out, a reply that arrived -
// goes through the same close, so the test that counts handles has one place to
// look rather than one place per error.
//
// It takes a dialler rather than calling Socket, because the dialler it is given
// is dial.Guarded wrapped around Socket. That is the seam: a test hands it a
// recording stand-in, the entry point hands it the guarded real one, and the
// rule about where this program may connect is enforced before a packet exists.
func Exchange(dialer dial.Dialer) resolve.Exchange {
	return func(ctx context.Context, resolver string, query []byte) ([]byte, error) {
		address, err := Target(resolver)
		if err != nil {
			// A resolver that is not an address cannot be dialled, and saying so
			// here is better than handing a hostname to a dialler that would try
			// to resolve it - which would mean resolving a name in order to ask
			// how names resolve.
			return nil, fmt.Errorf("%q is not an address this program can send a query to: %w", resolver, err)
		}

		conn, err := dialer(ctx, address)
		if err != nil {
			return nil, translate(err)
		}
		defer conn.Close()

		if _, err := conn.Write(query); err != nil {
			return nil, translate(err)
		}

		// ONE STRAY DATAGRAM USED TO COST THE WHOLE ANSWER. This read the first
		// thing that arrived and closed the socket, so a datagram carrying
		// somebody else's identifier - a late reply to an earlier query of ours,
		// or an off-path packet with a forged source - became a row saying this
		// resolver answered a different question, while the real answer was still
		// on its way. dnsmsg's own comment on ErrNotOurs said as much and nothing
		// acted on it.
		//
		// THE LOOP IS NARROW ON PURPOSE, AND THE NARROWNESS IS THE WHOLE DESIGN.
		// It reads again only when the IDENTIFIER differs, which is the one case
		// where more may still be coming. A datagram carrying OUR identifier and
		// answering a different question is a resolver behaving badly - nothing
		// better is coming, and the layer still reports it as the stray it is,
		// through the path R-4 built. So this does not swallow that finding; it
		// stops the socket from being closed before the answer exists.
		//
		// IT CANNOT SPIN. The socket carries the deadline this run gave it, so a
		// resolver flooding us with mismatched datagrams ends as a timeout rather
		// than as an unreadable answer - which is the truer of the two sentences.
		wantID, known := dnsmsg.ID(query)
		answer := make([]byte, answerLimit)
		strays := 0
		for {
			// BYTES FIRST, ERROR SECOND, AND THAT IS THE io CONTRACT RATHER THAN
			// leniency. A Reader is allowed to hand back data AND io.EOF in the
			// same call, and the documented rule is that a caller processes the
			// n > 0 bytes before considering the error. The first version checked
			// the error first and threw away a complete answer that arrived that
			// way.
			//
			// A connected UDP socket does not do this - a datagram comes back with
			// a nil error - but the port is an io.ReadWriteCloser and the next
			// thing behind it might. Being wrong here is silent: the answer is
			// discarded and the row reads as a resolver that said nothing.
			read, err := conn.Read(answer)
			if read == 0 && err != nil {
				return nil, timedOutPast(translate(err), strays)
			}
			if !known {
				// We could not read our own query's identifier, so we are in no
				// position to judge anybody else's. Hand back what arrived and let
				// the layer's parser have the argument.
				return answer[:read], nil
			}
			if id, ok := dnsmsg.ID(answer[:read]); ok && id != wantID {
				strays++
				continue
			}
			return answer[:read], nil
		}
	}
}

// timedOutPast adds the count of mismatched datagrams to a failure they help
// explain.
//
// WHY IT GOES IN THE ERROR AND NOT IN A FIELD. The seam between this port and
// the layer is ([]byte, error) and thirty-one stand-ins in this tree are shaped
// like it; widening it for a rare diagnostic would be thirty-one mechanical
// edits to tests, which is how a test quietly stops asserting what it did.
//
// WHAT THAT LEAVES OUT, SAID PLAINLY: strays that arrive BEFORE a real answer
// are absorbed and never reported, because a successful exchange has nowhere to
// put them. The case worth hearing about is the one where they are the whole
// story, and that is this one.
func timedOutPast(err error, strays int) error {
	if strays == 0 {
		return err
	}
	return fmt.Errorf("%w, and %d datagram(s) answering a different question arrived while waiting", err, strays)
}

// translate maps what the network did onto the three failures the layer can tell
// apart.
//
// THE MAPPING HAPPENS HERE AND NOT IN THE CORE, because the types it reads -
// a refusal from dial.Guarded, a deadline from the operating system - live at
// this level and the core may not name them. What crosses the boundary is one of
// the layer's own sentinels, so the decision "which reason does the report show"
// stays where the report is built.
//
// ANYTHING UNRECOGNISED IS LEFT ALONE and becomes a transport error one floor
// down. A failure nobody anticipated is better reported as having happened on the
// wire than as one we claimed to understand.
func translate(err error) error {
	var refusal *dial.Refusal
	switch {
	case errors.As(err, &refusal):
		// OUR OWN RULE, NOT THEIR NETWORK. Reporting this as a transport failure
		// would accuse a working resolver of being unreachable, and the person
		// reading it would go and check their firewall.
		return fmt.Errorf("%w: %s", resolve.ErrRefused, refusal.Error())
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		// SILENCE, WHICH IS NOT SERVFAIL. A forward to an unroutable address
		// produces exactly this and nothing else - measured on the coredns bench,
		// docs/17 section 6d - and it sends a person to a different place than a
		// resolver that answered badly.
		return fmt.Errorf("%w: %v", resolve.ErrTimeout, err)
	}
	return err
}
