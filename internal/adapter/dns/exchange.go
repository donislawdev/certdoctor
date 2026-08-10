package dns

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/donislawdev/certdoctor/internal/adapter/dial"
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

		answer := make([]byte, answerLimit)
		read, err := conn.Read(answer)
		// BYTES FIRST, ERROR SECOND, AND THAT IS THE io CONTRACT RATHER THAN
		// leniency. A Reader is allowed to hand back data AND io.EOF in the same
		// call, and the documented rule is that a caller processes the n > 0
		// bytes before considering the error. The first version checked the error
		// first and threw away a complete answer that arrived that way.
		//
		// A connected UDP socket does not do this - a datagram comes back with a
		// nil error - but the port is an io.ReadWriteCloser and the next thing
		// behind it might. Being wrong here is silent: the answer is discarded and
		// the row reads as a resolver that said nothing.
		if read == 0 && err != nil {
			return nil, translate(err)
		}
		return answer[:read], nil
	}
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
