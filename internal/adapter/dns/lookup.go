package dns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/dnsmsg"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
)

// Lookup builds the resolver a PAC file's dnsResolve, isResolvable and isInNet
// stand on.
//
// WHY THIS IS NOT L1 AND MUST NOT BECOME IT. L1 asks every resolver for every
// record type and reports what each one said, because the disagreement between
// them IS its finding. A PAC file asked a different question - "what does this
// name come out as" - and wants one answer, the way a browser's stub resolver
// gives one. Handing it L1's machinery would produce a layer result nobody
// consumes and several times the traffic, for a question with a single answer.
//
// IT ANSWERS THE CONTRACT pac.Ports WROTE DOWN, and the two failure directions
// are not interchangeable. An empty list means the name did not resolve, which
// includes NXDOMAIN and an answer with no records of either type; an error means
// nobody could be asked, which is every resolver refusing, failing or running out
// of time. The helpers turn the first into a browser-shaped "no" and the second
// into a state the layer refuses to build a verdict on, so collapsing them would
// let a run report a route worked out from a question it never got to ask.
//
// A IS ASKED BEFORE AAAA AND THE ORDER IS NOT COSMETIC. pac.Ports.DNSResolve
// hands the PAC file the first IPv4 address it can find, because that is what a
// browser's dnsResolve returns - ADR10 point 3. Asking A first means the common
// case costs one query rather than two, and the second is asked only when the
// name has no IPv4 at all, where an IPv6 answer is better than none.
//
// THE DEADLINE COVERS THE WHOLE CALL AND NOT ONE QUERY, and probe S16 is why.
// Measured 2026-09-07, three runs of three: the sandbox stopwatch does not
// interrupt a native call already running, but it does stop the next one from
// starting. So the budget a PAC evaluation can overrun by is exactly the longest
// single call into here - which makes that number worth holding directly. A
// per-query deadline would let one name cost resolvers times types times the
// deadline while still looking bounded.
func Lookup(exchange resolve.Exchange, resolvers []string, queryID func() uint16, budget time.Duration) func(host string) ([]string, error) {
	return func(host string) ([]string, error) {
		if exchange == nil || queryID == nil {
			return nil, errors.New("this build has no way to ask a resolver anything")
		}
		if len(resolvers) == 0 {
			return nil, errors.New("this machine lists no resolver to ask")
		}

		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()

		// answered records that somebody gave a complete, readable reply - with
		// or without records in it. It is what separates "this name does not
		// resolve" from "nothing usable came back", and those two go to the PAC
		// file as a browser-shaped no and as a refusal to decide.
		var answered bool
		var lastFailure error

		for _, resolver := range resolvers {
			for _, recordType := range []dnsmsg.Type{dnsmsg.TypeA, dnsmsg.TypeAAAA} {
				id := queryID()
				query, err := dnsmsg.Query(id, host, recordType)
				if err != nil {
					// The name cannot be put on the wire at all, and that is
					// true for every resolver and every type. It is also not a
					// failure to ask: nothing was asked and nothing will be, so
					// this is a name that does not resolve rather than a run
					// that could not look.
					return nil, nil
				}

				reply, err := exchange(ctx, resolver, query)
				if err != nil {
					lastFailure = err
					continue
				}

				message, err := dnsmsg.Parse(reply, id, host, recordType)
				if err != nil {
					// A reply arrived and could not be read as an answer to this
					// question. The next resolver still gets a turn, and this
					// does NOT count as having been answered - an unreadable
					// reply settles nothing about whether the name resolves.
					lastFailure = err
					continue
				}
				if message.Truncated {
					// A SHORTENED LIST IS REFUSED RATHER THAN USED, and dnsmsg
					// says why beside the bit: the answer did not fit and what
					// arrived looks complete. L1 refuses it for its own
					// comparison; here the cost of using it is sharper, because
					// isInNet asks whether an address falls in a subnet and the
					// address that would have matched may be one of the ones
					// that did not fit. That is a different branch of somebody's
					// PAC file taken on a truncated answer.
					lastFailure = fmt.Errorf(
						"resolver %s truncated its answer about %q, so what arrived is not the whole list", resolver, host)
					continue
				}
				if len(message.Addresses) > 0 {
					return message.Addresses, nil
				}
				answered = true
			}
		}

		if !answered {
			return nil, fmt.Errorf("no resolver on this machine gave a usable answer about %q: %w", host, lastFailure)
		}
		// Somebody answered in full and had no record of either type. That is a
		// name which does not resolve, which the PAC contract expresses as an
		// empty list rather than as a failure.
		return nil, nil
	}
}
