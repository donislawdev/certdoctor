// Package fanout runs a fixed set of independent attempts side by side.
//
// IT IS THE ONLY PLACE IN THIS PROGRAM THAT STARTS A GOROUTINE, and it is one
// function long on purpose - ADR43. The layers that use it keep every decision
// they make in files that stay under the concurrency guard in full.
//
// WHY IT IS A PACKAGE RATHER THAN A FUNCTION IN EACH LAYER. L3 opens a
// connection per address and L4 completes a handshake per address, and the rule
// they share - "results are placed by position, at most eight at a time, and
// every goroutine is waited for" - is one rule. Written twice it would be one
// rule living in two places, which is the measured shape of OBS50: a copy of a
// boundary function disarmed three existing mutation entries at once and
// reported them as SKIP, a difference of one number in a summary nobody reads
// closely. The same move ADR35 made for dial.Permission.
//
// It knows nothing about findings, addresses or layers. That is what lets both
// layers use it without either of them learning about the other.
package fanout

import (
	"fmt"
	"sync"
)

// AtOnce caps how many attempts are in flight at the same time.
//
// IT IS A CEILING RATHER THAN TUNING, AND BOTH NUMBERS BEHIND IT WERE MEASURED.
// The count of attempts comes from somebody else's resolver, so without a cap
// THEY decide how many sockets this machine opens at once. The widest real
// answer measured in this project is four addresses (example.com, P5a), while
// the protocol's ceiling without EDNS0 is a 512 byte response - roughly thirty A
// records - and a layer is handed the union of both DNS views with duplicates
// left in. Fifty simultaneous connections to one host is the shape of a scanner,
// and how an EDR reacts to this tool is still an open question (O6), in exactly
// the environments it is meant to be run in.
//
// Eight is twice the widest answer this project has ever measured. At four
// attempts it never binds; it binds first at a response an order of magnitude
// wider than anything seen here.
//
// It is exported so a caller can say how many attempts a wave holds when that
// matters to what the caller reports - never so a caller can raise it.
const AtOnce = 8

// Over runs attempt for every index from 0 to count-1, at most AtOnce at a time,
// and returns when every one of them has finished.
//
// THE CALLER WRITES ITS RESULT AT ITS OWN INDEX, WHICH IS WHY NOTHING IS
// RETURNED. Handing results back through a channel would need a wider exemption
// from the concurrency guard AND would invite assembling them in the order
// attempts finish - so a report's row order would change between runs on one
// machine, and a reader comparing two reports would be comparing rows about
// different things. A slice that already has its full length, written at index i
// by the goroutine that owns index i, cannot be assembled in any other order.
//
// EVERY GOROUTINE IS WAITED FOR BEFORE THIS RETURNS, INCLUDING WHEN ATTEMPTS
// FAIL. There is no early return in here at all, which is deliberate rather than
// incidental: leaving on the first failure would walk away from sockets still
// being opened behind us.
//
// A PANIC INSIDE ONE OF THESE GOROUTINES IS CAUGHT HERE AND NOWHERE ELSE - R-1.
// The recover in the orchestrator runs on the goroutine that walks the layers
// and cannot see these, so before this existed a panic anywhere under attempt
// killed the process with no report at all and an exit code from outside the
// table - the same failure ADR18 refused to accept from a shared map. And
// attempt reaches code this program does not own: net.Dialer for L3, crypto/tls
// for L4. "attempt must not panic" was a rule with nothing enforcing it, about
// code we do not write.
//
// IT COMES BACK AS AN ERROR RATHER THAN AS A RESULT, and that is the line this
// package will not cross: it still knows nothing about findings, addresses or
// layers, so it cannot say what a fallen attempt MEANS. The caller decides that,
// with its own vocabulary.
//
// A count of zero or less runs nothing and returns, rather than being a caller's
// bug to discover at run time.
func Over(count int, attempt func(i int)) error {
	// ONE SLOT PER ATTEMPT, WRITTEN BY THE GOROUTINE THAT OWNS IT - the same
	// doctrine as the caller's results, and the reason there is no mutex here.
	// A lock would be a wider exemption from the concurrency guard for a fact
	// that needs none.
	fell := make([]any, max(count, 0))

	// WAVES ARE A LOOP AND NOT A SEMAPHORE, which is what keeps the guard's
	// exemption this narrow: a semaphore on a channel would need the very
	// primitive ADR43 refused. A caller re-reading its budget inside attempt can
	// therefore still find it spent between waves, which is an honest fact about
	// our own budget rather than about somebody's network.
	for start := 0; start < count; start += AtOnce {
		end := start + AtOnce
		if end > count {
			end = count
		}

		var wg sync.WaitGroup
		for i := start; i < end; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				defer func() {
					if cause := recover(); cause != nil {
						fell[i] = cause
					}
				}()
				attempt(i)
			}(i)
		}
		wg.Wait()
	}

	// THE FIRST ONE, IN INDEX ORDER RATHER THAN IN THE ORDER THEY HAPPENED. Two
	// attempts falling over in one run would otherwise name whichever goroutine
	// lost the race, and the same run would report a different address twice in
	// a row - the order problem this whole package exists to avoid, arriving
	// through the error instead of through the results.
	for i, cause := range fell {
		if cause != nil {
			return fmt.Errorf("attempt %d fell over inside this program: %v", i, cause)
		}
	}
	return nil
}
