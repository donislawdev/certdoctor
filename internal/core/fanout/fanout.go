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

import "sync"

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
// being opened behind us, and a panic inside a goroutine is not caught by the
// recover in the orchestrator - the process would die with no report and no exit
// code from the table, which is the argument ADR18 used to keep masking out of
// the layers. So attempt must not panic, and nothing here returns early.
//
// A count of zero or less runs nothing and returns, rather than being a caller's
// bug to discover at run time.
func Over(count int, attempt func(i int)) {
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
				attempt(i)
			}(i)
		}
		wg.Wait()
	}
}
