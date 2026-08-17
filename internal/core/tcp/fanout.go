package tcp

import (
	"context"
	"sync"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// This is the only file in this program that starts a goroutine, and it is one
// function long on purpose - ADR43. The layer's decisions all live next door in
// layer.go, which stays under the concurrency guard in full. What is exempted
// here is a WaitGroup and a go statement; a channel, a select, a send, a receive
// and sync/atomic are still reported in this file exactly as they are everywhere
// else, and a canary in internal/guard proves that narrow exemption is narrow.

// atOnce caps how many attempts are in flight at the same time.
//
// IT IS A CEILING RATHER THAN TUNING, AND BOTH NUMBERS BEHIND IT WERE MEASURED.
// The count of addresses comes from somebody else's resolver, so without a cap
// THEY decide how many sockets this machine opens at once. The widest real
// answer measured in this project is four addresses (example.com, P5a), while
// the protocol's ceiling without EDNS0 is a 512 byte response - roughly thirty A
// records - and L3 is handed the union of both DNS views with duplicates left in
// (internal/app/run/wire.go). Fifty simultaneous SYNs at one host is the shape of
// a scanner, and how an EDR reacts to this tool is still an open question (O6),
// in exactly the environments it is meant to be run in.
//
// Eight is twice the widest answer this project has ever measured. At four
// addresses it never binds; it binds first at a response an order of magnitude
// wider than anything seen here.
const atOnce = 8

// fanOut makes one attempt per address and returns one finding per address.
//
// RESULTS ARE PLACED BY POSITION IN A SLICE THAT ALREADY HAS ITS FULL LENGTH,
// NEVER APPENDED IN THE ORDER ATTEMPTS FINISH. That is rule 2 of docs 22 section
// 2 and it is the reason this file needs no channel at all: row order stays the
// order the addresses arrived in, so two runs of the same machine produce the
// same report and a reader comparing two reports is comparing rows about the same
// address. Collecting through a channel would need a wider exemption AND invite
// the opposite.
//
// EVERY GOROUTINE IS WAITED FOR BEFORE THIS RETURNS, INCLUDING WHEN ATTEMPTS
// FAIL. There is no early return in here at all, which is deliberate rather than
// incidental: leaving on the first failure would walk away from sockets that are
// still being opened behind us, and a panic inside a goroutine is not caught by
// the recover in the orchestrator - the process would die with no report and no
// exit code from the table (the argument ADR18 used to keep masking out of the
// layers). So tryOne gains no new way to panic, and nothing here returns early.
func (in Input) fanOut(ctx context.Context, addresses []string) []report.Finding {
	findings := make([]report.Finding, len(addresses))

	// WAVES ARE A LOOP AND NOT A SEMAPHORE, which is what keeps the exemption
	// this narrow: a semaphore on a channel would need the very primitive ADR43
	// just refused. The budget is re-read inside each attempt, so an address in a
	// later wave can still come back not_attempted - an honest row about our own
	// budget, and one that cannot occur at all for an answer narrower than atOnce.
	for start := 0; start < len(addresses); start += atOnce {
		end := start + atOnce
		if end > len(addresses) {
			end = len(addresses)
		}

		var wg sync.WaitGroup
		for i := start; i < end; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				findings[i] = in.tryOne(ctx, addresses[i])
			}(i)
		}
		wg.Wait()
	}
	return findings
}
