package tcp

import (
	"context"

	"github.com/donislawdev/certdoctor/internal/core/fanout"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// atOnce is how many attempts this layer has in flight at once. It is the shared
// ceiling rather than a number of this layer's own, because L4 makes exactly the
// same promise about exactly the same addresses - ADR45.
const atOnce = fanout.AtOnce

// fanOut makes one attempt per address and returns one finding per address, at
// that address's own position.
//
// THE GOROUTINE ITSELF LIVES IN internal/core/fanout, NOT HERE, and that is the
// whole point of this file being three lines long. The rule "results are placed
// by position, at most AtOnce at a time, and every goroutine is waited for" is
// one rule; written once for L3 and again for L4 it would be one rule in two
// places, which is what OBS50 measured the cost of. So this file says what to do
// per address and the shared package says how many at a time.
func (in Input) fanOut(ctx context.Context, addresses []string) ([]report.Finding, error) {
	findings := make([]report.Finding, len(addresses))
	// AN ATTEMPT THAT FELL OVER COMES BACK AS AN ERROR AND NOT AS A ROW - R-1.
	// The slot of a goroutine that panicked holds a zero-valued finding, which
	// the report contract refuses, so a row would be this layer reporting its own
	// defect as a fact about one address. The caller says what it means instead.
	return findings, fanout.Over(len(addresses), func(i int) {
		findings[i] = in.tryOne(ctx, addresses[i])
	})
}
