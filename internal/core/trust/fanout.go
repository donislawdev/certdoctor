package trust

import (
	"context"

	"github.com/donislawdev/certdoctor/internal/core/fanout"
)

// family is one runtime family this machine has a probe for, in the order the
// descriptors declare it.
type family struct {
	descriptor Descriptor
	probe      Probe
}

// fanOut asks every family side by side and returns one answer per family, at
// that family's own position - ADR118.
//
// THE GOROUTINE LIVES IN internal/core/fanout AND NOT HERE - ADR45, the same
// reason L3 and L4 give. This file says what to do per family, and the shared
// package says how many at a time and in what order, so the rule "results are
// placed by position and every goroutine is waited for" stays in one place.
//
// A FAMILY'S ROWS DO NOT DEPEND ON WHICH FAMILY ANSWERED FIRST. Each answer is
// written at its family's index, so the matrix comes out in descriptor order on
// every run, however long each runtime took to start.
func (in Input) fanOut(ctx context.Context, chain [][]byte, families []family) ([]answer, error) {
	out := make([]answer, len(families))
	// A FAMILY THAT FELL OVER INSIDE ITS PROBE IS NOT WHAT COMES BACK AS AN
	// ERROR - askProbe turns that into the family's own row before it gets here.
	// What does come back is our own code falling over around it, and the slot
	// of that goroutine holds an answer with no descriptor at all.
	return out, fanout.Over(len(families), func(i int) {
		out[i] = in.askFamily(ctx, families[i], chain)
	})
}
