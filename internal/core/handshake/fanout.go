package handshake

import (
	"context"

	"github.com/donislawdev/certdoctor/internal/core/fanout"
)

// outcome is one address's answer, before it becomes a row.
type outcome struct {
	address string
	shown   Presented
	err     error
}

// fanOut completes one handshake per address, side by side.
//
// THE GOROUTINE LIVES IN internal/core/fanout AND NOT HERE - ADR45. L3 makes the
// same promise about the same addresses, and a second copy of it would be one
// rule in two places: the mutation entries aimed at it would report SKIP rather
// than prove anything, which is what OBS50 measured. So this file says what to
// do per address, and the shared package says how many at a time and in what
// order.
func (in Input) fanOut(ctx context.Context, addresses []string) []outcome {
	out := make([]outcome, len(addresses))
	fanout.Over(len(addresses), func(i int) {
		shown, err := in.attempt(ctx, addresses[i])
		out[i] = outcome{address: addresses[i], shown: shown, err: err}
	})
	return out
}
