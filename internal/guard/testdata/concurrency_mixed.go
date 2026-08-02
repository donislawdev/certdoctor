// This file is a fixture, never compiled and never part of the build. It holds
// exactly one shape and nothing else: a select that waits for cancellation AND
// for a real channel.
//
// It is its own file on purpose. Put next to other selects, a test asserting
// "the select was reported" would pass on the wrong one, and a guard proved by
// the wrong evidence is not proved at all.
package probe

import "context"

type results chan string

func waitForEitherCancellationOrWork(ctx context.Context, out results) {
	select {
	case <-ctx.Done():
	case value := <-out:
		_ = value
	}
}
