// This file is a fixture, never compiled and never part of the build. It holds
// the shapes the concurrency guard must NOT report: waiting for a context to be
// cancelled, which every probe with a deadline will contain.
package probe

import "context"

func waitForCancellation(ctx context.Context) {
	<-ctx.Done()
}

func waitOrGiveUpImmediately(ctx context.Context) {
	select {
	case <-ctx.Done():
	default:
	}
}

func waitForEitherContext(run, probe context.Context) {
	select {
	case <-run.Done():
	case <-probe.Done():
	}
}

func waitAndKeepTheValue(ctx context.Context) {
	select {
	case done := <-ctx.Done():
		_ = done
	}
}
