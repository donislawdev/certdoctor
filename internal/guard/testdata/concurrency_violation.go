// This file is a fixture, never compiled and never part of the build. It exists
// so the concurrency guard can be proved to fail on every primitive it claims to
// see.
package probe

import (
	"sync"
	"sync/atomic"
)

type worker struct {
	mu      sync.Mutex
	counter atomic.Int64
	results chan string
}

func (w *worker) run(done chan struct{}) {
	go func() {
		w.results <- "finished"
	}()

	select {
	case value := <-w.results:
		_ = value
	case <-done:
	}
}
