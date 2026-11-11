// Package planted is a fixture, never compiled and never part of the build. It
// reads the real clock under its own name and under one of its own, for the
// guard that says the core and the orchestrator take the clock as a port.
package planted

import (
	"time"
	clock "time"
)

var started = clock.Now()

func wait() time.Duration {
	clock.Sleep(time.Second)
	return time.Since(started)
}
