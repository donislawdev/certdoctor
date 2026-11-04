//go:build !windows

package main

import "runtime"

// loadRendererBeside answers that no renderer ships for this system.
//
// Nothing is shipped beside the window on Linux or macOS (ADR125 point 2), so
// --software-gl says so there rather than doing nothing in silence - a flag
// that does nothing without a word is a flag somebody waits on.
func loadRendererBeside() error {
	return notShipped{runtime.GOOS}
}
