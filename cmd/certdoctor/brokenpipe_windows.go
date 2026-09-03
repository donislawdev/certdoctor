//go:build windows

package main

// keepBrokenPipesFromKilling does nothing here, and the nothing is the answer
// rather than a gap.
//
// WINDOWS HAS NO SIGPIPE. A write to a pipe whose reader has gone comes back as
// an ordinary error, which deliver already turns into 6 IO with a sentence -
// measured 2026-09-03 on this machine, where the same pipeline that kills a
// process on Linux simply finishes. There is no signal to receive and nothing to
// register, so the function exists only to keep the caller free of a build tag.
func keepBrokenPipesFromKilling() {}
