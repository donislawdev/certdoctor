//go:build !windows

package main

import (
	"os/signal"
	"syscall"
)

// keepBrokenPipesFromKilling turns a write to a closed pipe into an ordinary
// error instead of a signal that ends the process - ADR84.
//
// WHY IT IS NEEDED AT ALL. Go does not translate SIGPIPE into EPIPE for file
// descriptors 1 and 2 - it lets the signal kill the process - UNLESS the program
// has said something about that signal. So `certdoctor --json | head` ends with
// a status of 141, which is not in this program's exit code table and arrives
// with no message at all. Every ending has to carry a code from the table and
// mean it, and 141 is neither.
//
// MEASURED 2026-09-03 in golang:1.27-alpine, one document written into a pipe
// whose reader had gone:
//
//	1 MiB, as it stood      -> killed, status 141, nothing said
//	1 MiB, with this line   -> 65536 bytes written, then
//	                           "write /dev/stdout: broken pipe", status 6
//	9 KiB, either way       -> written whole, status 0
//
// The 65536 in the middle row is the pipe buffer measured directly rather than
// looked up: a document smaller than that is handed over before the reader can
// be missed. THAT IS WHY THIS HAS NEVER BEEN SEEN. Measured the same day, a
// --json report is 35060 bytes on the owner's machine and 21773 in a container,
// so the margin is under twofold and shrinks as the trust matrix grows.
//
// Ignore RATHER THAN Notify, AND THAT IS NOT A DETAIL. The review proposes a
// channel with a goroutine draining it. Measured side by side on the same day,
// the two produce THE SAME RESULT - status 6 and the same error from Write - and
// Ignore needs neither a channel nor a goroutine, so this file stays off the
// concurrency guard's allowlists entirely. The signal's VALUE tells us nothing
// the failed write does not.
//
// WHAT HAPPENS INSTEAD: deliver already turns a failed write into 6 IO with a
// sentence, so a person piping into head learns they saw part of a diagnosis
// rather than all of it.
func keepBrokenPipesFromKilling() {
	signal.Ignore(syscall.SIGPIPE)
}
