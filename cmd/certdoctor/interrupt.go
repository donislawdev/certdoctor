package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
)

// THIS FILE IS ON THE CONCURRENCY GUARD'S FIFTH LIST AND IT IS A FILE OF ITS OWN
// FOR THAT REASON - ADR84, signalAllowlist in internal/guard/concurrency_test.go.
// An allowlist entry takes the guard off a file permanently, so the file it
// names has one job and stays short. Putting this in main.go would have exempted
// the wiring file, where every future goroutine would then pass unquestioned.
//
// What the entry excuses: a go statement, a channel type, a channel receive.
// What it does not: sync, sync/atomic, a channel send, a select.

// armSignalDefences puts both signal defences in place and hands back the way to
// take the second one off again.
//
// THE TWO ARE ARMED TOGETHER BECAUSE THEY ARE ONE DECISION: what this program
// does when the outside world tries to stop it. They are also armed HERE rather
// than in mainCode, and that is about being testable at all - mainCode runs the
// real program, so a line living there is a line no test can execute, and the
// coverage gate is the one guard that asks whether a branch ever ran.
func armSignalDefences(stderr io.Writer) (disarm func()) {
	keepBrokenPipesFromKilling()
	return leaveOnASecondInterrupt(stderr)
}

// leaveOnASecondInterrupt ends the process when a person interrupts twice.
//
// WHY THE FIRST ONE IS NOT ENOUGH. signal.NotifyContext keeps its registration
// until stop(), so once the context is cancelled every further interrupt is
// delivered to a channel nobody is reading and is dropped. A person who presses
// Ctrl-C again - because something is not finishing - gets nothing, and kill is
// the only way out. MEASURED 2026-09-03 in golang:1.27-alpine, with the exit
// status as the discriminator: three interrupts, process still running.
//
// AND THIS IS NOT WHAT THE REVIEW ASKED FOR, because what it asked for does not
// work. It proposed calling stop() once the context is cancelled, so the default
// handling would come back. Measured the same day: that leaves the process
// running through three interrupts, and so does signal.Reset(os.Interrupt).
// Watching for the signal ourselves does work - and it ends with 130
// INTERRUPTED, a code from the frozen table, where the review's version accepted
// a status outside it.
//
// TWO ARRIVALS ARE COUNTED ON A CHANNEL REGISTERED UP FRONT, rather than waiting
// on the context first. signal.Notify delivers to every registered channel, so
// this one sees the same interrupts NotifyContext does. Waiting on the context
// would arm this at the end of an ORDINARY run too - stop() cancels that same
// context - and a Ctrl-C in that window would replace a real exit code with this
// one.
// THE REGISTRATION IS SYNCHRONOUS AND ONLY THE WAITING IS NOT, which is both
// safer and the reason every construct the fifth list excuses lives in THIS
// file. Registering inside the goroutine would leave a window at the start of a
// run where an interrupt is not yet counted; starting the goroutine from main.go
// would have put the go statement in the wiring file and exempted that instead.
//
// IT RETURNS A WAY TO UNDO ITSELF, and that is for a test rather than for the
// program: mainCode arms this for the life of the process and has nothing to
// undo. A test that armed it and could not disarm it would leave the test binary
// unable to die from Ctrl-C, which is a change to somebody's tooling made by a
// test - the shape docs 05 calls a test with a side effect on its neighbours.
func leaveOnASecondInterrupt(stderr io.Writer) (disarm func()) {
	again := make(chan os.Signal, 2)
	signal.Notify(again, os.Interrupt)
	go onTheSecond(again, stderr, os.Exit)
	return func() { signal.Stop(again) }
}

// onTheSecond is the half of leaveOnASecondInterrupt that can be tested.
//
// THE EXIT IS A PARAMETER FOR THE ONLY REASON THAT EVER JUSTIFIES ONE: there is
// no other way. os.Exit ends the process, so a test of this rule would end the
// test binary - and the rule worth guarding is COUNTING TO TWO, because one
// interrupt must go to the ordinary path and leave this alone.
//
// IT IS AN EMERGENCY EXIT AND SAYS SO. os.Exit runs no deferred work: a report
// half written to standard output stays half written. That is the cost any
// signal-ended run pays, and the alternative it replaces is a run that cannot be
// stopped at all.
func onTheSecond(again <-chan os.Signal, stderr io.Writer, exit func(int)) {
	<-again
	<-again
	// INVIOLABLE RULE 1 APPLIES TO THIS ENDING TOO. A run that stops here did
	// less than it promised and has to say so, even though what it produced is
	// nothing.
	fmt.Fprintf(stderr, "%s: interrupted again, leaving at once - no report was produced\n", toolName)
	exit(exitcode.Interrupted.Int())
}
