// Package pac evaluates a proxy auto-configuration file inside a sandbox.
//
// THIS IS THE ONE PLACE IN THIS PROGRAM THAT EXECUTES SOMEBODY ELSE'S CODE.
// ADR8 permits it as a deliberate, named exception to docs/14 section 2.1, under
// five conditions that must all hold at once and none of which is negotiable.
// Relaxing that list is a load-bearing change - the record exists so that the
// next session does not add "a small convenience" to the sandbox.
//
// The conditions and where each is enforced:
//
//  1. No network beyond our own dnsResolve - the helpers come from
//     internal/core/pac, which cannot import net, and their ports are supplied
//     by the caller. Nothing here dials.
//  2. No file system and no host objects - measured by probe S12 on 2026-09-02:
//     a fresh goja Runtime has no require, process, fetch, XMLHttpRequest,
//     setTimeout or console. We add nothing but the twelve helpers.
//  3. A hard time limit, a memory ceiling enforced by stopwatch, and a
//     mandatory call stack limit - this file and the size check in sandbox.go.
//  4. Only the helper functions from the PAC specification - sandbox.go injects
//     twelve names and no others.
//  5. A limit or an error is an outcome with a reason, never an exception and
//     never a pass - every path here returns a pac.Result.
package pac

import (
	"context"
	"runtime"
	"time"

	"github.com/dop251/goja"
)

// Limit names the ceiling a stopwatch enforced. It travels back to the
// evaluating goroutine inside goja's own InterruptedError.
type Limit string

const (
	// LimitTime - the evaluation ran past its budget.
	LimitTime Limit = "time"
	// LimitMemory - the evaluation allocated past the ceiling.
	LimitMemory Limit = "memory"
)

// tick is how often the stopwatch looks at the clock and the heap.
//
// ONE MILLISECOND IS THE VALUE PROBE S12 MEASURED WITH, and the overshoot range
// ADR75 records - 1.75x to 1.88x over the ceiling - belongs to this interval. A
// longer tick makes the overshoot larger, because between two reads somebody
// else's doubling step runs again. A shorter one buys little: each read calls
// runtime.ReadMemStats, which stops the world briefly, so the instrument starts
// costing the thing it measures.
const tick = time.Millisecond

// watch starts the stopwatch that enforces condition 3 for one evaluation.
//
// THIS IS THE ONLY GOROUTINE IN THIS PACKAGE AND THE REASON THIS FILE SITS ON
// sandboxAllowlist - ADR77. That list excuses the go statement below and nothing
// else: no sync, no sync/atomic, no channel. It is narrower than the fan-out
// list, which needs a WaitGroup, and the difference was measured rather than
// copied from it.
//
// WHY NO SHARED STATE IS NEEDED, WHICH IS WHAT MAKES THE LIST THAT NARROW. The
// only thing this goroutine has to report is WHICH limit it hit, and
// Runtime.Interrupt carries a value that comes back to the evaluating goroutine
// inside *goja.InterruptedError. So the answer travels through the engine. There
// is no counter, no flag and no result slot for two goroutines to touch.
//
// IT STOPS BY POLLING ctx.Err(), WHICH IS A METHOD CALL AND NOT A RECEIVE, so
// even the cancellation exemption in the concurrency guard is not needed here.
//
// IT IS NOT WAITED FOR, AND THAT IS SAFE ONLY BECAUSE A RUNTIME IS NEVER
// REUSED. This goroutine can outlive the evaluation by up to one tick. If the
// same Runtime were handed a second PAC file, a late Interrupt would land on
// THAT evaluation and blame the wrong file. sandbox.go builds a fresh Runtime
// every time for exactly this reason, and that is the whole argument for
// leaving the WaitGroup out.
//
// IT CANNOT STOP NATIVE CODE, AND THE LIMIT IS THE ENGINE'S RATHER THAN OURS.
// Measured 2026-09-02: a Go function called from JavaScript that loops for three
// seconds runs to completion against a 50 millisecond budget, and the interrupt
// is only delivered once it returns. goja checks for an interrupt between
// bytecode instructions, so what this protects is the PAC file's own loops. What
// protects the rest is that internal/core/pac contains nothing that can block or
// loop without a bound, which is a rule stated in that package.
func watch(ctx context.Context, vm *goja.Runtime, budget time.Duration, ceiling uint64) {
	deadline := time.Now().Add(budget)

	// The baseline is taken HERE rather than inside the goroutine, so that the
	// ceiling measures what this evaluation added rather than what the rest of
	// the run was already holding.
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	go func() {
		for ctx.Err() == nil {
			if time.Now().After(deadline) {
				vm.Interrupt(LimitTime)
				return
			}
			var current runtime.MemStats
			runtime.ReadMemStats(&current)
			if current.HeapAlloc > base.HeapAlloc+ceiling {
				vm.Interrupt(LimitMemory)
				return
			}
			time.Sleep(tick)
		}
	}()
}
