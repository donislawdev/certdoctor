package pac

import (
	"context"
	"runtime/metrics"
	"time"
)

// heapMetrics are the two figures the watchdog adds up: memory held by heap
// objects and by goroutine stacks.
//
// STACKS ARE COUNTED BECAUSE A NATIVE RECURSION GROWS ONE. Probe S33 measured a
// PAC file nesting arrays a million deep and asking for their text: the engine
// recursed in Go, the stopwatch could not interrupt it, and the process was
// still running after a second and a half with hundreds of megabytes, most of it
// stack.
var heapMetrics = []string{
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/stacks:bytes",
}

// heapInUse reads what this process holds, without stopping the world.
//
// WHY runtime/metrics AND NOT runtime.ReadMemStats, WHICH THE STOPWATCH USES.
// ReadMemStats stops the world, and a goroutine inside a long copy in native
// code does not stop for it, so the reader waits for exactly the work it is
// meant to catch. metrics.Read stops nothing. Probe S33, 2026-11-16: with it,
// "x".repeat(1e10) was seen 2.2 to 13 ms after the allocation, with the
// process's resident memory still near 20 MB, on Windows, Linux and macOS -
// and within 45 ms with GOMAXPROCS=1.
//
// A FIGURE OF ANOTHER KIND COUNTS AS NOTHING. Both names are documented by the
// runtime as uint64 figures and a test holds them to that; if a toolchain ever
// drops one, this reads less rather than reading garbage, and the parent's
// clock still ends the process.
func heapInUse() uint64 {
	samples := make([]metrics.Sample, len(heapMetrics))
	for i, name := range heapMetrics {
		samples[i].Name = name
	}
	metrics.Read(samples)
	var held uint64
	for _, s := range samples {
		if s.Value.Kind() == metrics.KindUint64 {
			held += s.Value.Uint64()
		}
	}
	return held
}

// watchdog ends the sandbox process when it holds more than limit or has run
// longer than deadline, by calling exit with the code that says which.
//
// THIS IS THE ONE GOROUTINE THE CHILD ADDS, and sandboxAllowlist counts it -
// ADR150. Like the stopwatch, it shares nothing: it reads the runtime's figures
// and the clock, and its answer is the process ending with a code its parent
// reads. os.Exit from here ends the process even while the goroutine running
// the file is deep in native code, which is the whole point.
//
// IT STOPS WITH ctx, which Serve cancels when the evaluation returns, so a
// result already written is not followed by a second ending.
func watchdog(ctx context.Context, inUse func() uint64, limit uint64, deadline time.Duration, exit func(int)) {
	start := time.Now()
	go func() {
		for ctx.Err() == nil {
			if inUse() > limit {
				exit(ExitMemory)
				return
			}
			if time.Since(start) > deadline {
				exit(ExitDeadline)
				return
			}
			time.Sleep(tick)
		}
	}()
}
