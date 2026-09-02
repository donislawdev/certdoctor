// A PAC file that never returns - the time half of sandbox condition 3.
//
// Measured by probe S12 on 2026-09-02: goja's Interrupt, called from a stopwatch
// goroutine, ends this after 51 ms against a 50 ms budget, and the Runtime still
// works afterwards once ClearInterrupt has been called. That measurement is what
// the condition now rests on.
//
// Expected answer from certdoctor: UNKNOWN with a reason naming the time limit.

function FindProxyForURL(url, host) {
    while (true) {
        // Nothing. That is the point.
    }
    return "DIRECT";
}
