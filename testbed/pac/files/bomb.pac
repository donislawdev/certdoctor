// A PAC file that allocates rather than loops - the memory half of sandbox
// condition 3, which is the half that had to be REWRITTEN because the original
// wording was impossible.
//
// ADR75, from probe S12 on 2026-09-02: goja exposes NO API for a memory limit.
// A stopwatch reading HeapAlloc every millisecond stops this after 19 ms, but
// the heap peaks at 112 MiB against a 64 MiB ceiling - and 120 MiB on a second
// run, so the overshoot is a RANGE of 1.75-1.88x and not a constant. Between two
// reads somebody else's step doubles once more, so where the stopwatch lands
// decides the number.
//
// Expected answer from certdoctor: UNKNOWN with a reason. The ceiling is a
// ceiling on what gets noticed, not a guarantee about what gets allocated, and
// the report must not imply otherwise.

function FindProxyForURL(url, host) {
    var s = "x";
    while (true) {
        s = s + s;
    }
    return "DIRECT";
}
