// The PAC file that asks what day and what time it is - slice P8-K3f.
//
// 🔴 UNTIL 2026-09-08 THIS FILE WOULD HAVE BEEN CALLED BROKEN. Ports.Now was
// never wired in production, so weekdayRange, dateRange and timeRange came back
// "not understood", the sandbox threw, and the layer graded the whole evaluation
// malformed with the reason it keeps for a file that will not parse. Measured
// against the binary: L2 UNKNOWN unrecognized_output for a file whose only sin
// was weekdayRange("MON","FRI"). Nothing on this bench could see that, because
// no PAC file here asked the clock - the same gap OBS134 named for the resolver,
// one helper family along.
//
// BOTH RANGES ARE TRUE ON EVERY DAY AND AT EVERY HOUR, AND THAT IS THE WHOLE
// TRICK. weekdayRange("SUN","SAT") spans the week and timeRange(0,24) spans the
// day, so the expectation beside this file is a constant rather than something
// that would have to be recomputed - and a bench scenario that failed one day a
// week would be worse than no scenario at all. What is being checked is that the
// helpers ANSWERED, not what they answered.
//
// THE ANSWER STILL CARRIES A DATE AND THE REPORT HAS TO SAY SO. That is the
// second half of this scenario: a file deciding by the clock gives ONE of the
// answers this machine would give, not THE answer, so the row carries a caveat
// saying which moment it took. Somebody reading a Saturday run on Monday is
// reading about a route that may not be theirs today.

function FindProxyForURL(url, host) {
    // Every day of the week. A build with no clock behind this helper does not
    // answer false here - it throws, and the file is reported as unreadable.
    if (!weekdayRange("SUN", "SAT")) {
        return "DIRECT";
    }

    // Every hour of the day. A second helper on purpose: the instant is pinned
    // once per evaluation, so these two must agree even when a boundary falls
    // between them.
    if (!timeRange(0, 24)) {
        return "DIRECT";
    }

    return "PROXY 172.28.0.128:3128";
}
