// The PAC file that routes on an ADDRESS rather than on a spelling - the
// witness for P8-K3e, and the thing OBS134 says this bench was missing.
//
// EVERY OTHER PAC FILE HERE USES ONLY isPlainHostName, shExpMatch AND
// dnsDomainIs - three pure text functions with no ports behind them. That was
// measured before P8-K3b and it is why ADR91 could leave the resolver
// unwired: every oracle on this bench answered without one. The moment a
// resolver went in behind dnsResolve, isResolvable and isInNet - ADR93 - this
// bench stopped being able to see the difference between a run that has one and
// a run that does not. This file is the difference.
//
// 🔴 THE ANSWER IS CAUSED BY THE ADDRESS AND BY NOTHING ELSE, WHICH IS THE WHOLE
// EXPERIMENTAL DESIGN. Two names on this bench sit in the same zone, are spelled
// the same shape, and are served by the same DNS server - via.proxy.test and
// gw.proxy.test - and they differ in one thing only: 172.28.0.90 against
// 172.28.0.128. The mask below is /32, so the branch turns on that one
// difference. No text rule in this file could tell those two names apart, which
// is what makes a differing answer evidence about the resolver rather than about
// the string.
//
// WHY IT ASKS ABOUT A NAME IT WAS NOT GIVEN. isResolvable("gw.proxy.test") runs
// whatever host arrives, so the list this run reports in pac_script.asked is the
// FILE's choice rather than an echo of what the file was asked about. A report
// that only ever named the target could be produced without a resolver ever
// being called.
//
// WHY IT ASKS ABOUT THE SAME NAME TWICE. isInNet and dnsResolve both want the
// host's address. ADR93 part 3 puts a cache in front of the resolver and calls
// it part of the ceiling rather than an optimisation, so those two calls must
// leave this machine as ONE question - and the asked list is where that shows.

function FindProxyForURL(url, host) {
    // Asked about regardless of the host. This name is not the target in one of
    // the two scenarios and is the target in the other, which is how the same
    // file produces two different asked lists from one rule.
    if (!isResolvable("gw.proxy.test")) {
        return "DIRECT";
    }

    // The branch that turns on the address. A /32 mask, so gw.proxy.test - same
    // zone, same shape, one address along - takes the other way out.
    if (!isInNet(host, "172.28.0.90", "255.255.255.255")) {
        return "DIRECT";
    }

    // The second helper asking about a name already asked about. It must not
    // produce a second question, and its answer must be the dotted string the
    // Mozilla documentation describes rather than a boolean or an object.
    if (dnsResolve(host) != "172.28.0.90") {
        return "DIRECT";
    }

    return "PROXY 172.28.0.128:3128";
}
