// The PAC file that asks about more distinct names than one evaluation may
// resolve - the second half of the P8-K3e witness, OBS134.
//
// SIX NAMES, ALL OF WHICH THIS BENCH RESOLVES. Every one is in
// dns/proxy.test.zone, so nothing here fails for being unknown: a run that stops
// short stopped because of a ceiling of ours and for no other reason. That is
// the fact this file exists to expose, and it cannot be exposed by a file whose
// names do not resolve.
//
// 🔴 libproxy IS NOT THE ORACLE FOR THIS ONE, AND THE REASON IS NOT THAT IT IS
// WRONG. Measured 2026-09-07: it has no such ceiling and answers about all six,
// so it returns the proxy - which is what a browser would do and is the true
// reading of this file. certdoctor deliberately refuses to rest a verdict on a
// view it knows is truncated: from the file's point of view the names past the
// allowance simply did not resolve, which is the same known untruth a run with
// no resolver at all produces, and ADR93 part 5 gives it the same refusal under
// a different name. Two different answers, both correct, one of them ours on
// purpose - so this file records libproxy's rather than comparing against it.
//
// IT COUNTS RATHER THAN BRANCHING, so the answer says how far it got. A file
// that took a branch would hide the arithmetic in a return.
//
// THE NUMBER OF NAMES IS THIS FILE'S PROPERTY, NOT OURS. The expectation asks
// whether fewer names left this machine than the file asked about, which stays a
// true statement of the rule whatever the allowance is set to - the caveat
// certdoctor prints deliberately does not quote the limit either, for the same
// reason: it is a property of how the binary was wired rather than of anybody's
// machine or of their file.

function FindProxyForURL(url, host) {
    var names = [
        "ns.proxy.test",
        "pac.proxy.test",
        "gw.proxy.test",
        "via.proxy.test",
        "direct.proxy.test",
        "auth.proxy.test"
    ];

    var found = 0;
    for (var i = 0; i < names.length; i++) {
        if (isResolvable(names[i])) {
            found = found + 1;
        }
    }

    if (found < names.length) {
        return "DIRECT";
    }
    return "PROXY 172.28.0.128:3128";
}
