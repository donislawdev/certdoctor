// The bench's main proxy auto-configuration file - slice P4c, feeding P8.
//
// THIS FILE IS THE ORACLE'S SUBJECT, NOT ITS OUTPUT. The expectation files in
// expected/ were written by reading THIS file and working out what it must
// return, before certdoctor or any other evaluator was pointed at it. libproxy
// is then asked the same question independently. If libproxy and the expectation
// disagree, the suspect is this file or the reading of it - not the product.
//
// IT USES THE HELPER FUNCTIONS ON PURPOSE rather than comparing strings. ADR10
// says certdoctor implements the twelve PAC helpers itself, so the bench has to
// exercise them: isPlainHostName, shExpMatch and dnsDomainIs each decide one
// branch below. A PAC file made of == comparisons would prove nothing about the
// twelve functions that are the actual work of P8-K1.
//
// EVERY BRANCH IS REACHABLE FROM THIS BENCH. A rule no name can reach is a rule
// nobody checks, and an unchecked rule in a file this small would be a place for
// a mistake to sit.

function FindProxyForURL(url, host) {
    // A bare name has no domain to route on, so it never leaves this network.
    // Measured branch: any single-label host.
    if (isPlainHostName(host)) {
        return "DIRECT";
    }

    // THE EXCEPTION RULE, AND THE REASON THIS PRODUCT EXISTS. A proxy is
    // configured on the machine and this one name is sent past it anyway. Anyone
    // reading only the environment variables would say the request goes through
    // the proxy, and they would be wrong.
    if (shExpMatch(host, "direct.*")) {
        return "DIRECT";
    }

    // The name that must meet a proxy demanding credentials. Reaching it with
    // none produces 407.
    if (shExpMatch(host, "auth.*")) {
        return "PROXY 172.28.0.128:3129";
    }

    // Everything else this bench knows about goes through the open proxy.
    // dnsDomainIs matches a suffix, so the bare zone apex needs saying too.
    if (dnsDomainIs(host, ".proxy.test") || host == "proxy.test") {
        return "PROXY 172.28.0.128:3128";
    }
    if (dnsDomainIs(host, ".partner.test") || host == "partner.test") {
        return "PROXY 172.28.0.128:3128";
    }

    // Anything this bench does not know about. A PAC file ending in DIRECT
    // rather than in a proxy is the common shape, and it means a name absent
    // from every rule above quietly bypasses the proxy.
    return "DIRECT";
}
