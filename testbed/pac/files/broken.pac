// A PAC file that is not valid JavaScript - the ordinary fault, not an attack.
//
// WHAT certdoctor MUST DO WITH IT: UNKNOWN with a reason, never an exception and
// never PASS. That is condition 5 of the sandbox in docs/14 section 2.1 and it
// is inviolable rule 15 applied to somebody else's file.
//
// 🔴 libproxy IS NOT AN ORACLE FOR THIS FILE, AND THE MEASUREMENT SAYS SO.
// Measured 2026-09-02: libproxy 0.5.12 prints a warning and then answers
// direct://, which is a SILENT FALLBACK. Our contract forbids exactly that - a
// machine whose PAC is broken must be told, not quietly routed. So the two tools
// answer different questions here and the difference must never be read as
// certdoctor being wrong. docs/21 section 2a is about precisely this.

function FindProxyForURL(url, host) {
    return "PROXY 172.28.0.128:3128"
    this line is not JavaScript at all (((
