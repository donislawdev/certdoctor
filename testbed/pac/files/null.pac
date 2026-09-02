// A PAC file that answers with null - legal JavaScript, no answer at all.
//
// 🔴 THIS IS THE TRAP PROBE S12 FOUND WITHOUT BEING ASKED, AND IT WOULD HAVE
// SHIPPED. Measured 2026-09-02: goja exports null as the STRING "null" while
// goja.IsNull reports true. Reading the result with String() alone therefore
// turns "the PAC gave no answer" into "use a proxy whose host is called null" -
// a directive certdoctor would then print, and somebody would then go looking
// for a machine by that name.
//
// So the result is read through IsNull and IsUndefined, and this file is the
// bench that says so out loud.
//
// Expected answer from certdoctor: UNKNOWN with a reason. Never a proxy, and
// never the word null appearing as a host anywhere in the report.

function FindProxyForURL(url, host) {
    return null;
}
