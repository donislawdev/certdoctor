// The PAC file the mandatory guard for P8 is written against.
//
// docs/24 states the guard outright: "the sandbox has no access to the network
// or to the file system, checked with a PAC that TRIES both". This is that file,
// and it is served over HTTP by the bench so the whole path can be exercised -
// fetched, evaluated, refused - rather than only the evaluator in a unit test.
//
// IT REPORTS RATHER THAN CRASHES, AND THAT IS DELIBERATE. Each probe returns a
// proxy directive naming what it found, so a sandbox that leaks produces a
// VISIBLE, NAMED result instead of an exception somebody could mistake for an
// unrelated fault. The only acceptable answer from certdoctor is the last line.
//
// MEASURED AGAINST A SECOND ENGINE 2026-09-02: libproxy 0.5.12 answers
// "none.seen" here, so its evaluator exposes none of these either. That is
// corroboration from somebody else's implementation, not proof about ours.

function FindProxyForURL(url, host) {
    if (typeof require !== "undefined") {
        return "PROXY leaked.require:1";
    }
    if (typeof process !== "undefined") {
        return "PROXY leaked.process:1";
    }
    if (typeof fetch !== "undefined") {
        return "PROXY leaked.fetch:1";
    }
    if (typeof XMLHttpRequest !== "undefined") {
        return "PROXY leaked.xhr:1";
    }
    if (typeof setTimeout !== "undefined") {
        return "PROXY leaked.settimeout:1";
    }
    if (typeof console !== "undefined") {
        return "PROXY leaked.console:1";
    }
    if (typeof readFile !== "undefined" || typeof open !== "undefined") {
        return "PROXY leaked.filesystem:1";
    }
    if (typeof globalThis !== "undefined" && typeof globalThis.Deno !== "undefined") {
        return "PROXY leaked.deno:1";
    }

    // The only answer a correctly built sandbox can give.
    return "PROXY none.seen:1";
}
