// A PAC file that recurses without a floor - the third member of sandbox
// condition 3, and the one nobody ordered.
//
// 🔴 THIS FILE IS WHY SetMaxCallStackSize STOPPED BEING TUNING AND BECAME A
// CONDITION. Measured by probe S12 on 2026-09-02: at goja's default settings
// this was STILL RUNNING after ten seconds with a 213 MiB heap, and only the
// stopwatch ended it. With SetMaxCallStackSize(2000) the same file finishes in
// 1 ms with a clean StackOverflowError.
//
// Ten seconds is longer than the whole budget certdoctor gives a run, so without
// the stack limit this one file would spend a user's entire diagnosis.

function FindProxyForURL(url, host) {
    function down(n) {
        return down(n + 1);
    }
    return down(0);
}
