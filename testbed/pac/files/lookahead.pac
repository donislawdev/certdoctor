// The file that gives the engine choice a witness on the bench rather than only
// in a probe log.
//
// ADR75 rejected otto by MEASUREMENT, not by taste: otto stands on re2, an
// engine without backtracking, and "a".match(/(?=x)/) there ends with
// "re2: Invalid (?=) <lookahead>". A browser runs a PAC like this one without
// blinking, so an engine that cannot would make certdoctor say "your PAC is
// broken" about a working machine - untruth about somebody else's computer,
// which inviolable rule 18 exists to prevent. goja carries dlclark/regexp2 for
// exactly this.
//
// A REAL PAC FILE LOOKS LIKE THIS. Lookahead in a proxy rule is not a curiosity
// invented to fail an engine - it is how somebody writes "internal, but not the
// build servers" in one expression.
//
// Expected answer: DIRECT for a host containing .internal. and PROXY for the
// rest. An engine that cannot compile the expression produces neither.

function FindProxyForURL(url, host) {
    var internalButNotBuild = /^(?=.*\.internal\.)(?!build\.).*$/;
    if (internalButNotBuild.test(host)) {
        return "DIRECT";
    }
    return "PROXY 172.28.0.128:3128";
}
