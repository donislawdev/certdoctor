// Package proxy turns this machine's proxy configuration into what it MEANS -
// and it means different things to different programs on the same machine.
//
// THAT DIFFERENCE IS THE PRODUCT AND NOT A DETAIL. A helpdesk is told "the
// proxy is configured", and one program obeys it while the one next to it goes
// direct. The reason is rarely a broken machine: the exception lists have
// different SYNTAXES and different MATCHING RULES per runtime family, so one
// configuration honestly means two things at once. This package is where those
// rules live, one function each, so that the report can say which runtime is
// excused and which is not instead of averaging them into a sentence that is
// true for nobody.
//
// IT HAS NO BUILD TAG AND IT IS NOT ALLOWED TO GROW ONE. Everything here is
// pure text and address arithmetic, so it compiles and is tested on every
// platform. The reason is measured rather than tidy: internal/adapter/dns holds
// one rule in two build-tagged halves, and for a month the posix half had no
// test at all while the gate stayed green - 75,8% in a container against 91,4%
// on Windows at a floor of 90 (OBS100). On top of that the mutation register
// runs on Windows, so a rule living behind //go:build !windows cannot have an
// entry at all (OBS102). Rules belong here; only the transport that reads them
// off a platform belongs in internal/adapter/proxyconf.
//
// WHAT IS DELIBERATELY NOT HERE, AND THIS LIST HAS SHRUNK TWICE. The layer that
// reports all of it lives here now, and so does the reading of what an automatic
// configuration script answered - but the FETCHING and the ENGINE do not: they
// arrive through a port, so this package still reaches no network and still runs
// nobody else's code. WPAD discovery and asking a proxy for credentials are not
// here either, and those are the two that remain.
package proxy

import "fmt"

// Rule names one runtime family's way of reading a proxy exception list.
//
// THE LIST IS CLOSED, for the same reason the status vocabulary is: an open one
// means the next person adds a reading and the report starts claiming things
// about a runtime nobody checked. AN ENTRY NEEDS TWO THINGS AND NOT ONE: a
// source, read at the vendor or measured here, AND a consumer among the thirteen
// probes. Go has the first and not the second, so it is quoted at
// RuleNoProxyCurl and is not a rule.
//
// THERE ARE SIX, THE CARVING SAID THREE, AND EACH EXTRA ONE ARRIVED FROM A
// SOURCE RATHER THAN FROM A HUNCH. The fourth: the two Windows stacks were
// expected to share a rule and do not. Measured against the vendor's own pages
// on 2026-09-05, WinHTTP says a wildcard "must be the left-most character" and
// gives "aaa.*" as an example of what it does not support, while the Internet
// Explorer settings that WinINET reads document "www.microsoft.*" and even
// "123.1*.66.*" as working patterns. So the same string in ProxyOverride excuses
// a host from the proxy in Edge and does not excuse it in a service running on
// WinHTTP - one machine, two answers, no misconfiguration anywhere.
//
// The fifth came from running scutil on a Mac the same day, and it is the only
// one this project has that rests on its OWN measurement rather than on a
// vendor's page - see bypassExceptionsList for what that buys and what it costs.
//
// The sixth is the same NO_PROXY variable the first one reads, read the way .NET
// reads it. Two rules over one variable looks like a mistake until the vendor
// pages are put side by side: NO_PROXY=* turns proxying off in curl and is a
// host name nobody has in .NET.
type Rule string

const (
	// RuleNoProxyCurl is the NO_PROXY and no_proxy environment variable, as CURL
	// reads it - and only curl.
	//
	// THE NARROWING IS DELIBERATE AND IT COST ONE WORD IN THIS FILE. This
	// constant said "curl, Go, Python and most command line tooling" until
	// 2026-09-05, when the vendors were read side by side and two of them turned
	// out to disagree with curl on the same list:
	//
	// Go, golang.org/x/net/http/httpproxy, read 2026-09-05 - "A domain name
	// matches that name and all subdomains. A domain name with a leading "."
	// matches subdomains only. For example "foo.com" matches "foo.com" and
	// "bar.foo.com"; ".y.com" matches "x.y.com" but not "y.com"." curl strips
	// the leading dot instead, so ".y.com" excuses "y.com" there and not here.
	//
	// SO ONE NO_PROXY=example.com MEANS THREE DIFFERENT THINGS on one machine.
	// .NET's reading is RuleNoProxyDotNet below. Go's is NOT implemented, and
	// the reason is a rule of this project rather than an oversight: Go is not
	// one of the thirteen probes, so a rule for it would be code nothing in this
	// program could ever execute - the shape OBS98 names and the coverage gate
	// exists to find. The quotation stays here so that the day a Go runtime
	// becomes a probe, the source is already read.
	//
	// This constant therefore promises curl and nothing wider, because a rule
	// claiming to speak for runtimes it was never checked against is exactly what
	// inviolable rule 18 exists to stop.
	RuleNoProxyCurl Rule = "no_proxy_curl"
	// RuleNoProxyDotNet is the same variable read the way .NET reads it, which
	// is the strictest of the three and disagrees with curl twice over.
	//
	// SOURCE: Microsoft, HttpClient.DefaultProxy, read 2026-09-05 - "NO_PROXY: a
	// comma-separated list of hostnames that should be excluded from proxying.
	// Asterisks are not supported for wildcards; use a leading dot in case you
	// want to match a subdomain. Examples: NO_PROXY=.example.com (with leading
	// dot) will match www.example.com, but will not match example.com.
	// NO_PROXY=example.com (without leading dot) will not match www.example.com.
	// This behavior might be revisited in the future to match other ecosystems
	// better."
	// https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.defaultproxy
	//
	// THE VENDOR SAYING ITS OWN BEHAVIOUR MIGHT BE REVISITED IS WHY THIS IS A
	// SEPARATE RULE AND NOT A TWEAK. Folding it into curl's would make the report
	// silently wrong for .NET today, and folding curl's into it would make the
	// report silently wrong for curl the day Microsoft changes its mind.
	//
	// TWO CONSEQUENCES WORTH A ROW IN A REPORT. A bare name excuses only itself,
	// so NO_PROXY=corp.example leaves api.corp.example going through the proxy in
	// .NET while curl sends it direct. And NO_PROXY=*, the one value people reach
	// for to turn proxying off entirely, is not a wildcard here at all - it is a
	// host name nobody has, so .NET keeps using the proxy.
	RuleNoProxyDotNet Rule = "no_proxy_dotnet"
	// RuleWinINET is the ProxyOverride list, which Internet Explorer settings
	// hold and Edge, Chrome and .NET follow.
	RuleWinINET Rule = "wininet"
	// RuleWinHTTP is the bypass list in the machine's default WinHTTP
	// configuration, which services and much of the Windows stack follow.
	RuleWinHTTP Rule = "winhttp"
	// RuleNonProxyHosts is the JVM's http.nonProxyHosts property.
	RuleNonProxyHosts Rule = "non_proxy_hosts"
	// RuleExceptionsList is the macOS ExceptionsList, which scutil --proxy
	// reports and which every program going through the system configuration
	// follows.
	RuleExceptionsList Rule = "exceptions_list"
)

var ruleMeanings = map[Rule]string{
	RuleNoProxyCurl:    "the NO_PROXY environment variable, as curl reads it",
	RuleNoProxyDotNet:  "the NO_PROXY environment variable, as .NET reads it",
	RuleWinINET:        "the Windows ProxyOverride list, as Internet Explorer settings hold it",
	RuleWinHTTP:        "the bypass list in this machine's default WinHTTP configuration",
	RuleNonProxyHosts:  "the JVM's http.nonProxyHosts property",
	RuleExceptionsList: "the macOS ExceptionsList, as the system configuration holds it",
}

// AllRules lists every reading exactly once, in declaration order.
var AllRules = []Rule{RuleNoProxyCurl, RuleNoProxyDotNet, RuleWinINET, RuleWinHTTP, RuleNonProxyHosts, RuleExceptionsList}

// Valid reports whether r is one of the six.
func (r Rule) Valid() bool {
	_, ok := ruleMeanings[r]
	return ok
}

// Meaning returns the English text for r, or the empty string outside the list.
func (r Rule) Meaning() string { return ruleMeanings[r] }

// String makes Rule printable without a conversion at every call site.
func (r Rule) String() string { return string(r) }

// NonProxyHostsDefault is what a JVM bypasses when nobody set the property.
//
// SOURCE: Oracle, "Networking Properties" for JDK 21, read 2026-09-05 -
// http.nonProxyHosts has the default value "localhost|127.*|[::1]", and "the
// HTTPS protocol handler will use the same nonProxyHosts property as the HTTP
// protocol".
// https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/doc-files/net-properties.html
//
// IT IS HERE BECAUSE ITS ABSENCE IS A FACT, NOT A BLANK. A machine with
// HTTP_PROXY set and no Java configuration still sends localhost direct in a
// JVM and may not in curl - so a report that shows an empty Java exception list
// is describing a bypass that is happening.
const NonProxyHostsDefault = "localhost|127.*|[::1]"

// ExceptionsListDefault is what a stock Mac bypasses with nobody having
// configured a proxy at all.
//
// MEASURED RATHER THAN DOCUMENTED, which is the strongest kind of source this
// project has and the only rule here that has one. "scutil --proxy" on macOS
// with no proxy configured, 2026-09-05, returned an ExceptionsList holding
// exactly "*.local" and "169.254/16", and nothing else about proxying at all.
// The raw output is recorded beside probe S14 in internal_tools/README.md.
//
// SO EVERY STOCK MAC SENDS .local NAMES AND LINK-LOCAL ADDRESSES DIRECT, and
// that is a row in the report rather than a footnote: a helpdesk told "the proxy
// is configured" gets a different answer for one of those names than for
// anything else, with nobody having touched a setting.
//
// The entries are joined by newline because the platform hands them over as an
// ARRAY. This list has no separator of its own, so the separator is ours, and a
// newline is the one character an entry cannot contain.
const ExceptionsListDefault = "*.local\n169.254/16"

// Target is the place a run is asking about.
//
// IT CARRIES MORE THAN A HOST BECAUSE ONE OF THE FOUR RULES NEEDS MORE. A
// WinINET exception entry may begin with a protocol and may end with a port,
// and the vendor documents both as NARROWING the match. A signature of
// (list, host) would have to ignore them, which is the same as claiming an
// entry matches when the vendor says it does not.
type Target struct {
	// Scheme is the URL scheme, lower case, without "://". It may be empty when
	// a caller genuinely does not know it; see bypassWinINET for what an empty
	// scheme costs.
	Scheme string
	// Host is a host name or an IP literal, with no port and no brackets. A
	// bracketed IPv6 literal is accepted and unwrapped.
	//
	// IT IS EXPECTED IN PUNYCODE, not in its unicode spelling. curl documents
	// that "international hostnames require punycode encoding" in this list,
	// and this program already has internal/core/idna for exactly that
	// conversion - ADR57.
	Host string
	// Port is the decimal port, or empty when the URL did not name one.
	Port string
}

// normalise lower cases what is case insensitive and unwraps an IPv6 literal.
//
// Host names are case insensitive and a trailing dot is the same name, so the
// comparison has to happen on one spelling. Doing it here rather than in each
// of the four rules keeps it one rule in one place - the shape OBS50 has
// measured four times in this tree.
func (t Target) normalise() Target {
	t.Scheme = lower(t.Scheme)
	t.Host = lower(trimTrailingDot(unwrap(t.Host)))
	return t
}

// ErrUnknownRule is returned for a reading outside the four.
//
// It is an error rather than a false, because a rule this program does not know
// is a defect on our side and not something arriving from the machine being
// diagnosed. Answering "not excused" would put that defect in the report as a
// fact about somebody's proxy.
var ErrUnknownRule = fmt.Errorf("a proxy exception list can only be read under one of the rules in proxy.AllRules")

// ErrNoTarget is returned when there is no host to ask about.
var ErrNoTarget = fmt.Errorf("a proxy exception list is asked about a host, and none was given")
