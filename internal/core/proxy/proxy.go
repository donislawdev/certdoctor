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
// source - the program's own code, read, and a measurement where one can be
// taken - AND a consumer, a probe of the diagnosis or the noproxy tool (ADR147).
//
// ONE PROGRAM MAY HOLD SEVERAL READINGS OF NO_PROXY, one per range of versions
// whose code reads the list the same way. Node.js changed its reading five times
// in two years, inside release lines as well as between them, and a person on
// one release told what another release does has been told something untrue
// about their machine. Program and Versions say which range a reading speaks
// for.
//
// THE SYSTEM LISTS WERE SIX, THE CARVING SAID THREE, AND EACH EXTRA ONE ARRIVED
// FROM A SOURCE RATHER THAN FROM A HUNCH. The fourth: the two Windows stacks were
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
	// .NET's reading is RuleNoProxyDotNet below and Go's is RuleNoProxyGo, read
	// from Go's code rather than from this page (bypassNoProxyGo).
	//
	// This constant therefore promises curl, and git through the libcurl it is
	// linked with, and nothing wider, because a rule claiming to speak for
	// runtimes it was never checked against is exactly what inviolable rule 18
	// exists to stop.
	RuleNoProxyCurl Rule = "no_proxy_curl"
	// RuleNoProxyDotNet is the same variable read the way .NET reads it, which
	// is the strictest of the three: a bare name excuses only itself.
	//
	// THE PAGE BELOW IS WRONG ABOUT THE LEADING DOT, and that is measured, not
	// suspected (OBS233). .NET's own code matches ".example.com" against
	// example.com as well, and has since at least 2020; .NET 10 sent
	// example.test direct under NO_PROXY=.example.test. The quotation stays for
	// what it gets right - no asterisk, a bare name matching only itself - and
	// bypassNoProxyDotNet cites the code it follows instead.
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
	// RuleNoProxyDotNetNetworks is .NET from 11, which reads an entry written as
	// a network ("10.0.0.0/8") as a network and every other entry as before.
	RuleNoProxyDotNetNetworks Rule = "no_proxy_dotnet_11"
	// RuleNoProxyGo is Go's net/http, which never sends localhost or a loopback
	// address to a proxy and reads "*" in any position.
	RuleNoProxyGo Rule = "no_proxy_go"
	// RuleNoProxyPython is Python's urllib, which compares names as text, an
	// address included.
	RuleNoProxyPython Rule = "no_proxy_python"
	// RuleNoProxyRequests is requests up to 2.33, whose own loop compares the
	// end of the name as text, and pip up to 26.1, which carries it.
	RuleNoProxyRequests Rule = "no_proxy_requests"
	// RuleNoProxyRequestsDotBoundary is requests from 2.34, which matches only
	// at a dot, and pip from 26.2.
	RuleNoProxyRequestsDotBoundary Rule = "no_proxy_requests_2_34"
	// RuleNoProxyNodeHTTP is Node.js's own http and https modules up to the
	// release that made a leading dot match only at a dot.
	RuleNoProxyNodeHTTP Rule = "no_proxy_node_http"
	// RuleNoProxyNodeHTTPDotBoundary is the same modules from 24.16 and 26.1.
	RuleNoProxyNodeHTTPDotBoundary Rule = "no_proxy_node_http_24_16"
	// RuleNoProxyNodeFetch is fetch in Node.js - undici - before it learned to
	// read a leading dot as the domain too.
	RuleNoProxyNodeFetch Rule = "no_proxy_node_fetch"
	// RuleNoProxyNodeFetchApex is fetch from undici 7.22, where a leading dot or
	// "*." reaches the domain itself.
	RuleNoProxyNodeFetchApex Rule = "no_proxy_node_fetch_24_14_1"
	// RuleNoProxyNodeFetchBareIPv6 is fetch from undici 8.10, which reads an
	// IPv6 address without brackets.
	RuleNoProxyNodeFetchBareIPv6 Rule = "no_proxy_node_fetch_26_8"
	// RuleNoProxyNodeFetchTrailingDot is fetch from undici 8.10.2, which drops a
	// trailing dot on both sides.
	RuleNoProxyNodeFetchTrailingDot Rule = "no_proxy_node_fetch_26_8_2"
	// RuleNoProxyNodeFetchWildcard is fetch from undici 8.11, where "*" counts in
	// any position and "*." stops reaching the domain itself.
	RuleNoProxyNodeFetchWildcard Rule = "no_proxy_node_fetch_26_11"
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

// ruleText is what a person is told about a reading: what it reads, and for a
// reading of NO_PROXY, which program and which of its releases.
//
// THE VERSIONS ARE SOURCED, and where they come from is said once here rather
// than at every row. A range comes from the program's release notes and the
// history of the file holding the code - Node.js's changelogs and the undici
// tags that carry each change, the requests and pip release notes - read
// 2026-11-13 (ADR147). A single release names the one the code was read in,
// because nothing older was read.
//
// THE KEY IS A NAME A SCRIPT READS, the program's and not the reading's: the
// noproxy tool writes it into its document (ADR147), so it never changes. A
// reading's own identifier carries a release where its code changed, and stays
// out of that document, because a measurement can still move the release.
type ruleText struct {
	meaning  string
	program  string
	key      string
	versions string
	// condition is what a program needs before it reads the list at all, or
	// empty when reading the list is what it does with a proxy anyway.
	condition string
}

// nodeCondition is what Node.js needs before it takes a proxy, and with it
// NO_PROXY, from the environment - readings_node.go.
const nodeCondition = "NODE_USE_ENV_PROXY=1"

var ruleTexts = map[Rule]ruleText{
	RuleNoProxyCurl: {meaning: "the NO_PROXY environment variable, as curl reads it",
		program: "curl and git", key: "curl", versions: "8.23.0"},
	RuleNoProxyDotNet: {meaning: "the NO_PROXY environment variable, as .NET reads it",
		program: ".NET", key: "dotnet", versions: "10 and earlier"},
	RuleNoProxyDotNetNetworks: {meaning: "the NO_PROXY environment variable, as .NET 11 reads it",
		program: ".NET", key: "dotnet", versions: "11 and later"},
	RuleNoProxyGo: {meaning: "the NO_PROXY environment variable, as Go's net/http reads it",
		program: "Go", key: "go", versions: "1.27"},
	RuleNoProxyPython: {meaning: "the NO_PROXY environment variable, as Python's urllib reads it",
		program: "Python urllib", key: "python", versions: "3.10 and later"},
	RuleNoProxyRequests: {meaning: "the NO_PROXY environment variable, as requests up to 2.33 reads it",
		program: "requests and pip", key: "requests", versions: "requests 2.33 and earlier, pip 26.1 and earlier"},
	RuleNoProxyRequestsDotBoundary: {meaning: "the NO_PROXY environment variable, as requests from 2.34 reads it",
		program: "requests and pip", key: "requests", versions: "requests 2.34 and later, pip 26.2 and later"},
	RuleNoProxyNodeHTTP: {meaning: "the NO_PROXY environment variable, as Node.js http reads it",
		program: "Node.js http and https", key: "node_http", versions: "22.21 and later 22, 24.5 to 24.15, 26.0",
		condition: nodeCondition},
	RuleNoProxyNodeHTTPDotBoundary: {meaning: "the NO_PROXY environment variable, as Node.js http from 24.16 reads it",
		program: "Node.js http and https", key: "node_http", versions: "24.16 and later 24, 26.1 and later",
		condition: nodeCondition},
	RuleNoProxyNodeFetch: {meaning: "the NO_PROXY environment variable, as Node.js fetch reads it",
		program: "Node.js fetch", key: "node_fetch", versions: "22.21 and later 22, 24.0 to 24.14.0",
		condition: nodeCondition},
	RuleNoProxyNodeFetchApex: {meaning: "the NO_PROXY environment variable, as Node.js fetch from 24.14.1 reads it",
		program: "Node.js fetch", key: "node_fetch", versions: "24.14.1 and later 24, 26.0 to 26.7",
		condition: nodeCondition},
	RuleNoProxyNodeFetchBareIPv6: {meaning: "the NO_PROXY environment variable, as Node.js fetch from 26.8 reads it",
		program: "Node.js fetch", key: "node_fetch", versions: "26.8.0 to 26.8.1", condition: nodeCondition},
	RuleNoProxyNodeFetchTrailingDot: {meaning: "the NO_PROXY environment variable, as Node.js fetch from 26.8.2 reads it",
		program: "Node.js fetch", key: "node_fetch", versions: "26.8.2 to 26.10", condition: nodeCondition},
	RuleNoProxyNodeFetchWildcard: {meaning: "the NO_PROXY environment variable, as Node.js fetch from 26.11 reads it",
		program: "Node.js fetch", key: "node_fetch", versions: "26.11 and later", condition: nodeCondition},
	RuleWinINET:        {meaning: "the Windows ProxyOverride list, as Internet Explorer settings hold it"},
	RuleWinHTTP:        {meaning: "the bypass list in this machine's default WinHTTP configuration"},
	RuleNonProxyHosts:  {meaning: "the JVM's http.nonProxyHosts property"},
	RuleExceptionsList: {meaning: "the macOS ExceptionsList, as the system configuration holds it"},
}

// NoProxyRules are the readings of the NO_PROXY variable, one per program and
// range of releases, in the order a person looks for them: the command line
// tools first, then the runtimes, each program's oldest reading first.
var NoProxyRules = []Rule{
	RuleNoProxyCurl, RuleNoProxyDotNet, RuleNoProxyDotNetNetworks, RuleNoProxyGo, RuleNoProxyPython,
	RuleNoProxyRequests, RuleNoProxyRequestsDotBoundary, RuleNoProxyNodeHTTP, RuleNoProxyNodeHTTPDotBoundary,
	RuleNoProxyNodeFetch, RuleNoProxyNodeFetchApex, RuleNoProxyNodeFetchBareIPv6,
	RuleNoProxyNodeFetchTrailingDot, RuleNoProxyNodeFetchWildcard,
}

// AllRules lists every reading exactly once: the NO_PROXY readings, then the
// lists a system keeps.
var AllRules = append(append([]Rule{}, NoProxyRules...),
	RuleWinINET, RuleWinHTTP, RuleNonProxyHosts, RuleExceptionsList)

// Valid reports whether r is one of AllRules.
func (r Rule) Valid() bool {
	_, ok := ruleTexts[r]
	return ok
}

// Meaning returns the English text for r, or the empty string outside the list.
func (r Rule) Meaning() string { return ruleTexts[r].meaning }

// Program names the program a NO_PROXY reading speaks for, and is empty for a
// list a system keeps.
func (r Rule) Program() string { return ruleTexts[r].program }

// ProgramKey names Program for a script: one lower case word per program, the
// same for every reading of it, and empty for a list a system keeps.
func (r Rule) ProgramKey() string { return ruleTexts[r].key }

// Versions names the releases of Program a reading speaks for.
func (r Rule) Versions() string { return ruleTexts[r].versions }

// Condition is what Program needs before it reads the list at all - Node.js
// takes no proxy from the environment without NODE_USE_ENV_PROXY=1 - and is
// empty for a program that reads it whenever it has a proxy.
func (r Rule) Condition() string { return ruleTexts[r].condition }

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
// IT CARRIES MORE THAN A HOST BECAUSE SEVERAL RULES NEED MORE. A WinINET
// exception entry may begin with a protocol and may end with a port, and the
// vendor documents both as NARROWING the match; Go, Python, requests and
// Node.js read a port in a NO_PROXY entry, and some of them compare it only
// when the URL wrote one. A signature of (list, host) would have to ignore
// them, which is the same as claiming an entry matches when the program says
// it does not.
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
	// Port is the decimal port, or empty when the URL did not name one. EMPTY
	// IS NOT THE DEFAULT PORT: Python's urllib and requests compare an entry's
	// port only with a port the URL wrote, so the two are different questions.
	Port string
}

// normalise lower cases what is case insensitive and unwraps an IPv6 literal.
//
// Host names are case insensitive and a trailing dot is the same name, so the
// comparison has to happen on one spelling. Doing it here rather than in each
// of the rules that read the host this way keeps it one rule in one place -
// the shape OBS50 has measured four times in this tree. .NET and the readings
// added for the noproxy tool do not use it; see reading in bypass.go.
func (t Target) normalise() Target {
	t = t.foldCase()
	t.Host = trimTrailingDot(t.Host)
	return t
}

// foldCase is normalise without dropping the trailing dot - the host the way
// .NET's Uri hands it to its NO_PROXY reading, in lower case and with the root
// label kept. See reading in bypass.go.
func (t Target) foldCase() Target {
	t.Scheme = lower(t.Scheme)
	t.Host = lower(unwrap(t.Host))
	return t
}

// ErrUnknownRule is returned for a reading outside AllRules.
//
// It is an error rather than a false, because a rule this program does not know
// is a defect on our side and not something arriving from the machine being
// diagnosed. Answering "not excused" would put that defect in the report as a
// fact about somebody's proxy.
var ErrUnknownRule = fmt.Errorf("a proxy exception list can only be read under one of the rules in proxy.AllRules")

// ErrNotASCII is returned by a reading that takes printable ASCII only, for a
// list or a target holding anything else. See Decide.
var ErrNotASCII = fmt.Errorf("this reading of NO_PROXY answers only for printable ASCII text")

// ErrNoTarget is returned when there is no host to ask about.
var ErrNoTarget = fmt.Errorf("a proxy exception list is asked about a host, and none was given")
