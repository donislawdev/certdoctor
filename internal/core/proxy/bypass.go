package proxy

import (
	"fmt"
	"net/netip"
	"strings"
)

// Decision is what one program does with one list for one place.
type Decision struct {
	// Direct is true when the program goes to the place without the proxy.
	Direct bool
	// Entry is the part of the list that sent it direct, as the program cut it
	// out of the list - after the program trimmed it, before it folded case or
	// took off a dot or a port - so that a person can find it in their own
	// value. Empty when no entry did.
	Entry string
	// Basis is what the decision rests on.
	Basis Basis
}

// Basis is what a Decision rests on. The list is closed.
type Basis string

const (
	// BasisEntry is an entry of the list applying to the place.
	BasisEntry Basis = "entry"
	// BasisWholeValue is a value that is exactly "*", which some programs read
	// as "never use a proxy" only when it is the whole value.
	BasisWholeValue Basis = "whole_value"
	// BasisLocal is a place the program never sends to a proxy, whatever the
	// list says. Go is the one program with such places: localhost and the
	// loopback addresses.
	BasisLocal Basis = "local"
	// BasisNoEntry is nothing in the list applying: the proxy is used.
	BasisNoEntry Basis = "no_entry"
)

func byEntry(entry string) Decision { return Decision{Direct: true, Entry: entry, Basis: BasisEntry} }

func byWholeValue() Decision { return Decision{Direct: true, Entry: "*", Basis: BasisWholeValue} }

func throughProxy() Decision { return Decision{Basis: BasisNoEntry} }

// Decide answers, for one reading, whether the program goes to the target
// directly or through the proxy, and which entry of the list decided it.
//
// THE SAME LIST AND THE SAME HOST GIVE DIFFERENT ANSWERS UNDER DIFFERENT RULES,
// and that is the point of the function taking the rule rather than guessing it.
// A report that picked one reading would be right about one runtime on the
// machine and quietly wrong about the others.
//
// THE READINGS ADDED FOR THE noproxy TOOL TAKE PRINTABLE ASCII ONLY, and say so
// with ErrNotASCII rather than answering. Every one of those programs trims,
// folds case and converts international names its own way - Go turns an entry
// into punycode, Python lower-cases by its own Unicode tables - and none of that
// is read here, so an answer about such a list would be a guess presented as a
// fact about somebody's program.
func Decide(r Rule, list string, t Target) (Decision, error) {
	read, ok := readings[r]
	if !ok {
		// A RULE OUTSIDE THE LIST ARRIVES HERE RATHER THAN INHERITING A READING.
		// OBS95 was a classification that sorted every input into three cases
		// and let the fourth fall through every check without one - measured,
		// and invisible because the fourth case did not exist yet. A default
		// that silently picks a reading would put an unchecked claim about
		// somebody's runtime into the report.
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownRule, string(r))
	}
	if t.normalise().Host == "" {
		return Decision{}, ErrNoTarget
	}
	if read.asciiOnly && !(printableASCII(list) && printableASCII(t.Host) && printableASCII(t.Port)) {
		return Decision{}, ErrNotASCII
	}
	return read.decide(list, t), nil
}

// Bypasses reports whether the target is excused from the proxy by list, read
// under one runtime family's rule - Decide, without the entry and the basis.
func Bypasses(r Rule, list string, t Target) (bool, error) {
	d, err := Decide(r, list, t)
	return d.Direct, err
}

// reading is the code of one rule.
//
// THE FIRST SIX SEE THE HOST IN ONE SPELLING, lower case and without a trailing
// dot (Target.normalise), because the lists they read are compared that way by
// their programs or by the vendor's description. THE READINGS ADDED WITH ADR147
// SEE THE HOST AS GIVEN and spell it the way their program does - Go keeps
// "LOCALHOST" apart from "localhost", Python keeps a trailing dot - because each
// was read from the program's code, and that code does not all agree.
type reading struct {
	decide    func(list string, t Target) Decision
	asciiOnly bool
}

func normalised(read func(string, Target) Decision) reading {
	return reading{decide: func(list string, t Target) Decision { return read(list, t.normalise()) }}
}

func asWritten(read func(string, Target) Decision) reading {
	return reading{decide: read, asciiOnly: true}
}

var readings = map[Rule]reading{
	RuleNoProxyCurl:   normalised(bypassNoProxyCurl),
	RuleNoProxyDotNet: normalised(func(list string, t Target) Decision { return bypassNoProxyDotNet(list, t, false) }),
	RuleNoProxyDotNetNetworks: {decide: func(list string, t Target) Decision {
		return bypassNoProxyDotNet(list, t.normalise(), true)
	}, asciiOnly: true},
	RuleNoProxyGo:     asWritten(bypassNoProxyGo),
	RuleNoProxyPython: asWritten(bypassNoProxyPython),
	RuleNoProxyRequests: asWritten(func(list string, t Target) Decision {
		return bypassNoProxyRequests(list, t, false)
	}),
	RuleNoProxyRequestsDotBoundary: asWritten(func(list string, t Target) Decision {
		return bypassNoProxyRequests(list, t, true)
	}),
	RuleNoProxyNodeHTTP: asWritten(func(list string, t Target) Decision {
		return bypassNoProxyNodeHTTP(list, t, false)
	}),
	RuleNoProxyNodeHTTPDotBoundary: asWritten(func(list string, t Target) Decision {
		return bypassNoProxyNodeHTTP(list, t, true)
	}),
	RuleNoProxyNodeFetch:            undiciReading(undiciFeatures{}),
	RuleNoProxyNodeFetchApex:        undiciReading(undiciFeatures{apex: true}),
	RuleNoProxyNodeFetchBareIPv6:    undiciReading(undiciFeatures{apex: true, bareIPv6: true}),
	RuleNoProxyNodeFetchTrailingDot: undiciReading(undiciFeatures{apex: true, bareIPv6: true, trailingDot: true}),
	RuleNoProxyNodeFetchWildcard: undiciReading(undiciFeatures{apex: true, bareIPv6: true, trailingDot: true,
		wildcard: true}),
	RuleWinINET:        normalised(bypassWinINET),
	RuleWinHTTP:        normalised(bypassWinHTTP),
	RuleNonProxyHosts:  normalised(bypassNonProxyHosts),
	RuleExceptionsList: normalised(bypassExceptionsList),
}

// printableASCII reports whether s holds only printable ASCII and tabs.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < ' ' && c != '\t') || c > '~' {
			return false
		}
	}
	return true
}

// bypassNoProxyCurl reads the list the way curl's own code walks NO_PROXY.
//
// SOURCE: curl, lib/proxy.c at tag curl-8_23_0 - proxy_check_noproxy,
// match_host, match_ip, cidr4_match and cidr6_match - read 2026-11-13, and
// MEASURED the same day with curl 8.23.0 against a proxy that records what
// reaches it (ADR147). The page docs/cmdline-opts/noproxy.md this rule was first
// written from says less than the code does, and three of the differences
// changed answers (OBS234).
// https://raw.githubusercontent.com/curl/curl/curl-8_23_0/lib/proxy.c
//
// A NAME matches itself or any name ending in a dot and itself, without regard
// to case, with one leading dot and one trailing dot ignored - ".local.com" and
// "local.com" cannot answer differently.
//
// AN ADDRESS IS COMPARED AS AN ADDRESS AND NEVER AS A NAME. A host that is an
// IP literal is held against the entries that are addresses or networks, and
// a name entry cannot match it: measured, "0.0.1" does not excuse 10.0.0.1,
// although the text ends in ".0.0.1". See curlAddressMatches.
//
// THE LONE ASTERISK IS THE WHOLE VALUE, BYTE FOR BYTE. curl compares the value
// with "*" before reading any entry, so " *" is not it and "a.com,*" holds an
// entry named "*" that matches nothing - both measured.
func bypassNoProxyCurl(list string, t Target) Decision {
	if list == "*" {
		return byWholeValue()
	}
	addr, isAddr := curlHostAddr(t.Host)
	for _, entry := range curlEntries(list) {
		if isAddr {
			if curlAddressMatches(entry, addr) {
				return byEntry(entry)
			}
			continue
		}
		// match_host drops one trailing dot and then one leading dot, in that
		// order, and nothing else.
		name := lower(strings.TrimPrefix(trimTrailingDot(entry), "."))
		if name == "" {
			continue
		}
		if t.Host == name || strings.HasSuffix(t.Host, "."+name) {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// curlEntries cuts a NO_PROXY value the way proxy_check_noproxy walks it: an
// entry ends at a comma, a space or a tab, blanks around a comma are passed
// over, and A BLANK THAT NO COMMA FOLLOWS ENDS THE LIST. "a.test b.test" is the
// one entry a.test - measured, b.test went through the proxy and a.test did
// not - which is the difference a list pasted with spaces instead of commas
// makes, and the one this rule got wrong while it split on commas alone.
func curlEntries(list string) []string {
	var entries []string
	i := 0
	for i < len(list) {
		i = curlPassBlanks(list, i)
		start := i
		for i < len(list) && list[i] != ',' && !curlBlank(list[i]) {
			i++
		}
		if i > start {
			entries = append(entries, list[start:i])
		}
		i = curlPassBlanks(list, i)
		if i >= len(list) || list[i] != ',' {
			break
		}
		for i < len(list) && list[i] == ',' {
			i++
		}
	}
	return entries
}

// curlBlank is ISBLANK in curl: a space or a tab, and nothing else - a line
// break stays inside an entry.
func curlBlank(c byte) bool { return c == ' ' || c == '\t' }

func curlPassBlanks(list string, i int) int {
	for i < len(list) && curlBlank(list[i]) {
		i++
	}
	return i
}

// curlHostAddr reads the host as curl does before walking the list: an IPv4
// literal, else an IPv6 literal, else a name. An IPv4 address in its
// IPv6-mapped spelling STAYS IPv6, because curl tries AF_INET6 on it and never
// unmaps it - measured, "10.0.0.0/8" does not excuse [::ffff:10.0.0.1].
func curlHostAddr(host string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr, true
}

// curlAddressMatches holds one entry against an address host, by match_ip and
// the two cidr functions of curl 8.23.
//
// The entry is a full address with an optional "/bits" in decimal, read by
// inet_pton of the host's own family - so an IPv4 entry never matches an IPv6
// host, a bracketed "[::1]" never matches anything (measured: [::1] went
// through the proxy, ::1 did not), and the abbreviated "169.254/16" macOS ships
// is not an address here.
//
// "/0" IS NOT EVERYTHING IN CURL 8.23, and that is measured too: "0.0.0.0/0"
// did not excuse 10.0.0.1. Absent bits, "/0" and "/32" all mean the address
// itself for IPv4, and absent bits and "/0" mean all 128 bits for IPv6. curl
// changed that two days after 8.23 shipped (be652f3, "proxy: fix 0.0.0.0/0 and
// ::/0 CIDR matching", 2026-10-16), so a later curl excuses everything for
// those two entries. THIS RULE READS THE CURL PEOPLE HAVE: it cannot tell which
// curl a machine runs, and of the two answers it keeps the one that claims no
// bypass.
func curlAddressMatches(entry string, host netip.Addr) bool {
	network, bits, ok := curlNetwork(entry)
	if !ok || network.Is4() != host.Is4() {
		return false
	}
	if host.Is4() {
		if bits > 32 {
			return false
		}
		if bits > 0 && bits != 32 {
			return netip.PrefixFrom(network, bits).Masked().Contains(host)
		}
		return network == host
	}
	// curlNetwork has refused more than 128 bits already.
	if bits == 0 {
		bits = 128
	}
	return netip.PrefixFrom(network, bits).Masked().Contains(host)
}

// curlNetwork splits an entry into its address and its bits, 0 when it has no
// slash. The bits are read the way curlx_str_number reads them with a ceiling
// of 128: decimal digits, leading zeros allowed ("0128" is 128), and a value
// over the ceiling makes the entry unreadable as a network.
func curlNetwork(entry string) (netip.Addr, int, bool) {
	text, bitsText, slash := strings.Cut(entry, "/")
	bits := 0
	if slash {
		if !isDigits(bitsText) {
			return netip.Addr{}, 0, false
		}
		for _, c := range bitsText {
			if bits = bits*10 + int(c-'0'); bits > 128 {
				return netip.Addr{}, 0, false
			}
		}
	}
	addr, err := netip.ParseAddr(text)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, 0, false
	}
	return addr, bits, true
}

// bypassNoProxyDotNet reads the same variable the way .NET's own code does,
// which agrees with curl about a leading dot and disagrees about everything
// else.
//
// SOURCE: dotnet/runtime, HttpEnvironmentProxy.cs, IsMatchInBypassList - read
// 2026-11-13 on main and in its 2020 and 2023 versions, the same branch in all
// three - and MEASURED the same day with .NET 10 against a proxy that records
// what reaches it (ADR147, OBS233). The page quoted at RuleNoProxyDotNet says
// the opposite about the leading dot, and the code and the measurement win.
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Net.Http/src/System/Net/Http/SocketsHttpHandler/HttpEnvironmentProxy.cs
//
// A LEADING DOT MATCHES THE DOMAIN AND EVERY SUBDOMAIN - the code says ".foo.com
// will match foo.com it self or *.foo.com", and NO_PROXY=.example.test sent both
// example.test and www.example.test direct. A BARE NAME MATCHES ONLY ITSELF:
// NO_PROXY=example.test sent www.example.test through the proxy, which is
// where .NET and curl part company.
//
// THE ENTRY IS COMPARED AS WRITTEN, apart from the case and the spaces around
// it. A trailing dot is not dropped - "example.test." left example.test going
// through the proxy - and an IPv6 address is held against the host as .NET's
// Uri spells it, in brackets: "[::1]" excused [::1] and "::1" did not.
//
// THERE IS NO WILDCARD UP TO NOW AND NO NETWORK UP TO .NET 10. "*" and
// "*.example.test" are names nobody has - which is why NO_PROXY=* leaves .NET
// using the proxy - and "10.0.0.0/8" did not excuse 10.0.0.1 in .NET 10.
//
// .NET 11 READS NETWORKS, and with networks set this is its reading (OBS235).
// SOURCE: HttpEnvironmentProxy.cs at tag v11.0.0, read 2026-11-13 - the
// constructor hands every entry IPNetwork.TryParse accepts to a list of
// networks INSTEAD of the list of names, and IsMatchInBypassList asks the
// networks after the names, only for a host that is an address. The tag's file
// is byte for byte the one on main read the same day. dotNetNetwork is how an
// entry becomes a network. L2's row stays on .NET 10's reading, as ADR147 point
// 2 decided.
func bypassNoProxyDotNet(list string, t Target, networks bool) Decision {
	host := t.Host
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		host = "[" + host + "]"
	}
	var nets []string
	for _, entry := range splitList(list, ",") {
		if _, ok := dotNetNetwork(entry); ok && networks {
			nets = append(nets, entry)
			continue
		}
		name := lower(entry)
		if strings.HasPrefix(name, ".") {
			if host == name[1:] || strings.HasSuffix(host, name) {
				return byEntry(entry)
			}
			continue
		}
		if host == name {
			return byEntry(entry)
		}
	}
	return dotNetNetworkDecision(nets, t.Host)
}

// bypassWinINET reads the list the way Internet Explorer settings document it -
// the value that lives in ProxyOverride and that Edge, Chrome and .NET follow.
//
// SOURCE: Microsoft, "Use Proxy Servers with Internet Explorer" (KB 4551930),
// read 2026-09-05. "Multiple entries should be separated by semicolons." "A
// proxy bypass entry might begin by using an http://, https://, ftp://, or
// gopher:// protocol type. If a protocol type is used, the exception entry
// applies only to requests for that protocol." "If a port number is given, the
// request is processed only if all previous requirements are met and the
// request uses the specified port number." A wildcard may sit at the beginning
// ("*.example.com"), in the middle ("www.*.com") or at the end
// ("www.microsoft.*"), and several may be combined ("123.1*.66.*").
// https://learn.microsoft.com/en-us/troubleshoot/developer/browsers/connectivity-navigation/use-proxy-servers-with-ie
//
// THIS IS WHERE THE TWO WINDOWS STACKS PART COMPANY. Everything in the previous
// paragraph about a wildcard at the end is exactly what bypassWinHTTP refuses,
// with the vendor's own "aaa.* is not supported" beside it. One ProxyOverride
// string, two truthful answers.
//
// AN ENTRY WITH A PATH IS NOT HANDLED HERE AND THE REASON IS WRITTEN DOWN. The
// same page says the list "is intended to bypass servers, and not URLs" and that
// a trailing slash or a subweb is "invalidating the whole list otherwise" - so a
// user with "https://www.microsoft.com/" in ProxyOverride may have a list that
// excuses nothing at all. That is a finding worth reporting and it is not
// implemented as a matching rule, because killing the whole list on a documented
// sentence we have never measured would make this program claim a bypass is
// absent when it may not be. It is parked as OBS109 for P8-K3, where there is a
// layer that can say it out loud as a note beside the row.
//
// A BARE NAME HERE IS NOT A DOMAIN, WHICH IS THE OTHER HALF OF THE DIVERGENCE.
// The settings box is labelled "Do not use proxy server for addresses beginning
// with", and the same page tells a user who wants a whole domain to write
// "*.domain.com" - so "local.com" excuses that host and not "www.local.com".
// Under RuleNoProxyCurl the identical entry excuses both, because curl documents the
// opposite. Two runtimes, one string, two answers, and neither is misconfigured.
//
// AN EMPTY SCHEME LOSES TO A SCHEME-QUALIFIED ENTRY, deliberately. A caller that
// does not know the scheme cannot be told an entry applies, because the vendor
// says it applies only to that protocol - so the honest answer is "not excused",
// which sends the run through the proxy rather than claiming it will not.
func bypassWinINET(list string, t Target) Decision {
	for _, entry := range splitList(list, ";") {
		if isLocalMacro(entry) {
			if !strings.Contains(t.Host, ".") {
				return byEntry(entry)
			}
			continue
		}
		scheme, pattern, port := splitWinINETEntry(entry)
		if scheme != "" && scheme != t.Scheme {
			continue
		}
		if port != "" && port != t.Port {
			continue
		}
		if matchStar(t.Host, lower(trimTrailingDot(unwrap(pattern)))) {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// bypassWinHTTP reads the bypass list the way WinHTTP documents its own.
//
// SOURCE: Microsoft, WINHTTP_PROXY_INFO, read 2026-09-05 - "The proxy bypass
// list contains one or more server names separated by semicolons or whitespace.
// The proxy bypass list can also contain the string "<local>" to indicate that
// all local intranet sites are bypassed. Local intranet sites are considered to
// be all servers that do not contain a period in their name."
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_proxy_info
//
// SOURCE for the wildcard, same day: Microsoft, "ProxyCfg.exe proxy
// configuration tool" - the list "can contain wildcards, such as "*", that cause
// the application to bypass the proxy server for addresses that fit the
// specified pattern, for example, "*.microsoft.com" or "*.org". Wildcard
// characters must be the left-most characters in the list. For example, "aaa.*"
// is not supported."
// https://learn.microsoft.com/en-us/windows/win32/winhttp/proxycfg-exe--a-proxy-configuration-tool
//
// "NOT SUPPORTED" NEEDS NO BRANCH OF ITS OWN, AND THAT IS WORTH A SENTENCE
// BECAUSE THE FIRST DRAFT HAD ONE. The vendor says "aaa.*" is unsupported and
// does not say what happens instead. An explicit branch rejecting a non-leading
// asterisk was written, and then measured to be unable to change any answer: a
// host name cannot contain an asterisk, so an entry keeping one loses the exact
// comparison below anyway. It was a line that decided nothing, which is the one
// kind of code a mutation entry can never redden - OBS48 read from the other
// end. The vendor's rule falls out of the comparison instead of being asserted
// beside it, and the direction is the safe one for a diagnostic: the entry
// excuses nobody, so the run goes through the proxy rather than being told it
// will not.
func bypassWinHTTP(list string, t Target) Decision {
	for _, entry := range splitList(list, "; \t\r\n") {
		if isLocalMacro(entry) {
			if !strings.Contains(t.Host, ".") {
				return byEntry(entry)
			}
			continue
		}
		pattern := lower(trimTrailingDot(unwrap(entry)))
		if rest := strings.TrimLeft(pattern, "*"); len(rest) < len(pattern) {
			// A left-most wildcard, which is the only kind this stack honours.
			if strings.HasSuffix(t.Host, rest) {
				return byEntry(entry)
			}
			continue
		}
		if t.Host == pattern {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// bypassNonProxyHosts reads the list the way the JVM documents nonProxyHosts.
//
// SOURCE: Oracle, "Networking Properties" for JDK 21, read 2026-09-05 -
// http.nonProxyHosts is "a list of hosts, separated by the '|' character", "the
// wildcard character '*' can be used for pattern matching", the documented
// example is -Dhttp.nonProxyHosts="*.foo.com|localhost", and the default value
// is "localhost|127.*|[::1]".
// https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/doc-files/net-properties.html
//
// THE WILDCARD IS NOT PINNED TO THE LEFT HERE, and the proof is the vendor's own
// default: "127.*" has it on the right. So this is a third distinct wildcard
// rule on one machine, not a copy of either Windows one.
//
// THE DEFAULT IS NOT SUBSTITUTED HERE. An empty list means an empty list; the
// caller that knows whether the property was set at all is the one allowed to
// put NonProxyHostsDefault in its place. Substituting it here would make "nobody
// configured this" and "somebody configured exactly the default" give the same
// answer with no way to tell them apart.
func bypassNonProxyHosts(list string, t Target) Decision {
	for _, entry := range splitList(list, "|") {
		if matchesEntry(t.Host, entry) {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// matchesEntry is the comparison the two asterisk-only rules share: normalise
// the entry the way the host was normalised, then glob it.
//
// IT IS ONE FUNCTION BECAUSE IT IS ONE OPERATION, and writing it out at both
// call sites is the shape that disarmed two mutation entries in this very slice
// - one STRING in two places, which is OBS50 sharpened. The two rules stay
// different where they actually differ: their separator, and whether an entry
// may be a network.
func matchesEntry(host, entry string) bool {
	return matchStar(host, lower(trimTrailingDot(unwrap(entry))))
}

// bypassExceptionsList reads the macOS ExceptionsList.
//
// THIS IS THE ONE RULE HERE THAT RESTS ON OUR OWN MEASUREMENT RATHER THAN ON A
// VENDOR'S PAGE, so the line between what was measured and what was read matters
// more here than anywhere else in this package.
//
// MEASURED, 2026-09-05, "scutil --proxy" on a Mac with no proxy configured: the
// list is there even then, holding "*.local" and "169.254/16" - see
// ExceptionsListDefault.
//
// READ RATHER THAN MEASURED: that "*" is a wildcard here, and that "169.254/16"
// denotes 169.254.0.0/16. Apple documents neither. Checked the same day, the
// CFNetwork constant page for kCFNetworkProxiesExceptionsList carries no
// description of the entries at all, so there is nothing to quote. The
// abbreviated network form is the BSD inet_net_pton convention macOS inherits,
// where omitted trailing octets are zero, and the wildcard reading is the one
// the measured default only makes sense under.
//
// THE ABBREVIATED FORM IS WHY THIS CANNOT BORROW RuleNoProxyCurl, and the difference
// is not cosmetic. curl documents CIDR as "an appended slash and number of bits
// to an IP ADDRESS", and netip.ParsePrefix refuses "169.254/16" outright - so
// reading the macOS default under curl's rule would turn the link-local entry
// into a host name nobody has, and silently drop a bypass that is really
// happening on every Mac.
func bypassExceptionsList(list string, t Target) Decision {
	for _, entry := range splitList(list, "\n\r") {
		if prefix, ok := asAbbreviatedPrefix(entry); ok {
			if addr, ok := asAddr(t.Host); ok && prefix.Contains(addr) {
				return byEntry(entry)
			}
			continue
		}
		if matchesEntry(t.Host, entry) {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// asAbbreviatedPrefix reads an entry as a network written in the BSD form where
// trailing zero octets may be left out - "169.254/16" for 169.254.0.0/16.
//
// An entry with no slash is not one. An entry with a slash that still will not
// parse comes back as not-a-prefix and falls through to the name comparison,
// which is the same conservative direction the rest of this package takes: no
// claim of a bypass we could not read.
func asAbbreviatedPrefix(entry string) (netip.Prefix, bool) {
	network, bits, ok := strings.Cut(entry, "/")
	if !ok {
		return netip.Prefix{}, false
	}
	// An over-long address needs no guard of its own: padding leaves it as it
	// was and ParsePrefix refuses it below. A length check here would look like
	// it enforced something and would be the third line in this package unable
	// to change an answer.
	if !strings.Contains(network, ":") {
		parts := strings.Split(network, ".")
		for len(parts) < 4 {
			parts = append(parts, "0")
		}
		network = strings.Join(parts, ".")
	}
	prefix, err := netip.ParsePrefix(network + "/" + bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// isLocalMacro reports whether an entry is the <local> macro. The comparison is
// case insensitive because the entries around it are, and no source says this
// one is different.
//
// THE MACRO IS SOURCED FOR WinHTTP AND MEASURED FOR WinINET - OBS110, closed.
// The vendor defines <local> in WINHTTP_PROXY_INFO outright. For Internet
// Explorer settings it describes only the CHECKBOX with the same meaning and
// never says the registry spells it as this token, so applying it to both stacks
// was at first a step this program took rather than read. Measured 2026-09-05 by
// the mutating half of probe S14: with "<local>;*.s14.invalid" written to
// ProxyOverride, WinHttpGetIEProxyConfigForCurrentUser hands the token back
// verbatim. It is now our own measurement rather than an inference.
func isLocalMacro(entry string) bool { return strings.EqualFold(entry, "<local>") }

// splitWinINETEntry pulls an optional scheme and an optional port off an entry.
//
// THE PORT IS TAKEN OFF THE RIGHT AND ONLY WHEN IT IS DIGITS, so that an IPv6
// literal written without brackets keeps its colons instead of donating the last
// group to a port that was never there.
func splitWinINETEntry(entry string) (scheme, pattern, port string) {
	pattern = entry
	if i := strings.Index(pattern, "://"); i >= 0 {
		scheme = lower(pattern[:i])
		pattern = pattern[i+len("://"):]
	}
	if i := strings.LastIndex(pattern, ":"); i >= 0 {
		host, tail := pattern[:i], pattern[i+1:]
		switch {
		case strings.HasSuffix(host, "]") && isDigits(tail):
			// A bracketed IPv6 literal followed by a port.
			pattern, port = host, tail
		case !strings.Contains(host, ":") && isDigits(tail):
			// An ordinary name or IPv4 address followed by a port.
			pattern, port = host, tail
		}
		// Anything else still holding colons is a bare IPv6 literal, and its
		// last group is not a port.
	}
	return scheme, pattern, port
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// splitList cuts a list on any of the given separator characters, trims spaces
// off each entry and drops the empty ones.
//
// ONE FUNCTION FOR FOUR SEPARATORS RATHER THAN FOUR FUNCTIONS: the separator is
// the only thing that differs, and four copies of the trimming would be one rule
// in four places, which is the shape OBS50 has measured four times here. The
// separators themselves stay at each call site, beside the source that names
// them.
func splitList(list, separators string) []string {
	fields := strings.FieldsFunc(list, func(r rune) bool {
		return strings.ContainsRune(separators, r)
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// matchStar reports whether text matches pattern, where "*" stands for any run
// of characters and every other character stands for itself.
//
// WHY THIS IS NOT pac.ShExpMatch, WHICH ALREADY LIVES IN THIS TREE. That one
// implements the PAC specification: "*" AND "?" AND character classes like
// "[abc]". Microsoft and Oracle both document exactly one wildcard for an
// exception list. Borrowing the PAC matcher would turn "foo?.corp" and
// "[abc].corp" into patterns in a place where no vendor promised them, which is
// a claim about somebody's machine that nobody made. Same shape, different rule
// - so it is a second function and not a second CALLER, and OBS50 is about the
// second place a rule lives, not the second place an algorithm does.
//
// IT IS ITERATIVE AND ITS WORST CASE IS THE PRODUCT OF THE TWO LENGTHS. The
// obvious recursive glob backtracks exponentially on "*a*a*a*b", and the pattern
// here comes out of somebody else's registry.
//
// IT COMPARES RUNES, NOT BYTES - OBS88. A bypass list may hold a name in its
// unicode spelling even where curl asks for punycode, and comparing bytes would
// let a "*" swallow a third of a letter.
func matchStar(text, pattern string) bool {
	s, p := []rune(text), []rune(pattern)
	starPattern, starText := -1, 0
	si, pi := 0, 0

	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			starPattern, starText = pi, si
			pi++
		case pi < len(p) && p[pi] == s[si]:
			si++
			pi++
		case starPattern >= 0:
			starText++
			si, pi = starText, starPattern+1
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// asAddr reads a host as an IP address, or says it is a name.
func asAddr(host string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	// An IPv4 address that arrived in its IPv6-mapped spelling has to compare
	// against an IPv4 block, or "192.168.0.0/16" would miss "::ffff:192.168.1.1".
	return addr.Unmap(), true
}

func lower(s string) string { return strings.ToLower(s) }

// trimTrailingDot removes the root label. "example.com." and "example.com" are
// the same name, and only one of them can win a string comparison.
func trimTrailingDot(s string) string {
	if len(s) > 1 && strings.HasSuffix(s, ".") {
		return s[:len(s)-1]
	}
	return s
}

// unwrap removes the brackets around an IPv6 literal, so that "[::1]" and "::1"
// are one spelling by the time anything compares them.
func unwrap(s string) string {
	if len(s) > 1 && strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s[1 : len(s)-1]
	}
	return s
}
