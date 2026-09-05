package proxy

import (
	"fmt"
	"net/netip"
	"strings"
)

// Bypasses reports whether the target is excused from the proxy by list, read
// under one runtime family's rule.
//
// THE SAME LIST AND THE SAME HOST GIVE DIFFERENT ANSWERS UNDER DIFFERENT RULES,
// and that is the point of the function taking the rule rather than guessing it.
// A report that picked one reading would be right about one runtime on the
// machine and quietly wrong about the others.
func Bypasses(r Rule, list string, t Target) (bool, error) {
	n := t.normalise()
	switch r {
	case RuleNoProxy:
		if n.Host == "" {
			return false, ErrNoTarget
		}
		return bypassNoProxy(list, n), nil
	case RuleWinINET:
		if n.Host == "" {
			return false, ErrNoTarget
		}
		return bypassWinINET(list, n), nil
	case RuleWinHTTP:
		if n.Host == "" {
			return false, ErrNoTarget
		}
		return bypassWinHTTP(list, n), nil
	case RuleNonProxyHosts:
		if n.Host == "" {
			return false, ErrNoTarget
		}
		return bypassNonProxyHosts(list, n), nil
	case RuleExceptionsList:
		if n.Host == "" {
			return false, ErrNoTarget
		}
		return bypassExceptionsList(list, n), nil
	default:
		// A FIFTH RULE ARRIVES HERE RATHER THAN INHERITING THE LAST BRANCH.
		// OBS95 was a classification that sorted every input into three cases
		// and let the fourth fall through every check without one - measured,
		// and invisible because the fourth case did not exist yet. A default
		// that silently picks a reading would put an unchecked claim about
		// somebody's runtime into the report.
		return false, fmt.Errorf("%w: %q", ErrUnknownRule, string(r))
	}
}

// bypassNoProxy reads the list the way curl documents NO_PROXY.
//
// SOURCE: curl, docs/cmdline-opts/noproxy.md, read 2026-09-05 -
// "Comma-separated list of hosts for which not to use a proxy"; "Each name in
// this list is matched as either a domain which contains the hostname, or the
// hostname itself"; "For example, local.com would match local.com, local.com:80,
// and www.local.com, but not www.notlocal.com"; and CIDR notation "added in
// 7.86.0" where "an appended slash and number specifies the number of network
// bits out of the address to use in the comparison".
// https://raw.githubusercontent.com/curl/curl/master/docs/cmdline-opts/noproxy.md
//
// A LEADING DOT CHANGES NOTHING HERE AND THAT IS THE SOURCE, NOT A SHORTCUT.
// Everything curl says "if a name in the exclusion list starts with a dot, then
// the name matches that entire domain", which is the same match the sentence
// above already gives every entry. The dot is stripped so that ".local.com" and
// "local.com" cannot answer differently.
// https://everything.curl.dev/usingcurl/proxies/env.html
//
// THE LONE ASTERISK IS THE WHOLE VALUE, not one entry among several. The source
// says "you can set NO_PROXY to be a single asterisk" and says nothing about a
// star sitting in a list beside real names, so this reads the documented case
// and leaves the undocumented one to match nothing.
func bypassNoProxy(list string, t Target) bool {
	if strings.TrimSpace(list) == "*" {
		return true
	}
	for _, entry := range splitList(list, ",") {
		if prefix, ok := asPrefix(entry); ok {
			if addr, ok := asAddr(t.Host); ok && prefix.Contains(addr) {
				return true
			}
			continue
		}
		name := lower(trimTrailingDot(unwrap(strings.TrimPrefix(entry, "."))))
		if name == "" {
			continue
		}
		if t.Host == name || strings.HasSuffix(t.Host, "."+name) {
			return true
		}
	}
	return false
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
// Under RuleNoProxy the identical entry excuses both, because curl documents the
// opposite. Two runtimes, one string, two answers, and neither is misconfigured.
//
// AN EMPTY SCHEME LOSES TO A SCHEME-QUALIFIED ENTRY, deliberately. A caller that
// does not know the scheme cannot be told an entry applies, because the vendor
// says it applies only to that protocol - so the honest answer is "not excused",
// which sends the run through the proxy rather than claiming it will not.
func bypassWinINET(list string, t Target) bool {
	for _, entry := range splitList(list, ";") {
		if isLocalMacro(entry) {
			if !strings.Contains(t.Host, ".") {
				return true
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
			return true
		}
	}
	return false
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
func bypassWinHTTP(list string, t Target) bool {
	for _, entry := range splitList(list, "; \t\r\n") {
		if isLocalMacro(entry) {
			if !strings.Contains(t.Host, ".") {
				return true
			}
			continue
		}
		pattern := lower(trimTrailingDot(unwrap(entry)))
		if rest := strings.TrimLeft(pattern, "*"); len(rest) < len(pattern) {
			// A left-most wildcard, which is the only kind this stack honours.
			if strings.HasSuffix(t.Host, rest) {
				return true
			}
			continue
		}
		if t.Host == pattern {
			return true
		}
	}
	return false
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
func bypassNonProxyHosts(list string, t Target) bool {
	for _, entry := range splitList(list, "|") {
		if matchesEntry(t.Host, entry) {
			return true
		}
	}
	return false
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
// THE ABBREVIATED FORM IS WHY THIS CANNOT BORROW RuleNoProxy, and the difference
// is not cosmetic. curl documents CIDR as "an appended slash and number of bits
// to an IP ADDRESS", and netip.ParsePrefix refuses "169.254/16" outright - so
// reading the macOS default under curl's rule would turn the link-local entry
// into a host name nobody has, and silently drop a bypass that is really
// happening on every Mac.
func bypassExceptionsList(list string, t Target) bool {
	for _, entry := range splitList(list, "\n\r") {
		if prefix, ok := asAbbreviatedPrefix(entry); ok {
			if addr, ok := asAddr(t.Host); ok && prefix.Contains(addr) {
				return true
			}
			continue
		}
		if matchesEntry(t.Host, entry) {
			return true
		}
	}
	return false
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

// asPrefix reads an entry as a CIDR block, or says it is not one.
func asPrefix(entry string) (netip.Prefix, bool) {
	if !strings.Contains(entry, "/") {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
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
