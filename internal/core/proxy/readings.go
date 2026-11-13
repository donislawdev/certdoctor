package proxy

import (
	"net/netip"
	"strconv"
	"strings"
)

// This file holds the readings of NO_PROXY added for the noproxy tool (ADR147):
// Go, Python's urllib, requests, Node.js's http module and fetch in Node.js,
// and the network entries .NET 11 reads. Each one is the program's own code,
// read at the source named beside it, and spelled out here line for line where
// the program's line decides an answer - including where the program's answer
// looks like a mistake, because the question this package answers is what the
// program DOES.
//
// EVERY ONE OF THEM READS THE HOST AS GIVEN - Decide does not normalise it for
// them - and the port as the URL named it, empty when it did not.

func local() Decision { return Decision{Direct: true, Basis: BasisLocal} }

// portOf is the port a request goes to: the one the URL named, or the default
// for its scheme. These programs only send http and https through an HTTP
// proxy, so those are the two defaults.
func portOf(t Target) string {
	if t.Port != "" {
		return t.Port
	}
	switch lower(t.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// bypassNoProxyGo reads the list the way Go's net/http does.
//
// SOURCE: golang.org/x/net/http/httpproxy, proxy.go, as Go 1.27.4 carries it
// in src/vendor - useProxy, config.init and the four matchers - read
// 2026-11-13. The matching is byte for byte the module's main branch of the
// same day; only the order of the two spellings of the variable differs, and
// this function is handed the value.
// https://cs.opensource.google/go/x/net/+/master:http/httpproxy/proxy.go
//
// LOCALHOST AND A LOOPBACK ADDRESS NEVER GO TO A PROXY, whatever the list says,
// and the name is compared as the URL spelled it: "LOCALHOST" is not that name,
// because useProxy compares before anything folds its case.
//
// "*" IN ANY POSITION sends everything direct - init stops reading at it.
//
// AN ENTRY WITH A LEADING DOT MATCHES SUBDOMAINS ONLY, ".example.com" never
// reaching example.com, and "*." reads as a leading dot. A bare name matches
// itself and its subdomains. An entry may name a port, an address, or a
// network, and an address is held against addresses only.
func bypassNoProxyGo(list string, t Target) Decision {
	host := unwrap(t.Host)
	if host == "localhost" {
		return local()
	}
	addr, err := netip.ParseAddr(host)
	isAddr := err == nil
	if isAddr && addr.Unmap().IsLoopback() {
		return local()
	}
	for _, piece := range strings.Split(list, ",") {
		if entry := strings.TrimSpace(piece); lower(entry) == "*" {
			return byEntry(entry)
		}
	}
	host, port := lower(strings.TrimSpace(host)), portOf(t)
	for _, piece := range strings.Split(list, ",") {
		entry := strings.TrimSpace(piece)
		if goEntryMatches(lower(entry), host, port, addr, isAddr) {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// goEntryMatches is one entry of config.init and the matcher it becomes.
//
// Go asks the address entries before the name entries, and an address host can
// only meet an address entry while a name can only meet a name entry - so one
// pass in list order finds the entry Go would have found first.
func goEntryMatches(p, host, port string, addr netip.Addr, isAddr bool) bool {
	if p == "" {
		return false
	}
	if network, ok := goCIDR(p); ok {
		return isAddr && goNetworkContains(network, addr)
	}
	phost, pport, ok := goSplitHostPort(p)
	if !ok {
		phost, pport = p, ""
	}
	if phost == "" {
		// init calls this a malformed entry and ignores it. A host written
		// in brackets has lost them already, inside goSplitHostPort.
		return false
	}
	if ip, err := netip.ParseAddr(phost); err == nil && ip.Zone() == "" {
		return isAddr && ip.Unmap() == addr.WithZone("").Unmap() && (pport == "" || pport == port)
	}
	if isAddr {
		return false
	}
	return goDomainMatches(phost, pport, host, port)
}

// goDomainMatches is domainMatch: "*." becomes ".", a name without a leading
// dot also matches itself, and the port, when the entry names one, has to be
// the request's.
func goDomainMatches(phost, pport, host, port string) bool {
	if strings.HasPrefix(phost, "*.") {
		phost = phost[1:]
	}
	matchHost := phost[0] != '.'
	if matchHost {
		phost = "." + phost
	}
	if !strings.HasSuffix(host, phost) && !(matchHost && host == phost[1:]) {
		return false
	}
	return pport == "" || pport == port
}

// goCIDR is net.ParseCIDR: an address without a zone, a slash and decimal bits
// no wider than the address, leading zeros allowed.
//
// SOURCE: net/ip.go and net/parse.go (ParseCIDR, dtoi) in Go 1.27.4, read
// 2026-11-13. The core may not import net, so the rule is written out here.
func goCIDR(p string) (netip.Prefix, bool) {
	text, bitsText, found := strings.Cut(p, "/")
	if !found || !isDigits(bitsText) {
		return netip.Prefix{}, false
	}
	addr, err := netip.ParseAddr(text)
	bits, bitsErr := strconv.Atoi(bitsText)
	if err != nil || addr.Zone() != "" || bitsErr != nil || bits > addr.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, bits), true
}

// goNetworkContains is net.IPNet.Contains on what ParseCIDR built.
//
// GO FORGETS THAT AN IPv4-MAPPED NETWORK WAS WRITTEN AS IPv6. ParseCIDR keeps
// "::ffff:10.0.0.0/104" as sixteen bytes, and Contains then reads it as the
// IPv4 network 10.0.0.0/8 - the last four bytes of the address and of the
// mask. A host in its IPv4-mapped spelling is read as IPv4 the same way.
func goNetworkContains(network netip.Prefix, addr netip.Addr) bool {
	if network.Addr().Is4In6() {
		network = netip.PrefixFrom(network.Addr().Unmap(), max(network.Bits()-96, 0))
	}
	return network.Masked().Contains(addr.WithZone("").Unmap())
}

// goSplitHostPort is net.SplitHostPort, line for line.
//
// SOURCE: net/ipsock.go in Go 1.27.4, read 2026-11-13.
func goSplitHostPort(p string) (host, port string, ok bool) {
	i := strings.LastIndexByte(p, ':')
	if i < 0 {
		return "", "", false
	}
	j, k := 0, 0
	if p[0] == '[' {
		end := strings.IndexByte(p, ']')
		if end < 0 || end+1 != i {
			// No ']', nothing after it, or something other than the last
			// colon after it - the three errors SplitHostPort tells apart.
			return "", "", false
		}
		host, j, k = p[1:end], 1, end+1
	} else {
		host = p[:i]
		if strings.IndexByte(host, ':') >= 0 {
			return "", "", false
		}
	}
	if strings.IndexByte(p[j:], '[') >= 0 || strings.IndexByte(p[k:], ']') >= 0 {
		return "", "", false
	}
	return host, p[i+1:], true
}

// bypassNoProxyPython reads the list the way Python's urllib does.
//
// SOURCE: CPython, Lib/urllib/request.py, proxy_bypass_environment and
// _splitport, and ProxyHandler.proxy_open, which hands it req.host - the host
// as the URL wrote it, brackets and an explicit port included. Read 2026-11-13
// on main; the function is the same from 3.10 (ADR147).
// https://github.com/python/cpython/blob/main/Lib/urllib/request.py
func bypassNoProxyPython(list string, t Target) Decision {
	host := unwrap(t.Host)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if t.Port != "" {
		host += ":" + t.Port
	}
	return pythonBypass(list, host)
}

// pythonBypass is proxy_bypass_environment for one host string.
//
// NAMES ARE TEXT HERE, AN ADDRESS INCLUDED. Every entry loses ALL its leading
// dots and is compared with the host, with and without the port, as a whole or
// as the text after a dot - so "0.0.1" sends 10.0.0.1 direct, and an entry
// with a port matches only a URL that named that port.
//
// "*" counts only as the whole value, before any trimming.
func pythonBypass(list, host string) Decision {
	if list == "*" {
		return byWholeValue()
	}
	host = lower(host)
	hostOnly := pythonSplitPort(host)
	for _, piece := range strings.Split(list, ",") {
		entry := strings.TrimSpace(piece)
		if entry == "" {
			continue
		}
		name := lower(strings.TrimLeft(entry, "."))
		if hostOnly == name || host == name ||
			strings.HasSuffix(hostOnly, "."+name) || strings.HasSuffix(host, "."+name) {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// pythonSplitPort is _splitport: the regular expression "(.*):([0-9]*)" over
// the whole host, and a port only when the digits after the last colon are not
// empty. Only the last colon can work, because any earlier one has that colon
// after it.
func pythonSplitPort(host string) string {
	i := strings.LastIndexByte(host, ':')
	if i < 0 || !isDigits(host[i+1:]) {
		return host
	}
	return host[:i]
}

// bypassNoProxyRequests reads the list the way requests does, which is its own
// loop first and urllib's after it.
//
// SOURCE: requests, src/requests/utils.py, should_bypass_proxies, at tags
// v2.33.1 and v2.34.0, read 2026-11-13. The loop compares the end of the name
// as plain text up to 2.33 - ".example.com" misses example.com and "ample.com"
// catches it - and from 2.34 takes the leading dots off and matches the domain
// or the text after a dot. An address host is held only against addresses and
// IPv4 networks. Whatever the loop leaves, urllib's proxy_bypass decides, given
// the host name without the port.
// https://github.com/psf/requests/blob/v2.34.0/src/requests/utils.py
//
// pip carries requests inside itself: pip 26.1 carries 2.33.1 and pip 26.2
// carries 2.34.2, by pip's release notes and src/pip/_vendor/vendor.txt.
func bypassNoProxyRequests(list string, t Target, dotBoundary bool) Decision {
	hostname := lower(unwrap(t.Host))
	if d := requestsLoop(list, hostname, t.Port, dotBoundary); d.Direct {
		return d
	}
	return pythonBypass(list, hostname)
}

// requestsLoop is the part of should_bypass_proxies before urllib.
//
// Only the space character is removed, by no_proxy.replace(" ", ""), so a tab
// stays inside an entry.
func requestsLoop(list, hostname, port string, dotBoundary bool) Decision {
	var entries []string
	for _, entry := range strings.Split(strings.ReplaceAll(list, " ", ""), ",") {
		if entry != "" {
			entries = append(entries, entry)
		}
	}
	if addr, ok := looseIPv4(hostname); ok {
		for _, entry := range entries {
			if requestsAddressMatches(entry, hostname, addr) {
				return byEntry(entry)
			}
		}
		return throughProxy()
	}
	withPort := hostname
	if port != "" && strings.TrimLeft(port, "0") != "" {
		withPort += ":" + strings.TrimLeft(port, "0")
	}
	for _, entry := range entries {
		if requestsNameMatches(entry, hostname, withPort, dotBoundary) {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// requestsAddressMatches is the IPv4 branch: a network that is_valid_cidr
// accepts and address_in_network contains, or the very same text.
func requestsAddressMatches(entry, hostname string, addr netip.Addr) bool {
	if network, ok := requestsNetwork(entry); ok {
		return network.Contains(addr)
	}
	return entry == hostname
}

// requestsNetwork is is_valid_cidr: one slash, Python's int() of the bits
// between 1 and 32, and an address socket.inet_aton accepts.
func requestsNetwork(entry string) (netip.Prefix, bool) {
	if strings.Count(entry, "/") != 1 {
		return netip.Prefix{}, false
	}
	text, bitsText, _ := strings.Cut(entry, "/")
	bits, ok := pythonInt(bitsText)
	addr, isAddr := looseIPv4(text)
	if !ok || bits < 1 || bits > 32 || !isAddr {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

// requestsNameMatches is the name branch of the loop, in its two versions.
func requestsNameMatches(entry, hostname, withPort string, dotBoundary bool) bool {
	if !dotBoundary {
		return strings.HasSuffix(hostname, entry) || strings.HasSuffix(withPort, entry)
	}
	name := strings.TrimLeft(entry, ".")
	return hostname == name || withPort == name ||
		strings.HasSuffix(hostname, "."+name) || strings.HasSuffix(withPort, "."+name)
}

// pythonInt is int() of a str holding a whole number: blanks around it, one
// sign, and single underscores between digits.
func pythonInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	digits := strings.TrimLeft(s, "+-")
	if len(s)-len(digits) > 1 || digits == "" || digits[0] == '_' || digits[len(digits)-1] == '_' ||
		strings.Contains(digits, "__") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.ReplaceAll(digits, "_", ""))
	if err != nil {
		return 0, false
	}
	if s[0] == '-' {
		n = -n
	}
	return n, true
}

// looseIPv4 reads an IPv4 address the way the BSD inet_aton does, which is
// what Python's socket.inet_aton calls and what .NET's IPAddress.TryParse
// follows: one to four parts, each decimal, octal after a leading zero or
// hexadecimal after "0x", the last part filling the bytes that are left - so
// "10" is 0.0.0.10 and "10.1" is 10.0.0.1.
//
// THE QUIRKS OF ONE C LIBRARY ARE LEFT OUT, NAMED HERE: glibc accepts blanks
// and anything after them at the end, and a "0x" with no digits in a part that
// is not the last. Neither is accepted here, so such an entry is not an
// address under this reading.
func looseIPv4(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var value uint64
	for i, part := range parts {
		n, ok := inetPart(part)
		width := 8
		if i == len(parts)-1 {
			width = 8 * (5 - len(parts))
		}
		if !ok || n >= 1<<width {
			return netip.Addr{}, false
		}
		value = value<<width | n
	}
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}), true
}

// dotNetNetwork is IPNetwork.TryParse as .NET 11 calls it on an entry: an
// address IPAddress.TryParse accepts, the LAST slash, and decimal digits only
// (NumberStyles.None) no wider than the address. Bits set after the prefix are
// cleared, not refused - "10.0.0.1/8" is 10.0.0.0/8.
//
// SOURCE: dotnet/runtime, System.Net.Primitives, IPNetwork.cs and IPAddress.cs
// at tag v11.0.0, read 2026-11-13.
// https://github.com/dotnet/runtime/blob/v11.0.0/src/libraries/System.Net.Primitives/src/System/Net/IPNetwork.cs
func dotNetNetwork(entry string) (netip.Prefix, bool) {
	i := strings.LastIndexByte(entry, '/')
	if i < 0 || !isDigits(entry[i+1:]) {
		return netip.Prefix{}, false
	}
	addr, ok := dotNetAddress(entry[:i])
	bits, err := strconv.Atoi(entry[i+1:])
	if !ok || err != nil || bits > addr.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

// dotNetAddress is IPAddress.TryParse for the two shapes it meets here: an IPv6
// address, in brackets or not and with a port after the brackets, its scope
// set aside; or an IPv4 address in any form inet_aton reads.
func dotNetAddress(s string) (netip.Addr, bool) {
	if !strings.Contains(s, ":") {
		return looseIPv4(s)
	}
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 || (end+1 < len(s) && !(s[end+1] == ':' && isDigits(s[end+2:]))) {
			return netip.Addr{}, false
		}
		s = s[1:end]
	}
	addr, err := netip.ParseAddr(s)
	return addr.WithZone(""), err == nil && addr.Is6()
}

// dotNetNetworkDecision asks the networks after every name failed, and only for
// a host that is an address - IsMatchInBypassList in .NET 11.
//
// IPNetwork.Contains holds an IPv4 network against an IPv4-mapped IPv6
// address by the IPv4 part of it, which .NET 11 does and Go's netip does not.
func dotNetNetworkDecision(nets []string, host string) Decision {
	addr, ok := dotNetAddress(host)
	if !ok {
		return throughProxy()
	}
	for _, entry := range nets {
		network, _ := dotNetNetwork(entry)
		candidate := addr
		if network.Addr().Is4() && candidate.Is4In6() {
			candidate = candidate.Unmap()
		}
		if network.Contains(candidate) {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// inetPart is one part of an inet_aton address.
func inetPart(part string) (uint64, bool) {
	base, digits := 10, part
	switch {
	case len(part) > 2 && (strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X")):
		base, digits = 16, part[2:]
	case len(part) > 1 && part[0] == '0':
		base, digits = 8, part[1:]
	}
	if digits == "" || strings.ContainsAny(digits, "+-_") {
		return 0, false
	}
	n, err := strconv.ParseUint(digits, base, 64)
	return n, err == nil
}
