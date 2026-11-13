package proxy

import (
	"net/netip"
	"strconv"
	"strings"
)

// Node.js reads NO_PROXY in two places that do not share code - its own http
// and https modules, and fetch, which is undici - and only when started with
// NODE_USE_ENV_PROXY=1 or --use-env-proxy. Both changed their reading inside
// release lines, so each rule here names the releases it speaks for
// (ruleTexts) and the change that ends it.

// jsPort is the port Node.js asks about: the URL's, which the WHATWG parser
// keeps without leading zeros and empties for the scheme's default, or the
// default when it is empty or zero - "options.port || defaultPort" in the http
// client, "Number.parseInt(port, 10) || DEFAULT_PORTS[protocol]" in undici.
func jsPort(t Target) int {
	if n, err := strconv.Atoi(t.Port); err == nil && n != 0 {
		return n
	}
	if lower(t.Scheme) == "https" {
		return 443
	}
	return 80
}

// bypassNoProxyNodeHTTP reads the list the way Node.js's http and https modules
// do.
//
// SOURCE: nodejs/node, lib/internal/http.js, ProxyConfig and shouldUseProxy, at
// tags v22.23.5, v24.22.3 and v26.13.1, and lib/_http_client.js and
// lib/_http_agent.js at v24.22.3, which hand it the host name without brackets
// and the port with the default filled in - read 2026-11-13. The list is cut on
// commas only and every entry is trimmed and lower-cased; "*" counts in any
// position, a bare name or "name:port" matches only exactly, "*.x" matches
// below x, and "a-b" is a range of IPv4 addresses.
// https://github.com/nodejs/node/blob/v24.22.3/lib/internal/http.js
//
// A LEADING DOT MATCHED THE END OF THE TEXT until "http: fix no_proxy
// leading-dot suffix matching" (nodejs/node d44a71a), which the changelogs put
// in 24.16.0 and 26.1.0: before it ".example.com" also sent badexample.com
// direct, and "." sent everything. dotBoundary is the code after it.
func bypassNoProxyNodeHTTP(list string, t Target, dotBoundary bool) Decision {
	if list == "" {
		return throughProxy()
	}
	host := lower(unwrap(t.Host))
	hostWithPort := host + ":" + strconv.Itoa(jsPort(t))
	for _, piece := range strings.Split(list, ",") {
		entry := strings.TrimSpace(piece)
		if nodeHTTPMatches(lower(entry), host, hostWithPort, dotBoundary) {
			return byEntry(entry)
		}
	}
	return throughProxy()
}

// nodeHTTPMatches is one turn of the loop in shouldUseProxy. An entry that
// fails one test goes on to the next, as it does there.
func nodeHTTPMatches(entry, host, hostWithPort string, dotBoundary bool) bool {
	if entry == "*" || entry == host || entry == hostWithPort {
		return true
	}
	if strings.HasPrefix(entry, ".") && nodeDotMatches(entry[1:], host, dotBoundary) {
		return true
	}
	if strings.HasPrefix(entry, "*.") && strings.HasSuffix(host, entry[1:]) {
		return true
	}
	return strings.Contains(entry, "-") && nodeRangeContains(entry, host)
}

func nodeDotMatches(suffix, host string, dotBoundary bool) bool {
	if !dotBoundary {
		return strings.HasSuffix(host, suffix)
	}
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// nodeRangeContains is the "start-end" branch: both ends and the host have to
// be IPv4 addresses as Node's isIPv4 reads them - four decimal numbers without
// leading zeros - and the host between the ends, both included. Anything after
// a second hyphen is not read.
func nodeRangeContains(entry, host string) bool {
	parts := strings.Split(entry, "-")
	start, startOK := nodeIPv4(strings.TrimSpace(parts[0]))
	end, endOK := nodeIPv4(strings.TrimSpace(parts[1]))
	addr, hostOK := nodeIPv4(host)
	return startOK && endOK && hostOK && start.Compare(addr) <= 0 && addr.Compare(end) <= 0
}

func nodeIPv4(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	return addr, err == nil && addr.Is4()
}

// undiciFeatures are the changes to undici's reading, each with the release
// that brought it.
//
// SOURCE: nodejs/undici, lib/dispatcher/env-http-proxy-agent.js - the file at
// the undici Node.js 22.23.5, 24.22.3 and 26.13.1 carry, and the four commits
// that changed its reading, located in undici's tags with the GitHub compare
// view and in Node.js's changelogs by "deps: update undici to", read
// 2026-11-13:
//
//	apex        4658cdf "strip leading dot and asterisk" - undici 7.22.0 and
//	            8.0, Node.js 24.14.1 and 26.0.0. Never in undici 6, so never
//	            in Node.js 22.
//	bareIPv6    dfe00a9 "match bare IPv6 addresses" - undici 8.10.0, Node.js
//	            26.8.0.
//	trailingDot 5033aa1 "ignore trailing dots" - undici 8.10.2, Node.js 26.8.2.
//	wildcard    0712f7d "NO_PROXY wildcard semantics" - undici 8.11, Node.js
//	            26.11.0.
//
// https://github.com/nodejs/undici/blob/main/lib/dispatcher/env-http-proxy-agent.js
type undiciFeatures struct {
	apex, bareIPv6, trailingDot, wildcard bool
}

func undiciReading(f undiciFeatures) reading {
	return asWritten(func(list string, t Target) Decision { return bypassNoProxyUndici(list, t, f) })
}

// undiciEntry is one entry as #parseNoProxy keeps it.
type undiciEntry struct {
	raw      string
	hostname string
	port     int // 0 is any port, as "entry.port &&" reads it
	wildcard bool
}

// bypassNoProxyUndici is #getProxyAgentForUrl and #shouldProxy.
//
// THE LIST IS CUT ON COMMAS AND ON EVERY BLANK, so "a.test b.test" is two
// entries here and one in curl. Before the wildcard change "*" counts only as
// the whole value - except in the first reading, where a lone "*" entry is a
// suffix of every name - and after it in any position.
func bypassNoProxyUndici(list string, t Target, f undiciFeatures) Decision {
	var entries []undiciEntry
	for _, raw := range strings.FieldsFunc(list, isUndiciSeparator) {
		entries = append(entries, undiciParse(raw, f))
	}
	if len(entries) == 0 {
		return throughProxy()
	}
	if !f.wildcard && list == "*" {
		return byWholeValue()
	}
	host, port := undiciHost(t, f), jsPort(t)
	for _, e := range entries {
		if undiciMatches(e, host, port, f) {
			return byEntry(e.raw)
		}
	}
	return throughProxy()
}

// isUndiciSeparator is the class /[,\s]/ restricted to ASCII, which is all
// Decide lets through to this reading.
func isUndiciSeparator(r rune) bool { return r == ',' || strings.ContainsRune(" \t\n\v\f\r", r) }

// undiciHost is url.host without its port: lower case, an IPv6 address in
// brackets until bareIPv6 takes them off, a trailing dot until trailingDot
// does.
func undiciHost(t Target, f undiciFeatures) string {
	host := lower(unwrap(t.Host))
	if strings.Contains(host, ":") && !f.bareIPv6 {
		host = "[" + host + "]"
	}
	if f.trailingDot && len(host) > 1 && strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}
	return host
}

// undiciParse is #parseNoProxy for one entry.
func undiciParse(raw string, f undiciFeatures) undiciEntry {
	hostname, port := undiciSplitPort(raw, f.bareIPv6)
	// /^\*?\./ - one "*." or else one "." comes off the front, never both.
	if f.apex && strings.HasPrefix(hostname, "*.") {
		hostname = hostname[2:]
	} else if f.apex && strings.HasPrefix(hostname, ".") {
		hostname = hostname[1:]
	}
	if f.trailingDot && len(hostname) > 1 && strings.HasSuffix(hostname, ".") {
		hostname = hostname[:len(hostname)-1]
	}
	return undiciEntry{raw: raw, hostname: lower(hostname), port: port,
		wildcard: f.wildcard && strings.HasPrefix(raw, "*")}
}

// undiciSplitPort takes "name:port" apart. Before bareIPv6 it is
// /^(.+):(\d+)$/, which reads the last group of "::1" as a port; from it, a
// bracketed address keeps its port, the brackets come off, and only a single
// colon makes a port.
func undiciSplitPort(raw string, bareIPv6 bool) (string, int) {
	if bareIPv6 {
		if host, port, ok := cutPort(raw); ok && len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
			return host[1 : len(host)-1], port
		}
		if len(raw) > 2 && raw[0] == '[' && raw[len(raw)-1] == ']' {
			raw = raw[1 : len(raw)-1]
		}
		if strings.Count(raw, ":") != 1 {
			return raw, 0
		}
	}
	if host, port, ok := cutPort(raw); ok {
		return host, port
	}
	return raw, 0
}

// cutPort is /^(.+):(\d+)$/: something, the last colon, and digits to the end.
// A port too large for an int is still a port, one no request ever has.
func cutPort(raw string) (string, int, bool) {
	i := strings.LastIndexByte(raw, ':')
	if i < 1 || !isDigits(raw[i+1:]) {
		return "", 0, false
	}
	port, err := strconv.Atoi(raw[i+1:])
	if err != nil {
		port = -1
	}
	return raw[:i], port, true
}

// undiciMatches is one turn of the loop in #shouldProxy.
func undiciMatches(e undiciEntry, host string, port int, f undiciFeatures) bool {
	if f.wildcard && e.hostname == "*" {
		return e.port == 0 || e.port == port
	}
	if e.port != 0 && e.port != port {
		return false
	}
	if !f.apex {
		// The first reading: a name is exact, and anything starting with "."
		// or "*" is the end of the text once one "*" is off.
		if !strings.HasPrefix(e.hostname, ".") && !strings.HasPrefix(e.hostname, "*") {
			return host == e.hostname
		}
		return strings.HasSuffix(host, strings.TrimPrefix(e.hostname, "*"))
	}
	if !e.wildcard && host == e.hostname {
		return true
	}
	return strings.HasSuffix(host, "."+e.hostname)
}
