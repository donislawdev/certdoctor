package proxy

import "testing"

// The parsers below are other programs' parsers written out again, so each
// table holds what the program's own code gives for the input - read at the
// source named at the function under test.

func TestGoReadsAnEntryTheWayNetHTTPDoes(t *testing.T) {
	cases := []struct {
		list   string
		target Target
		direct bool
	}{
		{"example.com:80", Target{Scheme: "http", Host: "example.com"}, true},
		{"example.com:80", https("example.com"), false},
		{"example.com:21", Target{Scheme: "ftp", Host: "example.com"}, false},
		{"a.example,,example.com", https("example.com"), true},
		{"10.0.0.0/8", https("example.com"), false},
		{":443", https("example.com"), false},
		{"fe80::1%eth0", https("fe80::1"), false},
		{"10.0.0.1:443", https("10.0.0.1"), true},
		{"10.0.0.1:80", https("10.0.0.1"), false},
		{"[2001:db8::2]:443", https("2001:db8::2"), true},
		{"10.0.0.1", https("::ffff:10.0.0.1"), true},
		{"10.0.0.0/x", https("10.0.0.1"), false},
		{"10.0.0.0/33", https("10.0.0.1"), false},
		{"10.0.0.0/99999999999999999999", https("10.0.0.1"), false},
		{"fe80::%eth0/64", https("fe80::1"), false},
		{"10.0.0.0/08", https("10.0.0.1"), true},
		{"::ffff:10.0.0.0/104", https("10.0.0.1"), true},
		{"::ffff:0.0.0.0/80", https("192.0.2.1"), true},
		{"::ffff:10.0.0.0/104", https("2001:db8::1"), false},
		{"::/0", https("::ffff:192.0.2.1"), false},
		{"*.", https("example.com."), true},
	}
	for _, c := range cases {
		if got := ask(t, RuleNoProxyGo, c.list, c.target); got != c.direct {
			t.Errorf("Go: list %q for %+v went direct %v, want %v", c.list, c.target, got, c.direct)
		}
	}
}

func TestGoSplitsHostAndPortLikeSplitHostPort(t *testing.T) {
	cases := []struct {
		in, host, port string
		ok             bool
	}{
		{"example.com:80", "example.com", "80", true},
		{"example.com:", "example.com", "", true},
		{"[::1]:443", "::1", "443", true},
		{"example.com", "", "", false},
		{"[::1", "", "", false},
		{"[::1]", "", "", false},
		{"[::1]x:80", "", "", false},
		{"a:b:80", "", "", false},
		{"a[b:80", "", "", false},
		{"a]b:80", "", "", false},
		{"[a[]:80", "", "", false},
		{"[a]:8]0", "", "", false},
	}
	for _, c := range cases {
		host, port, ok := goSplitHostPort(c.in)
		if host != c.host || port != c.port || ok != c.ok {
			t.Errorf("goSplitHostPort(%q) = %q, %q, %v; want %q, %q, %v", c.in, host, port, ok, c.host, c.port, c.ok)
		}
	}
}

func TestPythonIntReadsWhatIntOfAStringReads(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"8", 8, true}, {"\t8", 8, true}, {"+8", 8, true}, {"-8", -8, true}, {"1_6", 16, true},
		{"+-8", 0, false}, {"", 0, false}, {"-", 0, false}, {"_8", 0, false}, {"8_", 0, false},
		{"1__6", 0, false}, {"8x", 0, false}, {"99999999999999999999", 0, false},
	}
	for _, c := range cases {
		if got, ok := pythonInt(c.in); got != c.want || ok != c.ok {
			t.Errorf("pythonInt(%q) = %d, %v; want %d, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestLooseIPv4ReadsWhatInetAtonReads(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10", "0.0.0.10"}, {"10.1", "10.0.0.1"}, {"10.1.2", "10.1.0.2"}, {"10.1.2.3", "10.1.2.3"},
		{"0x0a.0.0.1", "10.0.0.1"}, {"0X0A.0.0.1", "10.0.0.1"}, {"012.0.0.1", "10.0.0.1"},
		{"1.16777215", "1.255.255.255"}, {"4294967295", "255.255.255.255"}, {"0.0.0.0", "0.0.0.0"},
		{"1.2.3.4.5", ""}, {"256.0.0.1", ""}, {"1.16777216", ""}, {"4294967296", ""}, {"08.0.0.1", ""},
		{"0x", ""}, {"", ""}, {"1..2", ""}, {"+1.0.0.1", ""}, {"0x1g.0.0.1", ""}, {"a.b.c.d", ""},
	}
	for _, c := range cases {
		addr, ok := looseIPv4(c.in)
		if got := map[bool]string{true: addr.String(), false: ""}[ok]; got != c.want {
			t.Errorf("looseIPv4(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRequestsReadsANetworkTheWayIsValidCIDRDoes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.0.0/8", "10.0.0.0/8"}, {"10.1.2.3/16", "10.1.0.0/16"}, {"10/8", "0.0.0.0/8"},
		{"10.0.0.0/\t8", "10.0.0.0/8"}, {"10.0.0.0/8/9", ""}, {"10.0.0.0/x", ""}, {"10.0.0.0/0", ""},
		{"10.0.0.0/33", ""}, {"a.b/8", ""}, {"10.0.0.0", ""},
	}
	for _, c := range cases {
		network, ok := requestsNetwork(c.in)
		if got := map[bool]string{true: network.String(), false: ""}[ok]; got != c.want {
			t.Errorf("requestsNetwork(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		list, host string
		direct     bool
	}{
		{"10/8", "0.0.0.9", true}, {"192.168.0.0/16", "10.0.0.1", false}, {"10.0.0.1", "10.0.0.1", true},
	} {
		if got := ask(t, RuleNoProxyRequests, c.list, https(c.host)); got != c.direct {
			t.Errorf("requests: list %q for %s went direct %v, want %v", c.list, c.host, got, c.direct)
		}
	}
}

func TestRequestsComparesThePortTheURLWrote(t *testing.T) {
	for _, c := range []struct {
		list, port string
		direct     bool
	}{
		{"example.com:8443", "08443", true}, {"example.com:0", "0", false}, {"com:8443", "8443", true},
	} {
		target := Target{Scheme: "https", Host: "example.com", Port: c.port}
		if got := ask(t, RuleNoProxyRequests, c.list, target); got != c.direct {
			t.Errorf("requests: list %q for port %q went direct %v, want %v", c.list, c.port, got, c.direct)
		}
	}
}

// TestThreeEdgesOnlyOneProgramReads holds what the cross-program tables leave
// undecided: urllib takes every leading dot off, requests takes the spaces out
// of the middle of an entry before urllib sees it, and a Node.js range holds
// both of its ends.
func TestThreeEdgesOnlyOneProgramReads(t *testing.T) {
	cases := []struct {
		rule       Rule
		list, host string
		direct     bool
	}{
		{RuleNoProxyPython, "..example.com", "example.com", true},
		{RuleNoProxyPython, " *", "a.example", false},
		{RuleNoProxyRequestsDotBoundary, "a .example", "a.example", true},
		{RuleNoProxyPython, "a .example", "a.example", false},
		{RuleNoProxyNodeHTTP, "10.0.0.5-10.0.0.9", "10.0.0.5", true},
		{RuleNoProxyNodeHTTPDotBoundary, "10.0.0.5-10.0.0.9", "10.0.0.9", true},
		{RuleNoProxyNodeHTTP, "10.0.0.5-10.0.0.9", "10.0.0.10", false},
	}
	for _, c := range cases {
		if got := ask(t, c.rule, c.list, https(c.host)); got != c.direct {
			t.Errorf("%s: list %q for %s went direct %v, want %v", c.rule, c.list, c.host, got, c.direct)
		}
	}
}

func TestDotNet11ReadsANetworkTheWayIPNetworkDoes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.0.1/8", "10.0.0.0/8"}, {"10/8", "0.0.0.0/8"}, {"[::1]/128", "::1/128"}, {"::/0", "::/0"},
		{"[::1]:80/128", "::1/128"}, {"fe80::1%3/64", "fe80::/64"}, {"10.0.0.0", ""}, {"10.0.0.0/x", ""},
		{"10.0.0.0/", ""}, {"a/8", ""}, {"10.0.0.0/33", ""}, {"10.0.0.0/99999999999999999999", ""},
		{"[::1/128", ""}, {"[::1]x/128", ""}, {"[::1]:/128", ""}, {"1::2::3/64", ""},
	}
	for _, c := range cases {
		network, ok := dotNetNetwork(c.in)
		if got := map[bool]string{true: network.String(), false: ""}[ok]; got != c.want {
			t.Errorf("dotNetNetwork(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		rule       Rule
		list, host string
		want       Decision
	}{
		{RuleNoProxyDotNetNetworks, "10.0.0.0/8", "::ffff:10.0.0.1", byEntry("10.0.0.0/8")},
		{RuleNoProxyDotNetNetworks, "10.0.0.0/8,192.168.0.0/16", "192.168.1.1", byEntry("192.168.0.0/16")},
		{RuleNoProxyDotNetNetworks, "10.0.0.0/8", "172.16.0.1", throughProxy()},
		{RuleNoProxyDotNetNetworks, "10.0.0.0/8", "example.com", throughProxy()},
		{RuleNoProxyDotNetNetworks, "::/0", "10.0.0.1", throughProxy()},
		{RuleNoProxyDotNet, "10.0.0.0/8", "10.0.0.1", throughProxy()},
	} {
		if got, err := Decide(c.rule, c.list, https(c.host)); err != nil || got != c.want {
			t.Errorf("%s: list %q for %s = %+v, %v; want %+v", c.rule, c.list, c.host, got, err, c.want)
		}
	}
}

func TestUndiciCutsAnEntryTheWayParseNoProxyDoes(t *testing.T) {
	first, bare := undiciFeatures{}, undiciFeatures{apex: true, bareIPv6: true}
	all := undiciFeatures{apex: true, bareIPv6: true, trailingDot: true, wildcard: true}
	cases := []struct {
		raw  string
		f    undiciFeatures
		want undiciEntry
	}{
		{"::1", first, undiciEntry{raw: "::1", hostname: ":", port: 1}},
		{"Example.com:443", first, undiciEntry{raw: "Example.com:443", hostname: "example.com", port: 443}},
		{"example.com:http", first, undiciEntry{raw: "example.com:http", hostname: "example.com:http"}},
		{"a:99999999999999999999", first, undiciEntry{raw: "a:99999999999999999999", hostname: "a", port: -1}},
		{"[::1]:443", bare, undiciEntry{raw: "[::1]:443", hostname: "::1", port: 443}},
		{"[::1]", bare, undiciEntry{raw: "[::1]", hostname: "::1"}},
		{"::1", bare, undiciEntry{raw: "::1", hostname: "::1"}},
		{"example.com:443", bare, undiciEntry{raw: "example.com:443", hostname: "example.com", port: 443}},
		{"*..x", bare, undiciEntry{raw: "*..x", hostname: ".x"}},
		{"..x", bare, undiciEntry{raw: "..x", hostname: ".x"}},
		{"*x", all, undiciEntry{raw: "*x", hostname: "*x", wildcard: true}},
		{"*.x.", all, undiciEntry{raw: "*.x.", hostname: "x", wildcard: true}},
		{".", all, undiciEntry{raw: ".", hostname: ""}},
	}
	for _, c := range cases {
		if got := undiciParse(c.raw, c.f); got != c.want {
			t.Errorf("undiciParse(%q, %+v) = %+v, want %+v", c.raw, c.f, got, c.want)
		}
	}
}

func TestUndiciPortsAndTheWildcardEntry(t *testing.T) {
	cases := []struct {
		rule   Rule
		list   string
		target Target
		direct bool
	}{
		{RuleNoProxyNodeFetchWildcard, "*:80", Target{Scheme: "http", Host: "a.example"}, true},
		{RuleNoProxyNodeFetchWildcard, "*:80", https("a.example"), false},
		{RuleNoProxyNodeFetchWildcard, "a.example:80", https("a.example"), false},
		{RuleNoProxyNodeFetchWildcard, "a.example:0", https("a.example"), true},
		{RuleNoProxyNodeFetch, "a.example:443", Target{Scheme: "https", Host: "a.example", Port: "0"}, true},
		{RuleNoProxyNodeFetch, " , ", https("a.example"), false},
		{RuleNoProxyNodeFetch, "*a.example", https("a.example"), true},
		{RuleNoProxyNodeHTTP, "a-b", https("example.com"), false},
		{RuleNoProxyNodeHTTP, "10.0.0.1-x", https("10.0.0.1"), false},
		{RuleNoProxyNodeHTTP, "a.example:80", Target{Scheme: "http", Host: "A.example"}, true},
	}
	for _, c := range cases {
		if got := ask(t, c.rule, c.list, c.target); got != c.direct {
			t.Errorf("%s: list %q for %+v went direct %v, want %v", c.rule, c.list, c.target, got, c.direct)
		}
	}
	if _, ok := nodeIPv4("01.2.3.4"); ok {
		t.Error("Node's isIPv4 refuses a leading zero, and nodeIPv4 accepted one")
	}
	if _, ok := nodeIPv4("::1"); ok {
		t.Error("nodeIPv4 accepted an IPv6 address")
	}
}
