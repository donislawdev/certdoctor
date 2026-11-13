package proxy

import (
	"errors"
	"testing"
)

// Groups of readings, so that a row below names who goes direct in a line.
var (
	requestsBoth = []Rule{RuleNoProxyRequests, RuleNoProxyRequestsDotBoundary}
	nodeHTTPBoth = []Rule{RuleNoProxyNodeHTTP, RuleNoProxyNodeHTTPDotBoundary}
	dotNetBoth   = []Rule{RuleNoProxyDotNet, RuleNoProxyDotNetNetworks}
	fetchApex    = []Rule{RuleNoProxyNodeFetchApex, RuleNoProxyNodeFetchBareIPv6, RuleNoProxyNodeFetchTrailingDot,
		RuleNoProxyNodeFetchWildcard}
	fetchAll = append([]Rule{RuleNoProxyNodeFetch}, fetchApex...)
)

func readers(groups ...[]Rule) []Rule {
	var all []Rule
	for _, g := range groups {
		all = append(all, g...)
	}
	return all
}

func one(r ...Rule) []Rule { return r }

func https(name string) Target { return Target{Scheme: "https", Host: name} }

// throughEveryProgram asks every NO_PROXY reading about one list and one place,
// and wants exactly the readings in direct to go without the proxy.
//
// EVERY ROW NAMES ALL FOURTEEN, by naming who goes direct and leaving the rest
// to go through the proxy - so a reading added later and forgotten here fails
// every row it disagrees with instead of passing unseen.
func throughEveryProgram(t *testing.T, cases []noProxyCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := map[Rule]bool{}
			for _, r := range c.direct {
				want[r] = true
			}
			for _, r := range NoProxyRules {
				d, err := Decide(r, c.list, c.target)
				if err != nil {
					t.Fatalf("%s: Decide(%q, %+v) returned %v", r, c.list, c.target, err)
				}
				if d.Direct != want[r] {
					t.Errorf("%s: list %q for %+v goes direct %v, want %v (%s)", r, c.list, c.target, d.Direct,
						want[r], c.why)
				}
			}
		})
	}
}

type noProxyCase struct {
	name   string
	list   string
	target Target
	direct []Rule
	why    string
}

// TestOneNoProxyNameThroughEveryProgram is the noproxy tool's reason to exist,
// for names: one value, fourteen readings, and no row holds a mistake by
// anybody. Every answer is the program's code as read at the sources beside
// each reading.
func TestOneNoProxyNameThroughEveryProgram(t *testing.T) {
	throughEveryProgram(t, []noProxyCase{
		{name: "a bare name and a subdomain", list: "example.com", target: https("www.example.com"),
			direct: readers(one(RuleNoProxyCurl, RuleNoProxyGo, RuleNoProxyPython), requestsBoth, fetchApex),
			why:    ".NET, Node.js http and the first fetch match a bare name only exactly"},
		{name: "a leading dot and the domain", list: ".example.com", target: https("example.com"),
			direct: readers(one(RuleNoProxyCurl, RuleNoProxyPython), dotNetBoth, requestsBoth, nodeHTTPBoth, fetchApex),
			why:    "Go and the first fetch read a leading dot as subdomains only"},
		{name: "a leading dot and a longer name", list: ".example.com", target: https("badexample.com"),
			direct: one(RuleNoProxyNodeHTTP),
			why:    "Node.js http matched the end of the text until 24.16 and 26.1"},
		{name: "the end of a name without a dot", list: "ample.com", target: https("example.com"),
			direct: one(RuleNoProxyRequests),
			why:    "requests up to 2.33 compares the end of the text"},
		{name: "an asterisk and the domain", list: "*.example.com", target: https("example.com"),
			direct: one(RuleNoProxyNodeFetchApex, RuleNoProxyNodeFetchBareIPv6, RuleNoProxyNodeFetchTrailingDot),
			why:    "undici took \"*.\" off and matched the domain, until 8.11 made it subdomains only"},
		{name: "an asterisk and a subdomain", list: "*.example.com", target: https("www.example.com"),
			direct: readers(one(RuleNoProxyGo), nodeHTTPBoth, fetchAll),
			why:    "curl, .NET, Python and requests read \"*.example.com\" as a name nobody has"},
		{name: "an asterisk after a name", list: "a.example,*", target: https("other.example"),
			direct: readers(one(RuleNoProxyGo, RuleNoProxyNodeFetch, RuleNoProxyNodeFetchWildcard), nodeHTTPBoth),
			why:    "curl, Python and fetch from 24.14.1 to 26.10 read \"*\" only as the whole value"},
		{name: "the whole value is an asterisk", list: "*", target: https("other.example"),
			direct: readers(one(RuleNoProxyCurl, RuleNoProxyGo, RuleNoProxyPython), requestsBoth, nodeHTTPBoth, fetchAll),
			why:    ".NET has no wildcard at all"},
		{name: "a space instead of a comma", list: "a.example b.example", target: https("b.example"),
			direct: fetchAll,
			why:    "undici cuts on blanks, curl stops at the space, and the rest read one name holding a space"},
		{name: "a port the URL names", list: "example.com:8443",
			target: Target{Scheme: "https", Host: "example.com", Port: "8443"},
			direct: readers(one(RuleNoProxyGo, RuleNoProxyPython), requestsBoth, nodeHTTPBoth, fetchAll),
			why:    "curl and .NET do not read a port in an entry"},
		{name: "the default port the URL leaves out", list: "example.com:443", target: https("example.com"),
			direct: readers(one(RuleNoProxyGo), nodeHTTPBoth, fetchAll),
			why:    "Python and requests compare with the port only when the URL wrote one"},
		{name: "a trailing dot on the host", list: "example.com", target: https("example.com."),
			direct: readers(one(RuleNoProxyCurl), dotNetBoth, one(RuleNoProxyNodeFetchTrailingDot, RuleNoProxyNodeFetchWildcard)),
			why:    "curl drops it, undici from 8.10.2 does, and the rest keep it on the name"},
		{name: "a lone dot", list: ".", target: https("example.com"),
			direct: one(RuleNoProxyNodeHTTP),
			why:    "before 24.16 and 26.1, Node.js http took the empty end of the text after the dot"},
	})
}

// TestOneNoProxyAddressThroughEveryProgram is the same for addresses, where the
// programs part company over whether an address is text.
func TestOneNoProxyAddressThroughEveryProgram(t *testing.T) {
	throughEveryProgram(t, []noProxyCase{
		{name: "a network", list: "10.0.0.0/8", target: https("10.0.0.1"),
			direct: readers(one(RuleNoProxyCurl, RuleNoProxyDotNetNetworks, RuleNoProxyGo), requestsBoth),
			why:    ".NET up to 10, Python and Node.js read no networks"},
		{name: "the end of an address", list: "0.0.1", target: https("10.0.0.1"),
			direct: readers(one(RuleNoProxyPython), requestsBoth, fetchApex),
			why:    "Python and undici compare an address as text, curl and Go as an address (curl measured, OBS234)"},
		{name: "a range of addresses", list: "10.0.0.1-10.0.0.9", target: https("10.0.0.5"),
			direct: nodeHTTPBoth,
			why:    "only Node.js http reads a range"},
		{name: "an IPv6 address in brackets", list: "[::1]", target: https("::1"),
			direct: readers(dotNetBoth, one(RuleNoProxyGo, RuleNoProxyPython), fetchAll),
			why:    "curl reads no brackets (measured), Go never proxies a loopback address"},
		{name: "an IPv6 address without brackets", list: "::1", target: https("::1"),
			direct: readers(one(RuleNoProxyCurl, RuleNoProxyGo), requestsBoth, nodeHTTPBoth,
				one(RuleNoProxyNodeFetchBareIPv6, RuleNoProxyNodeFetchTrailingDot, RuleNoProxyNodeFetchWildcard)),
			why: ".NET compares the bracketed spelling (measured), and undici before 8.10 read \":1\" as a port"},
		{name: "localhost with nothing in the list", list: "", target: https("localhost"),
			direct: one(RuleNoProxyGo),
			why:    "Go never sends localhost to a proxy"},
	})
}

// TestDecideNamesTheEntryAndWhatItRestsOn holds the two fields a person reads
// beside the answer.
func TestDecideNamesTheEntryAndWhatItRestsOn(t *testing.T) {
	cases := []struct {
		rule   Rule
		list   string
		target Target
		want   Decision
	}{
		{RuleNoProxyCurl, "*", https("a.example"), Decision{Direct: true, Entry: "*", Basis: BasisWholeValue}},
		{RuleNoProxyNodeFetchTrailingDot, "*", https("a.example"), Decision{Direct: true, Entry: "*", Basis: BasisWholeValue}},
		{RuleNoProxyNodeFetchWildcard, "*", https("a.example"), Decision{Direct: true, Entry: "*", Basis: BasisEntry}},
		{RuleNoProxyGo, "x.example, * ", https("a.example"), Decision{Direct: true, Entry: "*", Basis: BasisEntry}},
		{RuleNoProxyGo, "a.example", https("localhost"), Decision{Direct: true, Basis: BasisLocal}},
		{RuleNoProxyGo, "", https("127.0.0.2"), Decision{Direct: true, Basis: BasisLocal}},
		{RuleNoProxyGo, "", https("::ffff:127.0.0.1"), Decision{Direct: true, Basis: BasisLocal}},
		{RuleNoProxyGo, "", https("LOCALHOST"), Decision{Basis: BasisNoEntry}},
		{RuleNoProxyPython, " .Example.COM ", https("www.example.com"),
			Decision{Direct: true, Entry: ".Example.COM", Basis: BasisEntry}},
		{RuleNoProxyNodeFetch, "x.test\tb.example", https("b.example"),
			Decision{Direct: true, Entry: "b.example", Basis: BasisEntry}},
		{RuleNoProxyNodeHTTP, "a.example", https("b.example"), Decision{Basis: BasisNoEntry}},
		{RuleWinINET, "<local>", https("intranet"), Decision{Direct: true, Entry: "<local>", Basis: BasisEntry}},
		{RuleNonProxyHosts, "a|*.b.example", https("x.b.example"),
			Decision{Direct: true, Entry: "*.b.example", Basis: BasisEntry}},
	}
	for _, c := range cases {
		got, err := Decide(c.rule, c.list, c.target)
		if err != nil || got != c.want {
			t.Errorf("%s: Decide(%q, %q) = %+v, %v; want %+v", c.rule, c.list, c.target.Host, got, err, c.want)
		}
	}
}

// TestTheNewReadingsAnswerOnlyForPrintableASCII is the refusal Decide
// documents: Go converts an entry to punycode and Python folds case by its own
// tables, and neither is read here.
func TestTheNewReadingsAnswerOnlyForPrintableASCII(t *testing.T) {
	for _, r := range NoProxyRules[2:] {
		for _, c := range []struct{ list, host, port string }{
			{"b\xc3\xbccher.example", "a.example", ""},
			{"a.example", "b\xc3\xbccher.example", ""},
			{"a.example", "a.example", "44\x003"},
			{"a\x1cb", "a.example", ""},
		} {
			_, err := Decide(r, c.list, Target{Scheme: "https", Host: c.host, Port: c.port})
			if !errors.Is(err, ErrNotASCII) {
				t.Errorf("%s: list %q, host %q, port %q gave %v, want ErrNotASCII", r, c.list, c.host, c.port, err)
			}
		}
		if _, err := Decide(r, "a.example\tb.example", https("a.example")); err != nil {
			t.Errorf("%s: a tab is printable enough for every program and was refused: %v", r, err)
		}
	}
	for _, r := range NoProxyRules[:2] {
		if _, err := Decide(r, "b\xc3\xbccher.example", https("a.example")); err != nil {
			t.Errorf("%s reads the environment for L2, which hands it whatever the machine holds, and refused: %v",
				r, err)
		}
	}
}
