package proxy

import (
	"errors"
	"testing"
)

// ask is a shorthand that fails the test on an error, so that the tables below
// read as claims about proxy behaviour rather than as error handling.
func ask(t *testing.T, r Rule, list string, target Target) bool {
	t.Helper()
	got, err := Bypasses(r, list, target)
	if err != nil {
		t.Fatalf("Bypasses(%s, %q, %+v) returned an error: %v", r, list, target, err)
	}
	return got
}

func host(name string) Target { return Target{Scheme: "https", Host: name, Port: "443"} }

func TestTheRuleListIsClosedAtFive(t *testing.T) {
	if len(AllRules) != 5 {
		t.Fatalf("AllRules has %d entries and the vocabulary is five; a sixth reading needs a source, measured or read at the vendor", len(AllRules))
	}
	seen := map[Rule]bool{}
	for _, r := range AllRules {
		if seen[r] {
			t.Errorf("AllRules lists %q twice", r)
		}
		seen[r] = true
		if !r.Valid() {
			t.Errorf("AllRules lists %q, which Valid rejects", r)
		}
		if r.Meaning() == "" {
			t.Errorf("rule %q has no meaning, so a report could print its bare identifier", r)
		}
		if r.String() != string(r) {
			t.Errorf("String() of %q gave %q", r, r.String())
		}
	}
	if Rule("socks").Valid() {
		t.Error("Valid accepted a rule that is not in the list")
	}
	if Rule("socks").Meaning() != "" {
		t.Error("a rule outside the list has a meaning")
	}
}

// TestEveryRuleInTheListHasAReading is the OBS95 guard: a classification that
// enumerates N cases has to say what happens to N+1. A fifth rule added to the
// vocabulary and forgotten in the switch would be caught here rather than
// silently inheriting whichever branch happened to be last.
func TestEveryRuleInTheListHasAReading(t *testing.T) {
	for _, r := range AllRules {
		if _, err := Bypasses(r, "example.com", host("example.com")); err != nil {
			t.Errorf("rule %q is in AllRules and Bypasses has no reading for it: %v", r, err)
		}
	}
}

func TestARuleOutsideTheListIsRefused(t *testing.T) {
	got, err := Bypasses(Rule("socks"), "*", host("example.com"))
	if !errors.Is(err, ErrUnknownRule) {
		t.Fatalf("an unknown rule gave error %v, and it has to be ErrUnknownRule", err)
	}
	if got {
		t.Error("an unknown rule answered that the target is excused, which would put an unchecked claim in the report")
	}
}

func TestAnAbsentHostIsRefused(t *testing.T) {
	for _, r := range AllRules {
		if _, err := Bypasses(r, "*", Target{Scheme: "https"}); !errors.Is(err, ErrNoTarget) {
			t.Errorf("rule %q with no host gave error %v, and it has to be ErrNoTarget", r, err)
		}
	}
}

// TestOneListMeansDifferentThingsToDifferentRuntimes is the product in one
// table. Every row is a single string that four programs on one machine read
// four ways, and no row contains a mistake by anybody.
func TestOneListMeansDifferentThingsToDifferentRuntimes(t *testing.T) {
	cases := []struct {
		name                                                     string
		list, target                                             string
		noProxy, winINET, winHTTP, nonProxyHosts, exceptionsList bool
		why                                                      string
	}{
		{
			name: "a wildcard on the right",
			list: "aaa.*", target: "aaa.corp",
			noProxy: false, winINET: true, winHTTP: false, nonProxyHosts: true, exceptionsList: true,
			why: "IE documents www.microsoft.* as working and WinHTTP names aaa.* as unsupported",
		},
		{
			name: "a bare domain name",
			list: "local.com", target: "www.local.com",
			noProxy: true, winINET: false, winHTTP: false, nonProxyHosts: false, exceptionsList: false,
			why: "curl matches a domain containing the host, every other rule matches the server named",
		},
		{
			name: "the local macro",
			list: "<local>", target: "intranet",
			noProxy: false, winINET: true, winHTTP: true, nonProxyHosts: false, exceptionsList: false,
			why: "<local> is a Windows macro and is an ordinary name everywhere else",
		},
		{
			name: "a wildcard on the left",
			list: "*.local.com", target: "www.local.com",
			noProxy: false, winINET: true, winHTTP: true, nonProxyHosts: true, exceptionsList: true,
			why: "the only wildcard position all four wildcard rules agree on",
		},
		{
			name: "an abbreviated network",
			list: "169.254/16", target: "169.254.1.1",
			noProxy: false, winINET: false, winHTTP: false, nonProxyHosts: false, exceptionsList: true,
			why: "the form every stock Mac ships in its own default, and the one curl's CIDR rule refuses",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := map[Rule]bool{
				RuleNoProxy:        c.noProxy,
				RuleWinINET:        c.winINET,
				RuleWinHTTP:        c.winHTTP,
				RuleNonProxyHosts:  c.nonProxyHosts,
				RuleExceptionsList: c.exceptionsList,
			}
			for _, r := range AllRules {
				if got := ask(t, r, c.list, host(c.target)); got != want[r] {
					t.Errorf("%s: list %q against %q gave %v, want %v (%s)",
						r, c.list, c.target, got, want[r], c.why)
				}
			}
		})
	}
}

// TestNoProxyMatchesADomainOrTheHostItself is curl's own worked example, kept
// as the vendor wrote it: local.com matches local.com and www.local.com, and
// does not match www.notlocal.com.
func TestNoProxyMatchesADomainOrTheHostItself(t *testing.T) {
	cases := []struct {
		list, target string
		want         bool
	}{
		{"local.com", "local.com", true},
		{"local.com", "www.local.com", true},
		{"local.com", "www.notlocal.com", false},
		{"local.com", "notlocal.com", false},
		{".local.com", "www.local.com", true},
		{".local.com", "local.com", true},
		{"a.com,b.com", "b.com", true},
		{" a.com , b.com ", "b.com", true},
		{"a.com", "b.com", false},
		{"", "a.com", false},
		{".", "a.com", false},
		{",,", "a.com", false},
	}
	for _, c := range cases {
		if got := ask(t, RuleNoProxy, c.list, host(c.target)); got != c.want {
			t.Errorf("NO_PROXY %q against %q gave %v, want %v", c.list, c.target, got, c.want)
		}
	}
}

func TestNoProxyUnderstandsCIDR(t *testing.T) {
	cases := []struct {
		list, target string
		want         bool
	}{
		{"192.168.0.0/16", "192.168.1.1", true},
		{"192.168.0.0/16", "192.169.1.1", false},
		{"192.168.0.0/16", "www.example.com", false},
		{"192.168.0.0/16", "::ffff:192.168.1.1", true},
		{"fd00::/8", "fd00::1", true},
		{"fd00::/8", "fe00::1", false},
		{"not/a/prefix", "192.168.1.1", false},
	}
	for _, c := range cases {
		if got := ask(t, RuleNoProxy, c.list, host(c.target)); got != c.want {
			t.Errorf("NO_PROXY %q against %q gave %v, want %v", c.list, c.target, got, c.want)
		}
	}
}

// TestALoneAsteriskIsTheWholeNoProxyValue holds the documented case and refuses
// the undocumented one. curl says NO_PROXY may be set TO a single asterisk; it
// says nothing about a star sitting beside real names.
func TestALoneAsteriskIsTheWholeNoProxyValue(t *testing.T) {
	if !ask(t, RuleNoProxy, "*", host("anything.example")) {
		t.Error("a lone asterisk did not excuse every host")
	}
	if !ask(t, RuleNoProxy, "  *  ", host("anything.example")) {
		t.Error("a lone asterisk with spaces around it did not excuse every host")
	}
	if ask(t, RuleNoProxy, "a.com,*", host("b.com")) {
		t.Error("an asterisk beside a real name excused an unrelated host, which no source documents")
	}
}

func TestWinINETNarrowsOnSchemeAndPort(t *testing.T) {
	cases := []struct {
		name        string
		list        string
		target      Target
		want        bool
		explanation string
	}{
		{
			name: "a scheme that matches", list: "https://api.corp",
			target: Target{Scheme: "https", Host: "api.corp", Port: "443"}, want: true,
			explanation: "the entry names the protocol the request uses",
		},
		{
			name: "a scheme that does not match", list: "http://api.corp",
			target: Target{Scheme: "https", Host: "api.corp", Port: "443"}, want: false,
			explanation: "the entry applies only to requests for that protocol",
		},
		{
			name: "a scheme in another case", list: "HTTPS://api.corp",
			target: Target{Scheme: "https", Host: "api.corp", Port: "443"}, want: true,
			explanation: "the protocol value is case insensitive",
		},
		{
			name: "a port that matches", list: "api.corp:8443",
			target: Target{Scheme: "https", Host: "api.corp", Port: "8443"}, want: true,
			explanation: "the request uses the specified port number",
		},
		{
			name: "a port that does not match", list: "api.corp:8443",
			target: Target{Scheme: "https", Host: "api.corp", Port: "443"}, want: false,
			explanation: "a port in the entry narrows the match",
		},
		{
			name: "an unknown scheme against a qualified entry", list: "https://api.corp",
			target: Target{Host: "api.corp", Port: "443"}, want: false,
			explanation: "a caller that does not know the scheme cannot be told a per-protocol entry applies",
		},
		{
			name: "an unqualified entry with an unknown scheme", list: "api.corp",
			target: Target{Host: "api.corp"}, want: true,
			explanation: "if no protocol is specified, any request that uses the address is bypassed",
		},
		{
			name: "a bracketed IPv6 literal with a port", list: "[::1]:8080",
			target: Target{Scheme: "http", Host: "[::1]", Port: "8080"}, want: true,
			explanation: "the last colon group belongs to the port only when brackets close before it",
		},
		{
			name: "a bare IPv6 literal keeps its last group", list: "::1",
			target: Target{Scheme: "http", Host: "::1"}, want: true,
			explanation: "an unbracketed literal has no port to take off",
		},
	}
	for _, c := range cases {
		if got := ask(t, RuleWinINET, c.list, c.target); got != c.want {
			t.Errorf("%s: ProxyOverride %q against %+v gave %v, want %v (%s)",
				c.name, c.list, c.target, got, c.want, c.explanation)
		}
	}
}

func TestWinINETTakesAWildcardAnywhere(t *testing.T) {
	cases := []struct {
		list, target string
		want         bool
	}{
		{"*.example.com", "some.example.com", true},
		{"www.*.com", "www.anything.com", true},
		{"www.microsoft.*", "www.microsoft.org", true},
		{"www.microsoft.*", "www.microsoftcorporation.com", false},
		{"123.1*.66.*", "123.144.66.12", true},
		{"123.1*.66.*", "123.244.66.12", false},
		{"a.corp;b.corp", "b.corp", true},
		{"a.corp;b.corp", "c.corp", false},
		// A colon with nothing after it is not a port, so the colon stays part
		// of the pattern and the entry names a host nobody has.
		{"api.corp:", "api.corp", false},
		// Nor is a tail that is not a number, so "api.corp:http" names no host
		// this run is asking about.
		{"api.corp:http", "api.corp", false},
	}
	for _, c := range cases {
		if got := ask(t, RuleWinINET, c.list, host(c.target)); got != c.want {
			t.Errorf("ProxyOverride %q against %q gave %v, want %v", c.list, c.target, got, c.want)
		}
	}
}

// TestWinHTTPRefusesAWildcardThatIsNotLeftMost is the vendor's own counter
// example. "aaa.*" is named as unsupported, and a host name has no asterisk in
// it for the entry to match literally, so the entry excuses nobody.
func TestWinHTTPRefusesAWildcardThatIsNotLeftMost(t *testing.T) {
	cases := []struct {
		list, target string
		want         bool
	}{
		{"*.microsoft.com", "www.microsoft.com", true},
		{"*.microsoft.com", "microsoft.com", false},
		{"*.org", "example.org", true},
		{"aaa.*", "aaa.corp", false},
		{"www.*.com", "www.anything.com", false},
		{"exact.corp", "exact.corp", true},
		{"exact.corp", "www.exact.corp", false},
		{"a.corp b.corp", "b.corp", true},
		{"a.corp;b.corp", "b.corp", true},
		{"a.corp\tb.corp", "b.corp", true},
	}
	for _, c := range cases {
		if got := ask(t, RuleWinHTTP, c.list, host(c.target)); got != c.want {
			t.Errorf("WinHTTP bypass %q against %q gave %v, want %v", c.list, c.target, got, c.want)
		}
	}
}

// TestTheLocalMacroMeansAHostWithoutAPeriod holds the vendor's definition
// literally: local intranet sites "are considered to be all servers that do not
// contain a period in their name".
func TestTheLocalMacroMeansAHostWithoutAPeriod(t *testing.T) {
	for _, r := range []Rule{RuleWinINET, RuleWinHTTP} {
		if !ask(t, r, "<local>", host("intranet")) {
			t.Errorf("%s: <local> did not excuse a name without a period", r)
		}
		if !ask(t, r, "<LOCAL>", host("intranet")) {
			t.Errorf("%s: <local> stopped working in another case", r)
		}
		if ask(t, r, "<local>", host("intranet.corp.example")) {
			t.Errorf("%s: <local> excused a name that contains a period", r)
		}
		if ask(t, r, "<local>", host("10.0.0.1")) {
			t.Errorf("%s: <local> excused an IPv4 address, which contains periods", r)
		}
	}
}

func TestNonProxyHostsAllowsAWildcardOnEitherSide(t *testing.T) {
	cases := []struct {
		list, target string
		want         bool
	}{
		{"*.foo.com|localhost", "bar.foo.com", true},
		{"*.foo.com|localhost", "localhost", true},
		{"*.foo.com|localhost", "foo.com", false},
		{NonProxyHostsDefault, "127.0.0.1", true},
		{NonProxyHostsDefault, "::1", true},
		{NonProxyHostsDefault, "128.0.0.1", false},
		{"a.corp|b.corp", "b.corp", true},
		{"a.corp;b.corp", "b.corp", false},
		{"*", "anything.example", true},
		{"abcdef", "abc", false},
		{"abc", "abcdef", false},
		{"*.corp*", "www.corp.example", true},
		// A trailing wildcard with nothing left to swallow still matches.
		{"abc*", "abc", true},
	}
	for _, c := range cases {
		if got := ask(t, RuleNonProxyHosts, c.list, host(c.target)); got != c.want {
			t.Errorf("nonProxyHosts %q against %q gave %v, want %v", c.list, c.target, got, c.want)
		}
	}
}

// TestTheJavaDefaultIsNotSubstituted keeps "nobody configured this" and
// "somebody configured exactly the default" distinguishable. Only a caller that
// knows whether the property was set may put the default in place of an empty
// list.
func TestTheJavaDefaultIsNotSubstituted(t *testing.T) {
	if ask(t, RuleNonProxyHosts, "", host("localhost")) {
		t.Error("an empty list behaved as though it held the JVM default, which hides whether anybody configured it")
	}
	if !ask(t, RuleNonProxyHosts, NonProxyHostsDefault, host("localhost")) {
		t.Error("the documented JVM default did not excuse localhost")
	}
}

// TestAHostIsComparedInOneSpelling covers the normalisation every rule shares.
// Two spellings of one name answering differently would be a defect nobody
// reading the report could explain.
func TestAHostIsComparedInOneSpelling(t *testing.T) {
	cases := []struct {
		name   string
		rule   Rule
		list   string
		target string
	}{
		{"upper case host", RuleNoProxy, "local.com", "WWW.LOCAL.COM"},
		{"upper case entry", RuleNoProxy, "LOCAL.COM", "www.local.com"},
		{"trailing dot on the host", RuleNoProxy, "local.com", "www.local.com."},
		{"trailing dot on the entry", RuleNoProxy, "local.com.", "www.local.com"},
		{"upper case under wininet", RuleWinINET, "*.LOCAL.COM", "WWW.local.com"},
		{"upper case under winhttp", RuleWinHTTP, "*.LOCAL.COM", "WWW.local.com"},
		{"upper case under java", RuleNonProxyHosts, "*.LOCAL.COM", "WWW.local.com"},
		{"a bracketed literal against a bare one", RuleNonProxyHosts, "[::1]", "::1"},
		{"a bare literal against a bracketed one", RuleNonProxyHosts, "::1", "[::1]"},
	}
	for _, c := range cases {
		if !ask(t, c.rule, c.list, host(c.target)) {
			t.Errorf("%s: %s did not excuse %q against %q, so one name has two answers",
				c.name, c.rule, c.target, c.list)
		}
	}
}

// TestAPatternDoesNotBacktrackForever is the sandbox lesson applied one package
// over: the pattern comes out of somebody else's registry, and the obvious
// recursive glob spends the whole run on a short hostile string. If this ever
// hangs, the matcher went recursive.
func TestAPatternDoesNotBacktrackForever(t *testing.T) {
	hostile := "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b"
	target := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
	if ask(t, RuleNonProxyHosts, hostile, host(target)) {
		t.Error("a pattern ending in b matched a target ending in c")
	}
}

// TestTheMacDefaultBypassesLocalNamesAndLinkLocal holds the measurement itself.
// This is the one list in this package that came off a machine rather than off a
// vendor's page - scutil --proxy on a Mac with no proxy configured, 2026-09-05 -
// and it says that a stock Mac already sends two whole families of address
// direct before anybody configures anything.
func TestTheMacDefaultBypassesLocalNamesAndLinkLocal(t *testing.T) {
	cases := []struct {
		target string
		want   bool
		why    string
	}{
		{"printer.local", true, "*.local is in the shipped default"},
		{"PRINTER.LOCAL", true, "and host names are case insensitive"},
		{"local", false, "the entry is *.local, not local"},
		{"notlocal.example", false, "an unrelated name is not excused"},
		{"169.254.1.1", true, "169.254/16 is the link-local block written the BSD way"},
		{"169.254.255.255", true, "and it covers the whole block"},
		{"169.255.1.1", false, "one octet outside it is outside it"},
		{"10.0.0.1", false, "an ordinary private address is not link-local"},
	}
	for _, c := range cases {
		if got := ask(t, RuleExceptionsList, ExceptionsListDefault, host(c.target)); got != c.want {
			t.Errorf("the shipped macOS default against %q gave %v, want %v (%s)", c.target, got, c.want, c.why)
		}
	}
}

// TestAnAbbreviatedNetworkIsAMacFormAndNotACurlOne is the reason the fifth rule
// exists at all. curl documents CIDR as a slash appended to an IP ADDRESS, and
// netip refuses "169.254/16"; macOS ships exactly that spelling in its own
// default. Reading one under the other's rule turns a real bypass into a host
// name nobody has.
func TestAnAbbreviatedNetworkIsAMacFormAndNotACurlOne(t *testing.T) {
	if ask(t, RuleNoProxy, "169.254/16", host("169.254.1.1")) {
		t.Error("NO_PROXY accepted an abbreviated network, which curl does not document")
	}
	if !ask(t, RuleExceptionsList, "169.254/16", host("169.254.1.1")) {
		t.Error("the macOS rule did not accept the form macOS itself ships")
	}
	// The full spelling has to work in both, or a Mac with a hand-written entry
	// would answer differently from one with the shipped one.
	if !ask(t, RuleNoProxy, "169.254.0.0/16", host("169.254.1.1")) {
		t.Error("NO_PROXY refused an ordinary CIDR block")
	}
	if !ask(t, RuleExceptionsList, "169.254.0.0/16", host("169.254.1.1")) {
		t.Error("the macOS rule refused an ordinary CIDR block")
	}
}

// TestAnUnreadableNetworkEntryClaimsNothing keeps the conservative direction. An
// entry we cannot parse must not become a bypass, because telling somebody their
// proxy is uninvolved when it is not is the expensive mistake here.
func TestAnUnreadableNetworkEntryClaimsNothing(t *testing.T) {
	for _, list := range []string{"1.2.3.4.5/16", "169.254/999", "//", "fd00::/8"} {
		if ask(t, RuleExceptionsList, list, host("10.0.0.1")) {
			t.Errorf("entry %q excused an address it says nothing about", list)
		}
	}
	// The IPv6 block is readable and does match an address inside it - the case
	// above only proves it does not match one outside.
	if !ask(t, RuleExceptionsList, "fd00::/8", host("fd00::1")) {
		t.Error("the macOS rule refused an IPv6 block written in full")
	}
}

// TestTheMacListSeparatorIsOursAndNotTheVendors pins the newline decision. The
// platform hands the entries over as an array, so this list has no separator of
// its own - a semicolon or a comma inside an entry has to stay part of it.
func TestTheMacListSeparatorIsOursAndNotTheVendors(t *testing.T) {
	if !ask(t, RuleExceptionsList, "a.corp\nb.corp", host("b.corp")) {
		t.Error("a newline did not separate two entries")
	}
	if ask(t, RuleExceptionsList, "a.corp;b.corp", host("b.corp")) {
		t.Error("a semicolon separated two entries, and this list does not have one")
	}
}
