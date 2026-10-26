package pac

import (
	"strings"
	"testing"
)

// The vectors below are TRANSCRIBED FROM MOZILLA'S PAC DOCUMENTATION, read
// 2026-09-02, not produced by running this package. That is the whole point of
// this file: OBS48 measured what happens when a test asks the code under test
// what the answer should be - it agrees with whatever the code does, including
// after a mutation. Every expectation here was written from the specification,
// and the ones that are ours rather than Mozilla's say so.

func TestIsPlainHostNameIsAboutTheDot(t *testing.T) {
	for _, c := range []struct {
		host string
		want bool
	}{
		// Mozilla's two documented examples.
		{"www.mozilla.org", false},
		{"www", true},
		// Ours: the bench's first branch, and the degenerate input.
		{"proxy.test", false},
		{"", true},
		{".", false},
	} {
		if got := IsPlainHostName(c.host); got != c.want {
			t.Errorf("IsPlainHostName(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestDNSDomainIsIsAPlainSuffixAndTheApexDoesNotMatch(t *testing.T) {
	for _, c := range []struct {
		host, domain string
		want         bool
	}{
		// Mozilla's documented examples.
		{"www.mozilla.org", ".mozilla.org", true},
		{"www", ".mozilla.org", false},
		// THE ONE THAT DECIDES THE SHAPE OF THE FUNCTION. The zone apex does
		// NOT match its own suffix form, which is why the bench's PAC file
		// spells the apex out on a line of its own. A "smarter" suffix match
		// would make this true and make certdoctor disagree with the browser.
		{"proxy.test", ".proxy.test", false},
		{"a.proxy.test", ".proxy.test", true},
		// A suffix that is longer than the host cannot match.
		{"x", ".proxy.test", false},
		// It is a string suffix, not a label suffix: this is somebody else's
		// behaviour and we reproduce it rather than improving on it.
		{"evilproxy.test", "proxy.test", true},
	} {
		if got := DNSDomainIs(c.host, c.domain); got != c.want {
			t.Errorf("DNSDomainIs(%q, %q) = %v, want %v", c.host, c.domain, got, c.want)
		}
	}
}

func TestLocalHostOrDomainIsNeedsAnExactMatchOrAnUnqualifiedName(t *testing.T) {
	for _, c := range []struct {
		host, hostDom string
		want          bool
	}{
		// Mozilla's four documented cases, in order.
		{"www.mozilla.org", "www.mozilla.org", true},
		{"www", "www.mozilla.org", true},
		{"www.google.com", "www.mozilla.org", false},
		{"home.mozilla.org", "www.mozilla.org", false},
		// Ours: a qualified host sharing only its FIRST LABEL must not match,
		// which is what stops the unqualified branch being written as a bare
		// prefix test.
		{"www.example.com", "www.mozilla.org", false},
	} {
		if got := LocalHostOrDomainIs(c.host, c.hostDom); got != c.want {
			t.Errorf("LocalHostOrDomainIs(%q, %q) = %v, want %v", c.host, c.hostDom, got, c.want)
		}
	}
}

func TestDNSDomainLevelsCountsDots(t *testing.T) {
	for _, c := range []struct {
		host string
		want int
	}{
		// Mozilla's three documented examples.
		{"www", 0},
		{"mozilla.org", 1},
		{"www.mozilla.org", 2},
	} {
		if got := DNSDomainLevels(c.host); got != c.want {
			t.Errorf("DNSDomainLevels(%q) = %d, want %d", c.host, got, c.want)
		}
	}
}

func TestShExpMatch(t *testing.T) {
	for _, c := range []struct {
		text, pattern string
		want          bool
	}{
		// Mozilla's two documented examples.
		{"http://home.netscape.com/people/ari/index.html", "*/ari/*", true},
		{"http://home.netscape.com/people/montulli/index.html", "*/ari/*", false},

		// Ours, one per rule of the matcher.
		{"anything", "*", true},
		{"", "*", true},
		{"", "", true},
		{"a", "", false},
		{"", "?", false},
		{"abc", "a?c", true},
		{"ac", "a?c", false},
		{"abc", "abc", true},
		{"abc", "ab", false},
		{"build.internal.example", "*.internal.*", true},

		// The class forms Firefox supports.
		{"a1", "a[0-9]", true},
		{"ax", "a[0-9]", false},
		{"ax", "a[^0-9]", true},
		{"a1", "a[^0-9]", false},
		{"a-", "a[a-]", true},
		{"a]", "a[]]", true},
		// An unclosed bracket is a literal bracket rather than a failure.
		{"a[", "a[", true},

		// OBS88 APPLIED TO THIS FUNCTION: "?" is documented to match one
		// CHARACTER. Comparing bytes would make it match one third of an
		// accented letter, so an internationalised host would stop matching a
		// pattern that a browser matches.
		// The letter is built from its code point rather than typed, because
		// .go files in this repository are pure ASCII and a guard says so.
		// U+00E9 is two bytes in UTF-8, so a byte-wise "?" would need two of
		// them to match it - which is what the second row pins.
		{"caf" + string(rune(0xE9)) + ".example", "caf?.example", true},
		{"caf" + string(rune(0xE9)) + ".example", "caf??.example", false},
	} {
		if got := ShExpMatch(c.text, c.pattern); got != c.want {
			t.Errorf("ShExpMatch(%q, %q) = %v, want %v", c.text, c.pattern, got, c.want)
		}
	}
}

// TestShExpMatchDoesNotBacktrackExponentially is a SANDBOX test wearing a unit
// test's clothes, and it is here rather than in the adapter because this is
// where the loop is.
//
// Measured 2026-09-02: the sandbox's interrupt does not stop native Go called
// from JavaScript. A PAC file can therefore hand this function the pattern that
// makes a naive recursive glob take exponential time, and nothing in the sandbox
// would end it - it would spend the user's whole run. The input below finishes
// immediately for the two-pointer matcher and would hang a recursive one.
func TestShExpMatchDoesNotBacktrackExponentially(t *testing.T) {
	text := ""
	for i := 0; i < 64; i++ {
		text += "a"
	}
	if ShExpMatch(text, "*a*a*a*a*a*a*a*a*a*a*b") {
		t.Fatal("the pattern demands a trailing b that the text does not have")
	}
}

// POLYNOMIAL IS NOT SHORT - ADR114. The product of the two lengths is billions
// of steps for a text a PAC file builds in one line, so the loop asks when to
// stop, and stopping is said rather than answered as a no. The asking costs
// nothing a finished match can see.
func TestShExpMatchStopsWhenAskedAndSaysItDidNot(t *testing.T) {
	text := strings.Repeat("a", 20000)
	pattern := "*" + strings.Repeat("a", 10000) + "b"
	asked := 0
	matched, finished := ShExpMatchUntil(text, pattern, func() bool { asked++; return asked == 3 })
	if matched || finished || asked != 3 {
		t.Errorf("got matched %v, finished %v after %d questions - want a stop at the third, said", matched, finished, asked)
	}

	never := func() bool { return false }
	if matched, finished := ShExpMatchUntil("http://a.test/x", "*a.test*", never); !matched || !finished {
		t.Errorf("a match that never had to stop came back %v, %v", matched, finished)
	}
	if matched, finished := ShExpMatchUntil(text, "a?", never); matched || !finished {
		t.Errorf("a refusal that never had to stop came back %v, %v", matched, finished)
	}
	if _, finished := ShExpMatchUntil(text[:stopEvery/4], "*b", func() bool { return true }); !finished {
		t.Error("a match shorter than one round of steps asked to stop")
	}
}

// AN ENTRY A CLIENT CAN FOLLOW - ADR114. Mozilla's documentation, read
// 2026-09-02: DIRECT takes nothing and every other keyword names "host:port".
func TestADirectiveIsUsableOnlyWithTheAddressItNeeds(t *testing.T) {
	for answer, want := range map[string]bool{
		"DIRECT":              true,
		"PROXY p.test:8080":   true,
		"SOCKS5 s.test:1080":  true,
		"PROXY":               false,
		"HTTPS":               false,
		"DIRECT p.test:8080":  false,
		"PROXY p.test 8080":   false,
		"WARP g.test:9":       false,
		"PROXY p.test:8080\t": true,
	} {
		directives := ParseDirectives(answer)
		if len(directives) != 1 || directives[0].Usable() != want {
			t.Errorf("%q: got %+v, want usable %v", answer, directives, want)
		}
	}
}
