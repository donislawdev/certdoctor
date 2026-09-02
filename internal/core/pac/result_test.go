package pac

import "testing"

func TestParseDirectivesKeepsAnUnknownKeyword(t *testing.T) {
	// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - entries are
	// separated by semicolons and tried left to right, and Firefox accepts
	// HTTP, HTTPS, SOCKS4 and SOCKS5 beyond the original DIRECT, PROXY and
	// SOCKS.
	//
	// AN UNKNOWN KEYWORD IS KEPT RATHER THAN DROPPED - inviolable rule 15. A
	// directive silently discarded would let a report say a client goes direct
	// when the file named something this program could not read.
	for _, c := range []struct {
		name   string
		answer string
		want   []Directive
	}{
		{"direct", "DIRECT", []Directive{{Kind: "DIRECT", Recognised: true}}},
		{"a proxy", "PROXY p.test:8080", []Directive{{Kind: "PROXY", Endpoint: "p.test:8080", Recognised: true}}},
		{"lower case", "direct", []Directive{{Kind: "DIRECT", Recognised: true}}},
		{"a chain", "PROXY a.test:1; DIRECT", []Directive{
			{Kind: "PROXY", Endpoint: "a.test:1", Recognised: true},
			{Kind: "DIRECT", Recognised: true},
		}},
		{"every keyword Firefox takes", "SOCKS4 s.test:1; SOCKS5 s.test:2; HTTP h.test:3; HTTPS h.test:4", []Directive{
			{Kind: "SOCKS4", Endpoint: "s.test:1", Recognised: true},
			{Kind: "SOCKS5", Endpoint: "s.test:2", Recognised: true},
			{Kind: "HTTP", Endpoint: "h.test:3", Recognised: true},
			{Kind: "HTTPS", Endpoint: "h.test:4", Recognised: true},
		}},
		{"an unknown keyword", "WARP g.test:9", []Directive{{Kind: "WARP", Endpoint: "g.test:9"}}},
		{"unknown before known", "WARP g.test:9; DIRECT", []Directive{
			{Kind: "WARP", Endpoint: "g.test:9"},
			{Kind: "DIRECT", Recognised: true},
		}},

		// Nothing at all, in the three ways a PAC file can say it. None of them
		// is a directive, and none is an error either.
		{"empty", "", nil},
		{"only spaces", "   ", nil},
		{"only separators", " ; ; ", nil},
	} {
		got := ParseDirectives(c.answer)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %d directives, want %d (%v)", c.name, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: directive %d is %+v, want %+v", c.name, i, got[i], c.want[i])
			}
		}
	}
}
