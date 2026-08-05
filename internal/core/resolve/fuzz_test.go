package resolve

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzAConfigNeverLetsUnreadableTextThrough is the second half of position 3 in
// the standard of code: the other parser of somebody else's input.
//
// WHAT IT ASSERTS IS ADR27 ITSELF, not the absence of a crash. A panic here would
// be caught at the entry point and end the run with an internal failure, which is
// loud. The quiet failure is the one worth fuzzing for: a byte that is not text
// travelling out of this parser, into a finding, and into --json - where it
// produces a document the consumer cannot decode, and the blame lands on us.
//
// The corpus starts from the ten shapes S9 measured on 2026-08-05, because a
// corpus of invented inputs is a corpus of inputs somebody thought of.
func FuzzAConfigNeverLetsUnreadableTextThrough(f *testing.F) {
	for _, seed := range []string{
		"nameserver 1.1.1.1\nsearch corp.example\n",
		"nameserver 192.168.65.7\nnameserver 8.8.8.8\noptions ndots:0\n",
		"\xef\xbb\xbfnameserver 1.1.1.1\n",
		"\xff\xfen\x00a\x00m\x00e\x00",
		"\xfe\xff\x00n\x00a",
		"nameserver 1.1.1.\x9c\n",
		"nameserver 1.1.1.1\x00\n",
		"# only a comment\n",
		"",
		"nameserver\n",
		"domain a.example\nsearch b.example\n",
		"hosts:\tfiles [NOTFOUND=return] dns\n",
		"hosts: files\nhosts: dns\n",
		"nameserver fe80::1%eth0\n",
		"\r\n\r\n",
		strings.Repeat("nameserver 1.1.1.1\n", 200),
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		total := len(lines(data))

		config, err := ParseResolverConfig(data)
		if err == nil {
			for _, address := range config.Nameservers {
				requireReportable(t, "a nameserver", address)
				// Every one of these goes into the set of places this program may
				// connect to. An entry that is not an address is a hole in
				// inviolable rule 16 rather than an untidy row.
				if !isAddress(address) {
					t.Fatalf("a nameserver that is not an address came through: %q", address)
				}
			}
			for _, name := range config.Search {
				requireReportable(t, "a search domain", name)
			}
			requireLinesExist(t, config.Skipped, total)
		}

		sources, err := ParseNameSources(data)
		if err == nil {
			for _, source := range sources.Order {
				requireReportable(t, "a name source", source)
				// The brackets are actions rather than places, and one reaching
				// the report would name [NOTFOUND=return] as somewhere this
				// machine looks up names.
				if strings.HasPrefix(source, "[") || strings.HasSuffix(source, "]") {
					t.Fatalf("a bracketed action came through as a source: %q", source)
				}
			}
			requireLinesExist(t, sources.Skipped, total)
		}
	})
}

// requireReportable is ADR27 stated as a property: whatever leaves this parser can
// be put in a report without breaking the report.
func requireReportable(t *testing.T, what, value string) {
	t.Helper()
	if !utf8.ValidString(value) {
		t.Fatalf("%s that is not valid UTF-8 came through and would go straight into --json: %q", what, value)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("%s carrying a control character came through, and it renders identically to a clean one: %q",
				what, value)
		}
	}
	if value == "" {
		t.Fatalf("%s came through empty, which renders as a row with nothing in it", what)
	}
}

// requireLinesExist keeps the one number a reader is asked to act on honest. "Go
// and look at line 12" is worthless advice about a file with four lines, and it
// is the kind of wrong that reads as a bug in their configuration rather than in
// ours.
func requireLinesExist(t *testing.T, skipped []Skipped, total int) {
	t.Helper()
	for _, s := range skipped {
		if s.Line < 1 || s.Line > total {
			t.Fatalf("a line was reported as skipped at %d in a file of %d lines", s.Line, total)
		}
		if s.Why == "" {
			t.Fatalf("line %d was reported as skipped with no reason, which is the silence this field exists to prevent", s.Line)
		}
	}
}
