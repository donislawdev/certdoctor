package main

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
)

// TestASchemeRefusalAdvisesWhatCanBeTyped holds the two refusals of a scheme
// apart (OBS205). An input with no scheme gets https:// in front as the
// suggestion, and an address of another scheme is told which ones this program
// diagnoses - it used to get https:// in front as well, so "ftp://example.com"
// was answered with "https://ftp://example.com", a suggestion that is not an
// address either. "localhost:8080" is the case between them: the URL parser
// reads it as the scheme "localhost", and what the person left out is the
// scheme.
func TestASchemeRefusalAdvisesWhatCanBeTyped(t *testing.T) {
	for _, c := range []struct{ raw, says string }{
		{"example.com", `for example "https://example.com"`},
		{"example.com/path", `for example "https://example.com/path"`},
		{"localhost:8080", `for example "https://localhost:8080"`},
		{"example.com:443", `for example "https://example.com:443"`},
		{"localhost:", `for example "https://localhost:"`},
		{"//example.com", `for example "https://example.com"`},
		{"/example.com", `for example "https://example.com"`},
		// A path keeps the suggestion apart from the example a hostless one
		// gives way to, so the slashes are seen to be taken off rather than
		// the whole input thrown away.
		{"//example.com/path", `for example "https://example.com/path"`},
		{"/", `for example "https://example.com"`},
		{"example.com:", `for example "https://example.com:"`},
		{"ftp://example.com", "uses the ftp scheme, and certdoctor diagnoses only http:// and https:// addresses"},
		{"FTP://example.com", "uses the ftp scheme"},
		{"file:///etc/hosts", "uses the file scheme"},
		{"mailto:bob@example.com", "uses the mailto scheme"},
		{"ws://example.com:8080", "uses the ws scheme"},
	} {
		h := invoke(c.raw)
		said := h.stderr.String()
		if h.code != exitcode.Usage {
			t.Errorf("%q ended with %s, want %s: %q", c.raw, h.code.Name(), exitcode.Usage.Name(), said)
		}
		if !strings.Contains(said, c.says) {
			t.Errorf("%q was answered %q, which does not say %q", c.raw, said, c.says)
		}
		// Whatever it offers to be typed instead has to be an address this
		// program diagnoses - the defect was a suggestion that is not one.
		if _, offered, found := strings.Cut(said, "for example "); found {
			suggestion, err := strconv.Unquote(strings.TrimSpace(offered))
			if err != nil {
				t.Errorf("%q: the suggestion %s is not one quoted string: %v", c.raw, offered, err)
				continue
			}
			u, err := url.Parse(suggestion)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				t.Errorf("%q was told to write %q, which is not an http:// or https:// address", c.raw, suggestion)
			}
		}
	}
}
