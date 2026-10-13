package redact

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzUserInfoNeverSurvives is the target the standard of code puts at the top
// of its list, above every parser: hostile input, and a consequence that cannot
// be undone once a report has been pasted somewhere.
//
// WHAT IT ASSERTS. Given a credential sitting in the one place this package
// promises to clear - the user info of a URL - it is not in the output. Not
// "usually", and not "for the shapes somebody thought of".
//
// WHAT IT DELIBERATELY SKIPS, said here rather than hidden in a condition:
// inputs where the credential is not in user info at all. A secret typed as
// bare text with nothing around it goes through, and that is correct - this
// package is a sieve and the report says so. Asserting otherwise would be
// asserting something untrue and the target would be tuned until it passed.
// controlSecret stands in for the fuzzed one when building the control run. It
// only has to be something no masker would invent on its own.
const controlSecret = "CONTROLSECRETVALUE"

func FuzzUserInfoNeverSurvives(f *testing.F) {
	seeds := []struct{ user, secret, host, tail string }{
		{"user", "hunter2", "proxy.corp.example:8080", ""},
		{"bob", "s3cr3t", "proxy", "/a/b?page=2"},
		{"DOMAIN\\bob", "p@ss", "proxy", ""},
		{"token", "x", "registry.example", "/v1"},
		{"u", "very long secret value here", "h", "/"},
		{"u", "%2F%40", "h", "/x"},
		{"u", "\u017a\u00f3\u0142w", "h", ""},
	}
	for _, s := range seeds {
		f.Add(s.user, s.secret, s.host, s.tail)
	}

	f.Fuzz(func(t *testing.T, user, secret, host, tail string) {
		if !isUserInfoComponent(user) || !isUserInfoComponent(secret) || !isHostComponent(host) {
			return
		}
		// A credential that also appears elsewhere would survive there for a
		// legitimate reason, and a credential that is part of the placeholder
		// cannot be told apart from it.
		if strings.Contains(tail, secret) || strings.Contains(host, secret) ||
			strings.Contains(Placeholder, secret) || strings.Contains(user, secret) {
			return
		}

		value := "https://" + user + ":" + secret + "@" + host + tail
		for _, mode := range []Mode{Credentials, Everything} {
			// The control is the same URL with a different secret. If the
			// string under test turns up in THAT output, it can only have come
			// from something the masker produced itself - a pseudonym, the
			// placeholder, the surviving host - and finding it in the real
			// output proves nothing.
			//
			// This check exists because the first fuzz run failed on a secret
			// of "1", found inside the pseudonym host-1. Answering that by
			// demanding longer secrets would have been tuning the target until
			// it passed. Comparing against a control asks the question that was
			// meant, and keeps asking it if the placeholder ever changes.
			control := New(mode).Text("https://" + user + ":" + controlSecret + "@" + host + tail)
			if strings.Contains(control, secret) {
				continue
			}

			got := New(mode).Text(value)
			if strings.Contains(got, secret) {
				t.Fatalf("mode %d let a credential through\n  in:  %q\n  out: %q\n  secret: %q",
					mode, value, got, secret)
			}
			if !New(mode).CarriedCredentials(value) {
				t.Fatalf("mode %d reported %q as carrying nothing", mode, value)
			}
		}
	})
}

// FuzzMaskingIsIdempotent is property 2 from the standard of code, over
// everything rather than over a list.
//
// It matters because a report passes through more than one hand: rendered,
// saved, quoted into a ticket, quoted again. A second pass that renamed
// host-1 to host-2 would make a report disagree with a copy of itself, and
// nobody would know which one to believe.
func FuzzMaskingIsIdempotent(f *testing.F) {
	for _, seed := range []string{
		"http://user:hunter2@proxy:8080",
		"https://api.example/v1?token=abc&key=def&page=2",
		"-Djavax.net.ssl.trustStorePassword=changeit",
		"Proxy-Authorization: Basic ZGVtbzpzZWNyZXQ=",
		"https://host-1/already-masked",
		"https://host-2/renumbered",
		"[redacted]",
		"",
		"\x00\x01 not text at all",
		"https://[::1]:8443/x and https://[::1]/y",
		// OBS152: punctuation straight after the separator is stepped over, so
		// the pseudonym lands after it and a second pass has to leave it there.
		"given as http://, which",
		"http://,secret.corp:8080 and (https://)",
		"C:\\Users\\jdoe\\AppData\\Roaming\\npm",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		for _, mode := range []Mode{Credentials, Everything} {
			r := New(mode, Name("jdoe"), Name("bob"))
			once := r.Text(text)
			twice := r.Text(once)
			if once != twice {
				t.Fatalf("mode %d: masking twice changed the text\n  in:    %q\n  once:  %q\n  twice: %q",
					mode, text, once, twice)
			}
		}
	})
}

// isUserInfoComponent reports whether s can sit in the user info of a URL. The
// grammar this package matches ends user info at a slash, an at sign or any
// space, so a string carrying one of those is simply not in that position.
func isUserInfoComponent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == '/' || r == '@' || r == ':' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func isHostComponent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == '/' || r == '@' || r == '?' || r == '#' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}
