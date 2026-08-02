package main

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
)

// FuzzCommandLineAlwaysEndsWithADeclaredCode is the fuzz target the standard of
// code has been asking for since before there was a command line.
//
// WHAT IT PROVES. For any command line at all, the process ends with a code
// from the frozen table, and a code that is not one of the three reporting
// codes leaves standard output untouched. Those two together are the whole
// contract a pipeline depends on, and neither of them can be established by
// listing the cases somebody thought of.
//
// WHY IT IS SAFE TO RUN. The environment handed in cannot reach a clock, a
// terminal or a file system, so no input can make this target create a file,
// open a socket or take a different amount of time. Fuzzing a program that can
// write to a path taken from its own input is how a corpus grows a surprising
// file in it.
//
// The seed corpus goes into the repository, so an ordinary go test walks
// everything ever found here even though the fuzzing engine itself is not run
// in CI - it searches without end, and that is a thing to run by hand with a
// budget rather than on every push.
func FuzzCommandLineAlwaysEndsWithADeclaredCode(f *testing.F) {
	seeds := [][]string{
		{"https://example.com"},
		{"https://example.com", "--json"},
		{"--help"},
		{"--version"},
		{"--license"},
		{},
		{"-"},
		{"--"},
		{"--format"},
		{"--format", "md"},
		{"--timeout", "-0"},
		{"--timeout", "1e309"},
		{"--out", ""},
		{"https://user:pass@example.com/p?token=t#f", "--json"},
		{"HTTPS://EXAMPLE.COM"},
		{"https://[::1]:8443/"},
		{"https://example.com", "--json", "--format=json"},
		{"https://example.com", "--redact", "--out", "x"},
		{"file:///etc/passwd"},
		{"https://", "--quiet", "--verbose"},
	}
	for _, seed := range seeds {
		f.Add(strings.Join(seed, "\n"))
	}

	f.Fuzz(func(t *testing.T, joined string) {
		var args []string
		if joined != "" {
			args = strings.Split(joined, "\n")
		}
		h := invoke(args...)

		if !h.code.Valid() {
			t.Fatalf("%q ended with %d, which is not in the frozen table", args, h.code.Int())
		}

		reports := h.code == exitcode.OK || h.code == exitcode.Diagnosis || h.code == exitcode.Inconclusive
		if !reports && h.stdout.Len() > 0 {
			t.Fatalf("%q ended with %s and left %d bytes on standard output",
				args, h.code.Name(), h.stdout.Len())
		}
		if !reports && h.stderr.Len() == 0 {
			t.Fatalf("%q ended with %s and said nothing at all", args, h.code.Name())
		}

		// Anything this program did manage to encode has to match the contract
		// it publishes. A document that does not is an internal failure, and
		// finding one from an odd command line is exactly what this is for.
		for path, written := range h.written {
			if err := render.ValidateDocument(written); err != nil && looksLikeJSON(written) {
				t.Fatalf("%q wrote a document to %q that does not match the declared schema:\n%v", args, path, err)
			}
		}
	})
}

// looksLikeJSON keeps the schema assertion off a terminal report, which is
// written to --out just as happily and is not a document.
func looksLikeJSON(data []byte) bool {
	return len(data) > 0 && data[0] == '{'
}
