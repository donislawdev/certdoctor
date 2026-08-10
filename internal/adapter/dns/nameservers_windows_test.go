//go:build windows

package dns

import (
	"strings"
	"testing"
)

// TestBothSpellingsOfTheSeparatorAreCut is measured behaviour, not a guess.
//
// Windows writes this setting two ways: a NameServer typed by hand is comma
// separated and DhcpNameServer is space separated. A parser that knew only one
// would report a single resolver whose name is three addresses glued together -
// which then goes into the set of places this run may connect to and matches
// nothing, so every query is refused on a machine that works.
func TestBothSpellingsOfTheSeparatorAreCut(t *testing.T) {
	cases := map[string][]string{
		"1.1.1.1,8.8.8.8":     {"1.1.1.1", "8.8.8.8"},
		"1.1.1.1 8.8.8.8":     {"1.1.1.1", "8.8.8.8"},
		"1.1.1.1;8.8.8.8":     {"1.1.1.1", "8.8.8.8"},
		"1.1.1.1, 8.8.8.8   ": {"1.1.1.1", "8.8.8.8"},
		"":                    {},
		"   ":                 {},
	}

	for value, want := range cases {
		got := splitServers(value)
		if len(got) != len(want) {
			t.Errorf("%q split into %v where %v was expected", value, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q split into %v", value, got)
				break
			}
		}
	}
}

// TestATextFromTheApiStopsAtItsTerminator covers the fixed array the IP helper
// API hands back.
//
// The struct behind it is transcribed from somebody else's header, so the string
// inside is NUL terminated rather than sized. Reading the whole array would put
// the padding into an address and the set of allowed targets would carry an entry
// nothing can match.
func TestATextFromTheApiStopsAtItsTerminator(t *testing.T) {
	padded := make([]byte, 16)
	copy(padded, "1.1.1.1")
	if got := cstring(padded); got != "1.1.1.1" {
		t.Errorf("a padded address read as %q", got)
	}

	// No terminator at all is the shape that would read past the end if this
	// were written with an index rather than a range.
	full := []byte("192.168.001.001x")
	if got := cstring(full); got != string(full) {
		t.Errorf("an array with no terminator read as %q", got)
	}
	if got := cstring(nil); got != "" {
		t.Errorf("an empty array read as %q", got)
	}
}

// TestTheRegistryWalkAnswersOrSaysWhy is a property, for the same reason the
// enumeration test is: this reads the machine it runs on.
//
// What has to hold everywhere is that it never invents an entry. Anything it
// returns goes into the set of places this run may connect to, so a value that is
// not an address would be a hole in inviolable rule 16 rather than an untidy
// list.
func TestTheRegistryWalkAnswersOrSaysWhy(t *testing.T) {
	found, err := registryResolvers()
	if err != nil && err.Error() == "" {
		t.Fatal("the registry walk failed and said nothing about why")
	}
	for _, resolver := range found {
		if strings.TrimSpace(resolver) != resolver || resolver == "" {
			t.Errorf("%q came out of the registry with whitespace or empty", resolver)
		}
	}
	t.Logf("the registry on this machine records %d resolver entries", len(found))
}

// TestAKeyThatIsNotThereIsNotAnError covers the branch a machine with no IPv6
// stack takes every run.
//
// Windows keeps IPv4 and IPv6 resolvers in separate service branches, and a
// machine with nothing configured for IPv6 simply has no Tcpip6 key. Treating
// that as a failure would report "this machine's resolvers could not be read" on
// an ordinary laptop.
func TestAKeyThatIsNotThereIsNotAnError(t *testing.T) {
	if got := valuesUnder(`SYSTEM\CurrentControlSet\Services\NoSuchServiceHere\Parameters`); got != nil {
		t.Errorf("a key that does not exist produced %v", got)
	}
	if _, err := openKey(`SYSTEM\CurrentControlSet\Services\NoSuchServiceHere\Parameters`); err == nil {
		t.Error("a key that does not exist was opened, so this test proves nothing")
	}
}
