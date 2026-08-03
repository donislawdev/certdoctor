package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// asciiAllowlist names the files allowed to carry a character outside ASCII.
//
// Exactly two, and both for one reason: the appearance dictionary declares the
// status glyphs and its test compares against them. That is the only place in
// this repository where a character outside ASCII is the CONTENT rather than
// decoration.
var asciiAllowlist = map[string]bool{
	"internal/adapter/render/appearance.go":      true,
	"internal/adapter/render/appearance_test.go": true,
}

// TestTheSourceIsASCIIOutsideTheAppearanceDictionary is the guard on a
// convention this repository followed by habit until it stopped.
//
// TWO SEPARATE COSTS, AND THE SECOND IS THE ONE THAT BITES. Decoration in a
// comment is harmless in Go and not harmless everywhere: the same habit put a
// character outside ASCII into a PowerShell script in the tooling directory, and
// PowerShell reading a file without a byte order mark can turn that into a parse
// error five lines further down - a failure that points at the wrong place. The
// second cost is worse and is what this guard is really for: an INVISIBLE
// character in source is one nobody reviewing it can see. A zero width space or
// a bidirectional override changes what a line means to a reader without
// changing what it means to the compiler, and this program exists to be
// believed.
//
// The appearance guard does not cover this. It reads string literals out of the
// syntax tree, so it never sees a comment - which is where every character this
// caught was living.
func TestTheSourceIsASCIIOutsideTheAppearanceDictionary(t *testing.T) {
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("the module could not be read: %v", err)
	}
	requireNoViolations(t, checkASCII(tr.root, tr.files), "a character outside ASCII")
}

// TestTheASCIIGuardCanFail is the canary. A scanner that finds nothing looks
// exactly like a scanner that reads nothing, and the difference is the whole
// value of the check above.
func TestTheASCIIGuardCanFail(t *testing.T) {
	planted := []sourceFile{{rel: filepath.Join("testdata", "appearance_violation.go")}}
	requireViolation(t, checkASCII(".", planted), "outside ASCII")
}

// TestTheASCIIAllowlistNamesFilesThatExist refuses an entry pointing at a file
// that has been renamed or removed. An allowlist guarding nothing reads as
// protection, which is worse than no allowlist at all.
func TestTheASCIIAllowlistNamesFilesThatExist(t *testing.T) {
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("the module could not be read: %v", err)
	}
	for name := range asciiAllowlist {
		if _, err := os.Stat(filepath.Join(tr.root, filepath.FromSlash(name))); err != nil {
			t.Errorf("the allowlist names %s, which is not in the tree: %v", name, err)
		}
	}
}

// checkASCII reports the first character outside ASCII on each line of each file
// that is not on the allowlist.
//
// It reads the bytes rather than walking the syntax tree, because comments are
// where this goes wrong and a syntax tree has already thrown them away.
func checkASCII(root string, files []sourceFile) []Violation {
	var violations []Violation
	for _, sf := range files {
		if asciiAllowlist[sf.rel] {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(sf.rel)))
		if err != nil {
			violations = append(violations, Violation{sf.rel, 0,
				fmt.Sprintf("could not be read, so nothing is known about it: %v", err)})
			continue
		}
		violations = append(violations, nonASCIIIn(sf.rel, string(content))...)
	}
	return sortViolations(violations)
}

// nonASCIIIn reports one violation per line, naming the character by code point
// rather than printing it. Printing it would put the thing being complained
// about into the complaint, where it is just as invisible.
func nonASCIIIn(rel, content string) []Violation {
	var violations []Violation
	for number, line := range strings.Split(content, "\n") {
		for at, r := range line {
			if r < utf8.RuneSelf {
				continue
			}
			violations = append(violations, Violation{rel, number + 1, fmt.Sprintf(
				"column %d carries %U, which is outside ASCII - see the allowlist in ascii_test.go", at+1, r)})
			break
		}
	}
	return violations
}
