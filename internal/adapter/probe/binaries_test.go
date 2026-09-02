package probe

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// refusing is what a DIRECTORY looks like through the file port: it opens, and
// then it will not give up a byte.
//
// MEASURED ON BOTH PLATFORMS 2026-09-02 rather than assumed. A directory named
// git opened without error on Windows and on Linux alike; the read failed with
// "Incorrect function" and "is a directory" respectively. Two different
// sentences in two different languages, which is exactly why the code asks
// whether a byte arrived rather than what the failure said - inviolable rule 19.
type refusing struct{ err error }

func (r refusing) Read([]byte) (int, error) { return 0, r.err }
func (r refusing) Close() error             { return nil }

// sourceOf builds the file port from a map of path to content. A path mapped to
// the empty string is an empty FILE, and a path listed in dirs is a DIRECTORY.
//
// IT FOLDS CASE WITH ITS OWN RULE AND NOT WITH PathKey, AND THAT IS THE WHOLE
// POINT OF THIS FUNCTION - OBS48, caught here by the mutation register. This
// fake is standing in for a WINDOWS FILESYSTEM, which does not distinguish
// C:\Windows from C:\WINDOWS. That is a fact about somebody else's disk;
// PathKey is our rule for deciding two paths are one file. They are spelled the
// same and they are not the same thing, and using PathKey here made the
// function under test its own oracle: a mutation that stopped it folding case
// stopped the FAKE folding case too, so both sides moved together and the test
// stayed green while the rule it defends was gone.
func sourceOf(files map[string]string, dirs ...string) func(string) (io.ReadCloser, error) {
	onWindows := func(path string) string { return strings.ToLower(filepath.Clean(path)) }

	cleaned := map[string]string{}
	for path, body := range files {
		cleaned[onWindows(path)] = body
	}
	isDir := map[string]bool{}
	for _, dir := range dirs {
		isDir[onWindows(dir)] = true
	}
	return func(path string) (io.ReadCloser, error) {
		key := onWindows(path)
		if isDir[key] {
			return refusing{err: errors.New("is a directory")}, nil
		}
		body, ok := cleaned[key]
		if !ok {
			return nil, errors.New("no such file")
		}
		return io.NopCloser(strings.NewReader(body)), nil
	}
}

// EVERY binary ON PATH, NOT THE FIRST ONE - ADR50. Measured 2026-09-02: this
// machine has git.exe in two PATH directories and curl.exe in two others, and
// taking the first of either reports one runtime and hides the other.
func TestEveryBinaryOnPathIsFound(t *testing.T) {
	source := sourceOf(map[string]string{
		`C:\Program Files\Git\cmd\git.exe`:          "MZ",
		`C:\Program Files\Git\mingw64\bin\git.exe`:  "MZ",
		`C:\Program Files\Git\mingw64\bin\curl.exe`: "MZ",
	})
	found := Binaries(source, []string{
		`C:\Program Files\Git\cmd`,
		`C:\Program Files\Git\mingw64\bin`,
	}, "git.exe", "git")

	if len(found) != 2 {
		t.Fatalf("found %d git binaries, want 2: %v", len(found), found)
	}
	// THE ORDER IS THE ORDER PATH SEARCHES, because that is the order a typed
	// command resolves in and the only one a person can check against.
	if filepath.Base(filepath.Dir(found[0])) != "cmd" {
		t.Errorf("the first hit is %q, and PATH names cmd first", found[0])
	}
}

// THE DEFECT THIS TEST EXISTS FOR WAS MEASURED, NOT IMAGINED. PATH on this
// machine carries system32 in two spellings, so the first version of this walk
// reported ONE binary as TWO stores and the verdict counted ten where there are
// nine. Caught by running the binary, never by a test.
func TestOneFileReachedByTwoSpellingsIsFoundOnce(t *testing.T) {
	source := sourceOf(map[string]string{`C:\Windows\system32\curl.exe`: "MZ"})
	found := Binaries(source, []string{`C:\Windows\system32`, `C:\WINDOWS\system32`}, "curl.exe")
	if len(found) != 1 {
		t.Fatalf("found %d entries for one binary: %v", len(found), found)
	}
}

// A DIRECTORY IS NOT A BINARY, AND OPENING IT DOES NOT SAY SO. Measured on both
// platforms 2026-09-02: os.Open succeeds on a directory and only the read tells
// them apart. Without the byte, a directory named git inside a PATH entry would
// enter the trust matrix as an installation - a claim about a store nobody has,
// which is what ADR48 part 2 refuses for Java.
func TestADirectoryOnPathIsNotABinary(t *testing.T) {
	source := sourceOf(map[string]string{`C:\tools\git.exe`: "MZ"}, `C:\tools\git`)

	found := Binaries(source, []string{`C:\tools`}, "git", "git.exe")
	if len(found) != 1 {
		t.Fatalf("found %v, want only the real binary", found)
	}
	if filepath.Base(found[0]) != "git.exe" {
		t.Errorf("the entry found is %q, and the directory is the one that had to be refused", found[0])
	}
}

// AN EMPTY FILE IS REFUSED BY THE SAME LINE AND DELIBERATELY: nothing executes
// a zero-byte binary, and measured 2026-09-02 an empty file reads back as EOF
// on both platforms, exactly like a directory does.
func TestAnEmptyFileIsNotABinary(t *testing.T) {
	source := sourceOf(map[string]string{`C:\tools\git.exe`: ""})
	if found := Binaries(source, []string{`C:\tools`}, "git.exe"); len(found) != 0 {
		t.Errorf("a zero-byte file was reported as a binary: %v", found)
	}
}

// AN EMPTY PATH FINDS NOTHING RATHER THAN GUESSING SOMEWHERE, which is what the
// entry point already reports by handing in no directories at all.
func TestNoDirectoriesFindNoBinaries(t *testing.T) {
	source := sourceOf(map[string]string{`C:\tools\git.exe`: "MZ"})
	if found := Binaries(source, nil, "git.exe"); len(found) != 0 {
		t.Errorf("an empty PATH still produced %v", found)
	}
}

// PathKey IS THE ONE PLACE THIS PROGRAM DECIDES TWO PATHS ARE THE SAME FILE, so
// both halves of that decision are asserted here rather than through a caller.
func TestPathKeyCleansAndFoldsCase(t *testing.T) {
	if PathKey(`C:\Windows\.\system32\curl.exe`) != PathKey(`C:\WINDOWS\system32\curl.exe`) {
		t.Error("two spellings of one file produced two keys")
	}
	if PathKey(`C:\tools\git.exe`) == PathKey(`C:\tools\git2.exe`) {
		t.Error("two different files produced one key")
	}
}
