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

// hostSpelling rewrites a Windows-spelled fixture path into the separator the
// platform running this test actually produces.
//
// WITHOUT IT THIS PACKAGE PASSED ON ONE PLATFORM AND FAILED ON TWO, and nobody
// saw it because CI had been red since August for an unrelated reason - an
// expired explanation that outlived its truth. Measured 2026-09-02 in a linux
// container: a fixture stored under "c:\program files\git\cmd\git.exe" is looked
// up as "c:\program files\git\cmd/git.exe", because filepath.Join puts the
// platform separator there and filepath.Clean does not treat a backslash as a
// separator anywhere but Windows. Twenty tests in four packages failed on it.
//
// THE FIXTURES STAY WINDOWS-SPELLED AND THAT IS THE POINT. These probes are
// about Windows installations - C:\Program Files\Git is the machine they
// describe - so respelling the fixtures as a Linux disk would test a different
// machine and quietly delete the case this file exists for. What was wrong is
// the FAKE: it stands in for a Windows filesystem, and a Windows filesystem
// treats both separators as one. Modelling that is a repair, not a workaround.
//
// IT IS NOT PathKey AND MUST NOT BECOME IT - OBS48, already caught once in this
// very function. The fake keeps a rule of its own so that a mutation stopping
// the code under test from folding paths does not stop the fake folding them
// too, which is how both sides moved together and the test stayed green.
func hostSpelling(path string) string {
	return strings.ReplaceAll(path, `\`, string(filepath.Separator))
}

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
// The Windows tree these fixtures describe, spelled for the host. Only the
// separator follows the platform - the shape stays Windows, because that is the
// machine these probes are about.
var (
	gitCmdDir   = hostSpelling(`C:\Program Files\Git\cmd`)
	gitCmdExe   = hostSpelling(`C:\Program Files\Git\cmd\git.exe`)
	gitMingwDir = hostSpelling(`C:\Program Files\Git\mingw64\bin`)
	gitMingwExe = hostSpelling(`C:\Program Files\Git\mingw64\bin\git.exe`)
	mingwCurl   = hostSpelling(`C:\Program Files\Git\mingw64\bin\curl.exe`)
	toolsDir    = hostSpelling(`C:\tools`)
	toolsGitExe = hostSpelling(`C:\tools\git.exe`)
	toolsGitDir = hostSpelling(`C:\tools\git`)
)

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
		gitCmdExe:   "MZ",
		gitMingwExe: "MZ",
		mingwCurl:   "MZ",
	})
	firstOnPath := gitCmdDir
	found := Binaries(source, []string{firstOnPath, gitMingwDir}, "git.exe", "git")

	if len(found) != 2 {
		t.Fatalf("found %d git binaries, want 2: %v", len(found), found)
	}
	// THE ORDER IS THE ORDER PATH SEARCHES, because that is the order a typed
	// command resolves in and the only one a person can check against.
	//
	// THE DIRECTORY IS MATCHED AS A PREFIX RATHER THAN THROUGH filepath.Dir.
	// Dir splits on the separator of the platform running the test, and these
	// fixtures are Windows-spelled on purpose, so off Windows the whole path is
	// a single element and Base would answer with all of it - which is how this
	// line passed here and failed on two other platforms.
	if !strings.HasPrefix(found[0], firstOnPath) {
		t.Errorf("the first hit is %q, and PATH names %q first", found[0], firstOnPath)
	}
}

// THE DEFECT THIS TEST EXISTS FOR WAS MEASURED, NOT IMAGINED. PATH on this
// machine carries system32 in two spellings, so the first version of this walk
// reported ONE binary as TWO stores and the verdict counted ten where there are
// nine. Caught by running the binary, never by a test.
func TestOneFileReachedByTwoSpellingsIsFoundOnce(t *testing.T) {
	source := sourceOf(map[string]string{hostSpelling(`C:\Windows\system32\curl.exe`): "MZ"})
	found := Binaries(source, []string{hostSpelling(`C:\Windows\system32`), hostSpelling(`C:\WINDOWS\system32`)}, "curl.exe")
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
	source := sourceOf(map[string]string{toolsGitExe: "MZ"}, toolsGitDir)

	found := Binaries(source, []string{toolsDir}, "git", "git.exe")
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
	source := sourceOf(map[string]string{toolsGitExe: ""})
	if found := Binaries(source, []string{toolsDir}, "git.exe"); len(found) != 0 {
		t.Errorf("a zero-byte file was reported as a binary: %v", found)
	}
}

// AN EMPTY PATH FINDS NOTHING RATHER THAN GUESSING SOMEWHERE, which is what the
// entry point already reports by handing in no directories at all.
func TestNoDirectoriesFindNoBinaries(t *testing.T) {
	source := sourceOf(map[string]string{toolsGitExe: "MZ"})
	if found := Binaries(source, nil, "git.exe"); len(found) != 0 {
		t.Errorf("an empty PATH still produced %v", found)
	}
}

// PathKey IS THE ONE PLACE THIS PROGRAM DECIDES TWO PATHS ARE THE SAME FILE, so
// both halves of that decision are asserted here rather than through a caller.
// THE PATHS GO THROUGH hostSpelling AND THE CLEANING HALF IS WHY. PathKey leans
// on filepath.Clean to drop a "." element, and Clean only sees one when the
// separators are the ones this platform uses - off Windows a backslash is an
// ordinary character in a filename, so the whole string is one element and there
// is nothing to clean. Spelled for the host, both halves of the decision are
// asserted everywhere instead of on Windows alone.
func TestPathKeyCleansAndFoldsCase(t *testing.T) {
	if PathKey(hostSpelling(`C:\Windows\.\system32\curl.exe`)) != PathKey(hostSpelling(`C:\WINDOWS\system32\curl.exe`)) {
		t.Error("two spellings of one file produced two keys")
	}
	if PathKey(hostSpelling(`C:\tools\git.exe`)) == PathKey(hostSpelling(`C:\tools\git2.exe`)) {
		t.Error("two different files produced one key")
	}
}
