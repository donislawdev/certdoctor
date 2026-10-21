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

// noLinks is a resolver for a filesystem with no symbolic links on it.
func noLinks(path string) (string, error) { return path, nil }

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
	found := Binaries(source, noLinks, []string{firstOnPath, gitMingwDir}, "git.exe", "git")

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
	found := Binaries(source, noLinks, []string{hostSpelling(`C:\Windows\system32`), hostSpelling(`C:\WINDOWS\system32`)}, "curl.exe")
	if len(found) != 1 {
		t.Fatalf("found %d entries for one binary: %v", len(found), found)
	}
}

// THE WALK ITSELF KEEPS EVERY SPELLING, WITH THE NAME IT CARRIES - ADR112. Two
// spellings of one file are two hits, in PATH order, so a probe telling them apart
// by more than where they lead can still ask which command reaches which.
func TestTheWalkKeepsEverySpellingWithItsName(t *testing.T) {
	system := hostSpelling(`C:\Windows\system32\curl.exe`)
	source := sourceOf(map[string]string{system: "MZ", toolsGitExe: "MZ"}, toolsGitDir)
	hits := OnPath(source, []string{hostSpelling(`C:\Windows\system32`), hostSpelling(`C:\WINDOWS\system32`), toolsDir},
		"curl.exe", "git.exe", "git")
	want := []Hit{
		{Path: system, Name: "curl.exe"},
		{Path: hostSpelling(`C:\WINDOWS\system32\curl.exe`), Name: "curl.exe"},
		{Path: toolsGitExe, Name: "git.exe"},
	}
	if len(hits) != len(want) {
		t.Fatalf("got %v, want %v", hits, want)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Errorf("hit %d is %v, want %v", i, hits[i], want[i])
		}
	}
}

// AN ALIAS TAKES ITS PLACE ON PATH, AND ONLY A FILE THAT GAVE NO BYTE IS ASKED
// ABOUT - ADR112. A readable file is never taken for an alias, a path the alias
// port refuses or names no package for is no hit, and OnPath asks nothing.
func TestTheWalkKeepsAnAliasWherePathReachesIt(t *testing.T) {
	apps := hostSpelling(`C:\Users\jdoe\AppData\Local\Microsoft\WindowsApps`)
	python := hostSpelling(`C:\Python313\python.exe`)
	source := sourceOf(map[string]string{python: "MZ"})
	var asked []string
	alias := func(path string) (string, error) {
		asked = append(asked, path)
		switch filepath.Base(path) {
		case "python.exe":
			return "PythonSoftwareFoundation.PythonManager_qbz5n2kfra8p0", nil
		case "pip.exe":
			return "", nil
		}
		return "", errors.New("not an alias")
	}
	dirs := []string{apps, filepath.Dir(python)}
	hits := OnPathOrAliases(source, alias, dirs, "python.exe", "python3.exe", "pip.exe")
	want := []Hit{
		{Path: filepath.Join(apps, "python.exe"), Name: "python.exe", Package: "PythonSoftwareFoundation.PythonManager_qbz5n2kfra8p0"},
		{Path: python, Name: "python.exe"},
	}
	if len(hits) != len(want) || hits[0] != want[0] || hits[1] != want[1] {
		t.Errorf("got %v, want %v", hits, want)
	}
	for _, path := range asked {
		if path == python {
			t.Errorf("a readable file was asked about as an alias")
		}
	}
	if len(asked) != 5 {
		t.Errorf("asked about %v", asked)
	}
	if hits := OnPath(source, dirs, "python.exe"); len(hits) != 1 || hits[0].Path != python {
		t.Errorf("OnPath found %v", hits)
	}
}

// A DIRECTORY IS NOT A BINARY, AND OPENING IT DOES NOT SAY SO. Measured on both
// platforms 2026-09-02: os.Open succeeds on a directory and only the read tells
// them apart. Without the byte, a directory named git inside a PATH entry would
// enter the trust matrix as an installation - a claim about a store nobody has,
// which is what ADR48 part 2 refuses for Java.
func TestADirectoryOnPathIsNotABinary(t *testing.T) {
	source := sourceOf(map[string]string{toolsGitExe: "MZ"}, toolsGitDir)

	found := Binaries(source, noLinks, []string{toolsDir}, "git", "git.exe")
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
	if found := Binaries(source, noLinks, []string{toolsDir}, "git.exe"); len(found) != 0 {
		t.Errorf("a zero-byte file was reported as a binary: %v", found)
	}
}

// AN EMPTY PATH FINDS NOTHING RATHER THAN GUESSING SOMEWHERE, which is what the
// entry point already reports by handing in no directories at all.
func TestNoDirectoriesFindNoBinaries(t *testing.T) {
	source := sourceOf(map[string]string{toolsGitExe: "MZ"})
	if found := Binaries(source, noLinks, nil, "git.exe"); len(found) != 0 {
		t.Errorf("an empty PATH still produced %v", found)
	}
}

// READABLE ASKS WHAT THE WALK ASKS - ADR112. The python probe checks the
// interpreter a script or a launcher names, a file the walk never found itself,
// and it has to refuse what the walk refuses: an empty file, a directory, and a
// file that is not there.
func TestReadableRefusesWhatTheWalkRefuses(t *testing.T) {
	source := sourceOf(map[string]string{toolsGitExe: "MZ", mingwCurl: ""}, toolsGitDir)
	for path, want := range map[string]bool{
		toolsGitExe: true,
		mingwCurl:   false,
		toolsGitDir: false,
		gitCmdExe:   false,
	} {
		if got := Readable(source, path); got != want {
			t.Errorf("Readable(%q) = %v, want %v", path, got, want)
		}
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

// ONE FILE REACHED THROUGH A LINKED DIRECTORY IS ONE BINARY - OBS170. Measured
// 2026-10-19 in debian:stable-slim: /bin is a link to usr/bin, PATH carries
// both, and git and curl each came out as two rows describing one file.
func TestOneFileReachedThroughALinkedDirectoryIsFoundOnce(t *testing.T) {
	usrBin, bin := hostSpelling(`\usr\bin`), hostSpelling(`\bin`)
	source := sourceOf(map[string]string{
		filepath.Join(usrBin, "git"): "\x7fELF",
		filepath.Join(bin, "git"):    "\x7fELF",
	})
	resolve := func(path string) (string, error) {
		if filepath.Dir(path) == bin {
			return filepath.Join(usrBin, filepath.Base(path)), nil
		}
		return path, nil
	}

	found := Binaries(source, resolve, []string{usrBin, bin}, "git")
	if len(found) != 1 {
		t.Fatalf("found %d entries for one binary reached through a linked directory: %v", len(found), found)
	}
	// THE ROW KEEPS THE SPELLING PATH REACHED FIRST, because that is the file a
	// typed command runs and the one a person can check against.
	if want := filepath.Join(usrBin, "git"); found[0] != want {
		t.Errorf("the row names %q, and PATH reaches %q first", found[0], want)
	}
}

// TWO DIFFERENT FILES STAY TWO WHEN THE RESOLVER FAILS. A failure is a reason
// to fall back to the path as written, never a licence to merge rows - one
// binary shown twice is visible, two binaries shown as one is not.
func TestAResolverThatFailsKeepsEveryBinary(t *testing.T) {
	source := sourceOf(map[string]string{gitCmdExe: "MZ", gitMingwExe: "MZ"})
	failing := func(string) (string, error) { return "", errors.New("cannot resolve") }
	if found := Binaries(source, failing, []string{gitCmdDir, gitMingwDir}, "git.exe"); len(found) != 2 {
		t.Errorf("found %v, want both binaries when nothing could be resolved", found)
	}
}

// THE RESOLVER IS ASKED ONLY ABOUT A FILE THAT OPENED. The open port refuses a
// path that leaves this machine by its text alone, and resolving first would
// follow links on exactly that path - the cost docs/14 section 3a measured.
func TestTheResolverIsAskedOnlyAboutFilesThatOpened(t *testing.T) {
	source := sourceOf(map[string]string{toolsGitExe: "MZ"})
	var asked []string
	resolve := func(path string) (string, error) {
		asked = append(asked, path)
		return path, nil
	}

	Binaries(source, resolve, []string{gitCmdDir, toolsDir}, "git.exe")
	if len(asked) != 1 || asked[0] != toolsGitExe {
		t.Errorf("the resolver was asked about %v, and only %s opened", asked, toolsGitExe)
	}
}
