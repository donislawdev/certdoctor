package probe

import (
	"io"
	"path/filepath"
	"strings"
)

// Binaries walks every directory on PATH and returns every file there carrying
// one of names, in the order a typed command would search them.
//
// THIS IS A SEARCH AND NOT A SELECTION - ADR50. Taking the first hit would be
// naming a favourite, which is what ADR48 part 4 forbids. Measured on this
// machine: walking all of PATH finds TWO curl.exe and TWO git.exe, while taking
// the first of either would report one and hide the other.
//
// IT LIVES HERE RATHER THAN IN EACH PROBE, and that is OBS50 answered before it
// happened rather than after. Two probes ask "which binaries of this name does
// this machine have", and this tree has four measured cases of a rule copied
// into a second home while somebody was tidying - each time a mutation entry
// aimed at one copy quietly stopped proving anything about the other.
//
// IT LOOKS FOR A FILE AND NOT FOR A NAME. On Windows "curl" and "git" can both
// be PowerShell aliases, so a name that resolves proves nothing about a binary.
//
// AND A FILE HAS TO GIVE UP ONE BYTE, WHICH IS MEASURED RATHER THAN CAREFUL.
// Opening a DIRECTORY succeeds on both platforms - measured 2026-09-02: a
// directory named git opened without error on Windows and on Linux alike, and
// only the read told them apart, with "Incorrect function" and "is a directory"
// respectively. Without this a directory named git in a PATH entry would enter
// the trust matrix as an installation, which is a claim about a store nobody
// has. An empty file is refused by the same line and deliberately: nothing
// executes a zero-byte binary.
func Binaries(open func(string) (io.ReadCloser, error), pathDirs []string, names ...string) []string {
	var found []string
	seen := map[string]bool{}

	for _, dir := range pathDirs {
		for _, name := range names {
			path := filepath.Clean(filepath.Join(dir, name))
			key := PathKey(path)
			if seen[key] {
				continue
			}
			if !readableFile(open, path) {
				continue
			}
			seen[key] = true
			found = append(found, path)
		}
	}
	return found
}

// PathKey folds a path into the key this program tells two files apart by.
//
// DEDUPLICATION IS CASE INSENSITIVE, AND THIS WAS A MEASURED DEFECT rather than
// a precaution. PATH on this machine carries system32 in two spellings -
// Windows and WINDOWS - and filepath.Clean does not fold case, so the first run
// of the curl probe reported ONE binary as TWO stores and the verdict counted
// ten where there are nine.
//
// THE COST, NAMED: on a case-sensitive filesystem two genuinely different files
// whose names differ only by case would be folded into one. That is a pathology
// nobody ships, while mixed spellings in a Windows PATH are measured and here.
func PathKey(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

// readableFile reports whether this path is a file this program can read from.
func readableFile(open func(string) (io.ReadCloser, error), path string) bool {
	reader, err := open(path)
	if err != nil {
		return false
	}
	defer func() { _ = reader.Close() }()
	// ReadFull RATHER THAN Read, because io.Reader is allowed to return zero
	// bytes and no error, and a port that wraps another reader may well do it.
	// The question here is whether a byte can be had at all, not what one call
	// happened to return.
	one := make([]byte, 1)
	_, err = io.ReadFull(reader, one)
	return err == nil
}
