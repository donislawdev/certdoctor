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
//
// ONE FILE REACHED THROUGH TWO DIRECTORIES IS ONE BINARY - OBS170, measured
// 2026-10-19 in debian:stable-slim: /bin is a link to usr/bin, PATH names both,
// and every git and curl came out twice. resolve tells them apart by where the
// file really is, and the row keeps the spelling PATH reached first, because
// that is the one a typed command runs.
//
// THE FILE IS OPENED BEFORE ITS PATH IS RESOLVED, AND THE ORDER IS THE POINT.
// open is the guarded port, which judges a path by its text before touching the
// filesystem and refuses one that leaves this machine. Resolving first would
// follow a link on exactly such a path - the cost docs/14 section 3a measured
// as twenty-one seconds on one UNC name.
func Binaries(open func(string) (io.ReadCloser, error), resolve func(string) (string, error), pathDirs []string, names ...string) []string {
	var found []string
	seen := map[string]bool{}

	for _, dir := range pathDirs {
		for _, name := range names {
			path := filepath.Clean(filepath.Join(dir, name))
			if !readableFile(open, path) {
				continue
			}
			key := IdentityKey(resolve, path)
			if seen[key] {
				continue
			}
			seen[key] = true
			found = append(found, path)
		}
	}
	return found
}

// IdentityKey is what two paths are told apart by: the file or directory a
// path really names, folded the way PathKey folds it. The Java probe asks it
// about installation roots, so one rule decides "the same thing" for every
// runtime - a second copy is the shape OBS50 has measured four times.
func IdentityKey(resolve func(string) (string, error), path string) string {
	return PathKey(Resolved(resolve, path))
}

// Resolved is the path a link leads to, or the path itself when it cannot be
// resolved.
//
// A RESOLVER THAT FAILS OR IS MISSING FALLS BACK TO THE PATH AS WRITTEN. The
// worst that does is show one binary twice, which is visible, rather than merge
// two different binaries into one row, which is not.
func Resolved(resolve func(string) (string, error), path string) string {
	if resolve != nil {
		if real, err := resolve(path); err == nil && real != "" {
			return real
		}
	}
	return path
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
