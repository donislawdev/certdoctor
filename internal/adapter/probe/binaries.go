package probe

import (
	"io"
	"path/filepath"
	"runtime"
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

	for _, hit := range OnPath(open, pathDirs, names...) {
		key := IdentityKey(resolve, hit.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		found = append(found, hit.Path)
	}
	return found
}

// Hit is one file on PATH carrying one of the names a probe asked for.
type Hit struct {
	// Path is the file as PATH reached it, the spelling a typed command runs.
	Path string
	// Name is which of the names it carries.
	Name string
	// Package is the package an app execution alias belongs to, and empty for a
	// file - see OnPathOrAliases.
	Package string
}

// OnPath is the walk Binaries consumes, without its folding: every readable file
// on PATH carrying one of names, in the order a typed command would search them,
// with two spellings of one file kept as two hits.
//
// IT EXISTS FOR THE PROBE THAT TELLS TWO FILES APART BY MORE THAN WHERE THEY
// LEAD - ADR112. A virtual environment's python is a link to the interpreter it
// was made from and is a different environment all the same, and which command
// name reaches which interpreter is part of that probe's answer. The walk stays
// here, once, for the reason Binaries gives.
func OnPath(open func(string) (io.ReadCloser, error), pathDirs []string, names ...string) []Hit {
	return walk(open, nil, pathDirs, names)
}

// OnPathOrAliases is OnPath that also keeps Windows' app execution aliases, in
// the place PATH reaches them - ADR112, decided by the owner 2026-10-21.
//
// AN ALIAS IS A FILE NOTHING CAN READ, so OnPath leaves it out, and on a machine
// where Python came from the Microsoft Store it is the only python on PATH. alias
// is asked only about a path that gave up no byte, and names the package behind
// it - which program it starts is for the probe to learn, because the alias names
// a file inside a package this program may not read. Every other probe keeps
// OnPath: none of them was measured on an alias.
func OnPathOrAliases(open func(string) (io.ReadCloser, error), alias func(string) (string, error), pathDirs []string,
	names ...string) []Hit {
	return walk(open, alias, pathDirs, names)
}

// walk is the one walk both of them make. A nil alias asks nothing.
func walk(open func(string) (io.ReadCloser, error), alias func(string) (string, error), pathDirs, names []string) []Hit {
	var hits []Hit
	for _, dir := range pathDirs {
		for _, name := range names {
			path := filepath.Clean(filepath.Join(dir, name))
			if readableFile(open, path) {
				hits = append(hits, Hit{Path: path, Name: name})
				continue
			}
			if alias == nil {
				continue
			}
			// A package with no name would make the hit look like a file.
			if pkg, err := alias(path); err == nil && pkg != "" {
				hits = append(hits, Hit{Path: path, Name: name, Package: pkg})
			}
		}
	}
	return hits
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
// CASE IS FOLDED ONLY WHERE THE USUAL FILESYSTEM FOLDS IT - ADR114 R15. Windows
// treats file and directory names as case-insensitive (read 2026-10-26 at
// https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity), and APFS as
// macOS formats a volume does too - the case-sensitive one is a variant to be
// chosen (read the same day at
// https://support.apple.com/guide/disk-utility/file-system-formats-dsku19ed921c/mac).
// Elsewhere two names differing only by case are two files, and folding them
// hid one of them.
//
// THE COST, NAMED, EACH WAY. A case-sensitive volume on a Mac, or a directory
// made case-sensitive on Windows, still folds. A case-insensitive mount on Linux
// - an NTFS drive under WSL is one, by the same Microsoft page - does not, so
// one file reached by two spellings shows as two rows there. Both cost a row
// that can be seen, never a file that cannot.
func PathKey(path string) string { return pathKey(path, foldsCase) }

// foldsCase says whether this platform's usual filesystem folds case.
var foldsCase = runtime.GOOS == "windows" || runtime.GOOS == "darwin"

// pathKey is PathKey with the folding as a parameter, so both rules are
// asserted on every platform.
func pathKey(path string, fold bool) string {
	path = filepath.Clean(path)
	if fold {
		return strings.ToLower(path)
	}
	return path
}

// Readable reports whether this path is a file this program can read from - the
// test every hit of the walk passed, for a probe checking a file the walk did not
// find itself, such as the interpreter a script names.
func Readable(open func(string) (io.ReadCloser, error), path string) bool {
	return readableFile(open, path)
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
