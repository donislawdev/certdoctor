package file

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Live returns the real plumbing behind the two ports in this package.
//
// THIS IS THE ONLY FILE IN THIS PACKAGE THAT TOUCHES A DISK, with its Windows
// half in live_windows.go, and the package comment in file.go says the rest of
// it does not. Both statements have to stay true together: the rule lives there
// and is a pure function of what it is handed, the plumbing lives here and is
// named on the file allowlist in reach_test.go. Keeping them apart is what makes
// the number of places in this program able to turn a path into bytes something
// a person can count.
//
// NEITHER FUNCTION CHECKS ANYTHING. That is deliberate and it is the whole
// shape: Guarded judges the path as written, resolves links, judges what they
// led to and only then opens under a size cap - in that order, for reasons
// written where the order lives. A check repeated here would be a second opinion
// that can disagree with the first, and the two would drift.
func Live() (Source, Resolve) {
	return liveSource, liveResolve
}

// LiveList is the directory listing port, handed out separately because only L5
// needs it and the two ports above are enough for everything else.
func LiveList() List { return liveList }

// LiveFiles is the same port for the other half of a directory - what is in it
// that is not a directory. L5 needs it for the certificate directories a Linux
// distribution keeps beside its bundle - ADR104.
func LiveFiles() List { return liveFiles }

// LiveAppAlias is the port for Windows' app execution aliases, which Source
// cannot open - ADR112. Its plumbing is in live_windows.go, and elsewhere it
// refuses every path.
func LiveAppAlias() AppAlias { return liveAppAlias }

// liveSource opens a path for reading and nothing else.
//
// It hands back the handle without reading a byte, because the cap on how much
// is read belongs to Guarded - the limit is per parser and arrives as a
// parameter, so this function has no honest number of its own.
//
// ONLY A REGULAR FILE IS HANDED BACK - ADR114. A limit on bytes does not bound
// TIME: a FIFO with no writer blocks in the open itself on Linux, a terminal
// device blocks in the first read, and both can be named by a variable or a
// PATH entry this program follows. So the path is asked what it names before
// it is opened - see expect.
func liveSource(path string) (io.ReadCloser, error) {
	if err := expect(path, fs.FileMode.IsRegular); err != nil {
		return nil, err
	}
	return os.Open(path)
}

// expect refuses a path that does not name what want accepts, before anything
// opens it.
//
// THE QUESTION IS ASKED OF THE PATH, NOT OF A HANDLE, AND THAT LEAVES A WINDOW:
// a path swapped for a FIFO between this and the open still blocks the open.
// An open that cannot wait - O_NONBLOCK - would close it, and os.OpenFile is
// the one call able to ask for that, which the write guard counts as a write
// because it can obtain a handle to write with whatever its flags say. Whoever
// can swap a file at that moment, in a directory this program reads, already
// owns that directory. What this cannot bound either is a slow filesystem behind
// a regular file - no stopwatch interrupts a read the kernel is still serving.
func expect(path string, want func(fs.FileMode) bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !want(info.Mode()) {
		return &NotRegular{Path: path, Mode: info.Mode()}
	}
	return nil
}

// liveResolve follows symbolic links to the path they actually name.
//
// IT IS WHY THE SECOND PORT EXISTS AT ALL, and the case is measured rather than
// imagined: /etc/resolv.conf is a link in WSL and on any systemd machine, and a
// link whose target sits under a mount from another host is a remote path
// wearing a local name.
//
// A path that does not exist comes back as an error wrapping fs.ErrNotExist,
// which Guarded passes on rather than refusing - "your configuration names a
// file that is not there" is a fact about the machine being diagnosed.
func liveResolve(path string) (string, error) { return filepath.EvalSymlinks(path) }

// liveList names the directories directly inside one directory.
//
// IT IS A THIRD PIECE OF PLUMBING AND IT LIVES HERE FOR THE SAME REASON AS THE
// OTHER TWO: this file is the one place in this package allowed to touch a disk,
// and the file allowlist in reach_test.go names it. L5 needs it because Java
// installations are grouped under a parent whose children are versions nobody
// can predict - measured, six of them on this machine - and a probe may not
// reach for the filesystem behind the port.
//
// IT RETURNS DIRECTORIES ONLY. A file sitting beside the installations is not a
// candidate, and filtering here keeps the caller from having to know what a
// directory entry is.
func liveList(path string) ([]string, error) {
	entries, err := readDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, filepath.Join(path, entry.Name()))
		}
	}
	return names, nil
}

// liveFiles names every entry directly inside one directory that is not itself
// a directory - files and symbolic links alike.
//
// A LINK IS NAMED WITHOUT BEING FOLLOWED. Following it is a filesystem operation
// on wherever it points, and judging where it points before touching it is
// Guarded's job - so the caller opens each name through that port, the same way
// it opens everything else.
func liveFiles(path string) ([]string, error) {
	entries, err := readDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, filepath.Join(path, entry.Name()))
		}
	}
	return names, nil
}

// listingCeiling is the most entries one directory may hold before it is
// refused rather than listed - ADR114.
//
// IT BOUNDS THE LISTING, NOT WHAT A CALLER ACCEPTS. The caller's own limit -
// 4096 files in a certificate directory - used to be applied to a list this
// file had already read in full, sorted and copied. Sixty-five thousand is far
// past any directory this program is pointed at, an assessment and not a
// measurement, and it keeps a directory of millions from being held in memory
// to be refused afterwards.
const listingCeiling = 1 << 16

// listingBatch is how many entries are read at a time.
const listingBatch = 512

// readDir is os.ReadDir with the ceiling, and with the question liveSource asks.
//
// THE PATH IS ASKED WHAT IT NAMES BEFORE IT IS OPENED, for the reason liveSource
// gives: a directory named by somebody's variable can be a pipe.
// THE ORDER IS BY NAME, as os.ReadDir gives it, because callers turn it into
// rows and two runs on one machine have to print them alike.
func readDir(path string) ([]os.DirEntry, error) { return readDirWithin(path, listingCeiling) }

// readDirWithin is readDir with the ceiling as a parameter, so a test can reach
// it with three files rather than sixty-five thousand.
func readDirWithin(path string, ceiling int) ([]os.DirEntry, error) {
	if err := expect(path, fs.FileMode.IsDir); err != nil {
		return nil, err
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	var entries []os.DirEntry
	for {
		batch, err := dir.ReadDir(listingBatch)
		entries = append(entries, batch...)
		if len(entries) > ceiling {
			return nil, fmt.Errorf("%s holds more than %d entries, so it was not listed", path, ceiling)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}
