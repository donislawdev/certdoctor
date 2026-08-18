package file

import (
	"io"
	"os"
	"path/filepath"
)

// Live returns the real plumbing behind the two ports in this package.
//
// THIS IS THE ONLY FILE IN THIS PACKAGE THAT TOUCHES A DISK, and the package
// comment in file.go says the rest of it does not. Both statements have to stay
// true together: the rule lives there and is a pure function of what it is
// handed, the plumbing lives here and is named on the file allowlist in
// reach_test.go. Keeping them apart is what makes the number of places in this
// program able to turn a path into bytes something a person can count.
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

// liveSource opens a path for reading and nothing else.
//
// It hands back the handle without reading a byte, because the cap on how much
// is read belongs to Guarded - the limit is per parser and arrives as a
// parameter, so this function has no honest number of its own.
func liveSource(path string) (io.ReadCloser, error) { return os.Open(path) }

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
	entries, err := os.ReadDir(path)
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
