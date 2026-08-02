// Package output puts a finished report at the path the user named.
//
// This is the only package in certdoctor allowed to create a file, and the
// allowlist in the write guard names exactly one file inside it. That narrowness
// is the point: the promise on the first line of the README is that this tool
// diagnoses and never repairs, and a promise like that survives as long as there
// is exactly one place where writing is possible at all.
//
// Nothing here decides WHERE to write. The path arrives from the command line,
// having been named explicitly by a person. There is no default path, no
// fallback directory and no temporary file anywhere except beside the
// destination.
package output

import (
	"fmt"
	"os"
	"path/filepath"
)

// reportPermissions is what a finished report is created with.
//
// Readable and writable by its owner and nobody else. A report carries internal
// host names, file system paths and user names by design, so the restrictive
// mode is the right default and widening it is the reader's decision to make
// deliberately. On Windows this has little effect, and that is not a reason to
// drop it on the platforms where it does.
const reportPermissions = 0o600

// WriteFile puts data at path, atomically.
//
// The file appears under a temporary name in the destination's own directory
// and is renamed into place only after the bytes are on disk. Two things follow,
// and both matter more than the small cost:
//
//   - a run interrupted halfway leaves no file that looks complete. A half
//     written report is indistinguishable from a whole one to whoever opens it
//     next, and this tool exists to be believed.
//   - the temporary file is beside the destination rather than in a system
//     temporary directory, because a rename across file systems is not atomic
//     and would silently become a copy.
//
// A failure at any point removes the temporary file and returns. The
// destination is left exactly as it was.
func WriteFile(path string, data []byte) error {
	directory := filepath.Dir(path)

	temporary, err := os.CreateTemp(directory, ".certdoctor-report-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file beside %s: %w", path, err)
	}
	name := temporary.Name()

	if err := finish(temporary, data); err != nil {
		os.Remove(name)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("moving the finished report to %s: %w", path, err)
	}
	return nil
}

// finish writes the bytes, forces them out and closes the handle.
//
// The sync is deliberate. Without it the rename can land before the contents
// do, which turns a crash into a file that exists, has the right name and is
// empty - the one outcome atomicity was supposed to rule out.
func finish(file *os.File, data []byte) error {
	if err := file.Chmod(reportPermissions); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
