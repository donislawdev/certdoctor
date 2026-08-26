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
	"errors"
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
	if err := refuseDevice(path); err != nil {
		return err
	}
	return writeAndRename(path, data)
}

// writeAndRename is the write itself, with the pre-flight refusal already done.
//
// IT IS ITS OWN FUNCTION SO THAT THE CLEANUP CAN BE TESTED - and that is not a
// convenience, it is the answer to OBS26. The branches that remove a temporary
// file after a failure had no test that executed them, because there was no
// portable way to make the write fail from inside this process: the one trick
// that worked - a destination that is already a directory - is now caught by
// refuseDevice before anything is created.
//
// AND THE BRANCHES STILL HAVE TO WORK. The pre-flight check is a courtesy, not a
// guarantee: a destination can become a directory between the check and the
// rename, and a run interrupted mid-write must not leave a file in somebody
// else's directory either way. A test that reaches past the courtesy is testing
// the guarantee.
func writeAndRename(path string, data []byte) error {
	directory := filepath.Dir(path)

	temporary, err := os.CreateTemp(directory, ".certdoctor-report-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file beside %s: %w", path, err)
	}
	name := temporary.Name()

	if err := finish(temporary, data); err != nil {
		return errors.Join(fmt.Errorf("writing %s: %w", path, err), removeTemporary(name))
	}
	if err := os.Rename(name, path); err != nil {
		return errors.Join(fmt.Errorf("moving the finished report to %s: %w", path, err), removeTemporary(name))
	}
	return nil
}

// refuseDevice stops a run that names a device as its destination, and says why.
//
// A DEVICE CANNOT BE REPLACED BY A RENAME, which is the whole mechanism here.
// Asking for one is not unreasonable - "send this nowhere" is an ordinary thing
// to want - so what it deserves is an answer rather than the failure it used to
// produce further in. MEASURED on both systems, 2026-08-03:
//
//	--out /dev/null   creating a temporary file beside /dev/null:
//	                  open /dev/.certdoctor-report-2539093753: permission denied
//	--out NUL         moving the finished report to NUL:
//	                  Cannot create a file when that file already exists
//
// Both are true and neither says what happened. One of them names a directory
// the person never mentioned and the other says a file exists when they were
// trying to create one.
//
// os.Stat answers the same way on both: NUL and CON on Windows come back as
// character devices, and so does /dev/null. A path that does not exist yet is
// the ordinary case and is left alone - the check is only about what is already
// there.
func refuseDevice(path string) error {
	existing, err := os.Stat(path)
	if err != nil {
		// A PATH THAT DOES NOT EXIST YET IS THE ORDINARY CASE. This check is only
		// about what is already there.
		return nil
	}
	// A DIRECTORY GETS THE SAME ANSWER AND FOR THE SAME REASON - P3-7. Measured
	// on this machine 2026-08-27, "--out ." said:
	//
	//	moving the finished report to .: rename .\.certdoctor-report-1719771881 .:
	//	Access is denied.
	//
	// Every word of that is true and none of it is the answer. It names a
	// temporary file the person never mentioned, and it says access when the
	// problem is that a directory is not a file - so a reader goes looking at
	// permissions. Naming a directory is an ordinary slip, especially with tab
	// completion, and it deserves a sentence rather than a diagnosis of the
	// wrong thing.
	if existing.IsDir() {
		return fmt.Errorf(
			"%s is a directory rather than a file, so there is no name to write the report under. "+
				"Give a path including a file name, or use - to send the report to standard output",
			path)
	}
	if existing.Mode()&os.ModeDevice == 0 {
		return nil
	}
	return fmt.Errorf(
		"%s is a device rather than a file, and a report is written under a temporary name and renamed into place, which cannot be done to a device. Use - to send the report to standard output, or give a path to a file",
		path)
}

// removeTemporary takes the half written file away, and says so when it cannot.
//
// The failure to remove used to be discarded. That is this program's one promise
// broken in the quietest way available: the only file certdoctor creates is a
// report at a path a person named, and a leftover .certdoctor-report-* is
// neither. The message named the write that failed and said nothing about what
// was still lying in the directory, so the person who went to look found a file
// nobody had mentioned.
func removeTemporary(name string) error {
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("the temporary file %s could not be removed and is still there: %w", name, err)
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
