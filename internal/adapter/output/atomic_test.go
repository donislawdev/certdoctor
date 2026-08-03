package output

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestARemovalThatFailsIsReportedRatherThanSwallowed covers the clean up path
// after a failed write.
//
// The result of removing the temporary file used to be discarded. That is this
// program's one promise broken in the quietest way there is - the only file
// certdoctor creates is a report at a path a person named, and a leftover
// .certdoctor-report-* is not that. The message named the write that had failed
// and said nothing about what was still lying in the directory.
//
// Removing a file that is not there is the one way to make the call fail on
// every platform. The three real ways - a handle held open by a scanner, a
// permission withdrawn mid-run, a file system that went away - are not
// reachable portably, which is why the branch went untested in the first place.
func TestARemovalThatFailsIsReportedRatherThanSwallowed(t *testing.T) {
	err := removeTemporary(filepath.Join(t.TempDir(), "was-never-created"))
	if err == nil {
		t.Fatal("a removal that failed returned no error, so a leftover file would never be mentioned")
	}
	if !strings.Contains(err.Error(), "still there") {
		t.Errorf("the message does not say the file is still there: %v", err)
	}
}

func TestTheReportLandsAtTheNamedPath(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "report.json")
	want := []byte("{\"schema_version\":\"1.0\"}\n")

	if err := WriteFile(path, want); err != nil {
		t.Fatalf("writing failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the report is not at the path it was given: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("the file holds %q, want %q", got, want)
	}
}

// TestNoTemporaryFileSurvivesASuccessfulWrite is the half of atomicity people
// forget. A rename that left the temporary file behind would still produce a
// correct report and would litter the user's directory every time they ran the
// tool.
func TestNoTemporaryFileSurvivesASuccessfulWrite(t *testing.T) {
	directory := t.TempDir()

	if err := WriteFile(filepath.Join(directory, "report.txt"), []byte("x")); err != nil {
		t.Fatalf("writing failed: %v", err)
	}
	left := namesIn(t, directory)
	if len(left) != 1 || left[0] != "report.txt" {
		t.Errorf("the directory holds %v, want only report.txt", left)
	}
}

// TestAFailedWriteLeavesTheDirectoryAsItWas covers the failure path. The tool
// creates exactly one file when it succeeds and none when it does not - a rule
// that only means something if somebody checked the second half.
func TestAFailedWriteLeavesTheDirectoryAsItWas(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "no-such-directory", "report.txt")

	if err := WriteFile(missing, []byte("x")); err == nil {
		t.Fatal("writing into a directory that does not exist reported success")
	}
	if left := namesIn(t, directory); len(left) != 0 {
		t.Errorf("a failed write left %v behind", left)
	}
}

// TestAFailedRenameLeavesNoTemporaryFileBehind covers the branch that decides
// whether this tool litters somebody's directory.
//
// WHY IT WAS MISSING AND HOW IT WAS FOUND. Every guard in the repository was
// green while the failure branches of the only function allowed to write a file
// had never been executed - the package sat at the lowest coverage in the tree
// and nobody had looked. The write guard cannot see this: it scans the
// allowlist statically and has no opinion about whether a file is cleaned up
// afterwards.
//
// The rename is made to fail by pointing it at an existing DIRECTORY, which
// both platforms refuse, rather than by any trick with permissions that would
// behave differently on one of them.
func TestAFailedRenameLeavesNoTemporaryFileBehind(t *testing.T) {
	directory := t.TempDir()
	occupied := filepath.Join(directory, "report.txt")
	if err := os.Mkdir(occupied, 0o755); err != nil {
		t.Fatalf("setting the destination up as a directory failed: %v", err)
	}

	if err := WriteFile(occupied, []byte("x")); err == nil {
		t.Fatal("renaming onto a directory reported success")
	}

	// The directory we created is expected to still be there. Anything else is
	// a temporary file this program failed to clean up after itself.
	for _, name := range namesIn(t, directory) {
		if name != "report.txt" {
			t.Errorf("a failed write left %q behind - certdoctor creates exactly one file and only where it was told", name)
		}
	}
}

// TestFinishReportsAFailureRatherThanReturningNil reaches the inner function
// directly, because a handle that has already been closed is the only way to
// make a write fail that behaves the same on every platform.
//
// The value is narrow and worth stating: it proves the error paths return an
// error at all. A version that closed the handle and returned nil would leave
// WriteFile renaming a file whose contents never arrived - the exact outcome
// the sync in that function exists to rule out.
func TestFinishReportsAFailureRatherThanReturningNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "already-closed")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating the file failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("closing it failed: %v", err)
	}

	if err := finish(file, []byte("x")); err == nil {
		t.Error("writing through a closed handle reported success")
	}
}

// TestTheFailureSaysWhichPathItWas keeps the message useful. A person who
// pointed the tool at an unwritable place needs to see which place.
func TestTheFailureSaysWhichPathItWas(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "no-such-directory", "report.txt")

	err := WriteFile(missing, []byte("x"))
	if err == nil {
		t.Fatal("writing into a directory that does not exist reported success")
	}
	if !strings.Contains(err.Error(), "report.txt") {
		t.Errorf("the failure does not name the path: %v", err)
	}
}

// TestAnExistingReportIsReplacedWholesale covers the second run into the same
// path. A write that appended, or that left the tail of a longer previous
// report behind, would produce a file that parses and lies.
func TestAnExistingReportIsReplacedWholesale(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "report.txt")

	if err := WriteFile(path, []byte("a much longer earlier report")); err != nil {
		t.Fatalf("the first write failed: %v", err)
	}
	if err := WriteFile(path, []byte("short")); err != nil {
		t.Fatalf("the second write failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back failed: %v", err)
	}
	if string(got) != "short" {
		t.Errorf("the file holds %q after being overwritten", got)
	}
}

// TestTheReportIsNotWorldReadable is skipped on Windows, where the permission
// bits are not the mechanism and asserting them would be checking nothing while
// looking like a check.
func TestTheReportIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits are not how access is decided here")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "report.txt")

	if err := WriteFile(path, []byte("internal host names and paths")); err != nil {
		t.Fatalf("writing failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the report is not there: %v", err)
	}
	if mode := info.Mode().Perm(); mode != reportPermissions {
		t.Errorf("the report is mode %o, want %o - it carries internal names and paths", mode, reportPermissions)
	}
}

func namesIn(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("reading %s: %v", directory, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
