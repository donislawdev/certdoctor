package output

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
