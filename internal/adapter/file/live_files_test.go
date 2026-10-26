package file

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The second half of a directory - ADR104. Exercised against a real temporary
// directory for the reason TestTheLiveListingReturnsDirectoriesOnly gives: this
// is the plumbing that touches a disk, and a fake would prove nothing about it.
func TestTheLiveFileListingReturnsEverythingButDirectories(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatalf("no directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "root.pem"), []byte("x"), 0o600); err != nil {
		t.Fatalf("no file: %v", err)
	}

	names, err := LiveFiles()(root)
	if err != nil {
		t.Fatalf("listing failed: %v", err)
	}
	if len(names) != 1 || names[0] != filepath.Join(root, "root.pem") {
		t.Errorf("got %v, want only the file, named in full", names)
	}
	if _, err := LiveFiles()(filepath.Join(root, "absent")); err == nil {
		t.Error("listing a directory that is not there came back as success")
	}
}

// A LINK IS NAMED, NOT FOLLOWED - the shape every certificate directory on
// Debian has, where each entry is a link into /usr/share/ca-certificates and a
// dangling one is an ordinary leftover. Guarded judges where it leads.
func TestALinkIsListedWithoutBeingFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symbolic link on Windows needs a privilege this test does not ask for")
	}
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(root, "gone.pem"), filepath.Join(root, "dangling.pem")); err != nil {
		t.Fatalf("no link: %v", err)
	}
	names, err := LiveFiles()(root)
	if err != nil {
		t.Fatalf("listing failed: %v", err)
	}
	if len(names) != 1 || filepath.Base(names[0]) != "dangling.pem" {
		t.Errorf("got %v, want the dangling link named", names)
	}
}

// ONLY A REGULAR FILE IS HANDED BACK - ADR114. A directory is the one thing
// that is not a file on every platform; the pipe and the device are each
// checked where they exist.
func TestTheLiveSourceHandsBackRegularFilesAlone(t *testing.T) {
	dir := t.TempDir()
	_, err := liveSource(dir)
	var refused *NotRegular
	if !errors.As(err, &refused) || refused.Path != dir {
		t.Errorf("a directory was opened for reading: %v", err)
	}

	regular := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(regular, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := liveSource(regular)
	if err != nil {
		t.Fatalf("a regular file was refused: %v", err)
	}
	_ = opened.Close()
}

// A DIRECTORY IS LISTED WHOLE, IN NAME ORDER, OR NOT AT ALL - ADR114. Read in
// batches, so the ceiling is met while reading rather than after, and the order
// is the one os.ReadDir gave, which rows are built from.
func TestADirectoryIsListedInOrderUpToItsCeiling(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"c.pem", "a.pem", "b.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := readDirWithin(dir, 3)
	if err != nil || len(entries) != 3 || entries[0].Name() != "a.pem" || entries[2].Name() != "c.pem" {
		t.Errorf("got %v, %v - want a.pem, b.pem, c.pem", entries, err)
	}
	if _, err := readDirWithin(dir, 2); err == nil || !strings.Contains(err.Error(), "more than 2 entries") {
		t.Errorf("three entries under a ceiling of two came back %v", err)
	}
	var refused *NotRegular
	if _, err := readDir(filepath.Join(dir, "a.pem")); !errors.As(err, &refused) {
		t.Errorf("a file was listed as a directory: %v", err)
	}
}
