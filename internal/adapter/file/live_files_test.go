package file

import (
	"os"
	"path/filepath"
	"runtime"
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
