//go:build windows

package file

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// THE LIVE PLUMBING IS ASKED ABOUT REAL PATHS, because it is the one piece of
// this port that touches a disk: a path that is not there, a file that is not a
// reparse point, and a path Windows cannot even spell.
func TestTheLiveAliasPortRefusesWhatIsNoAlias(t *testing.T) {
	root := t.TempDir()
	plain := filepath.Join(root, "python.exe")
	if err := os.WriteFile(plain, []byte("MZ"), 0o600); err != nil {
		t.Fatalf("no file: %v", err)
	}
	const notAReparsePoint = syscall.Errno(4390)
	if _, err := LiveAppAlias()(plain); !errors.Is(err, notAReparsePoint) {
		t.Errorf("an ordinary file: %v", err)
	}
	if _, err := LiveAppAlias()(filepath.Join(root, "absent.exe")); !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		t.Errorf("a path that is not there: %v", err)
	}
	if _, err := LiveAppAlias()("python\x00.exe"); err == nil {
		t.Error("a path holding a zero was read")
	}
}

// A REPARSE POINT THAT IS NOT AN ALIAS IS READ AND REFUSED BY THE PARSER -
// which proves the port opened the reparse point itself rather than what it
// leads to: without FILE_FLAG_OPEN_REPARSE_POINT the junction opens as the
// directory it names and Windows says it is no reparse point. "Documents and
// Settings" is a junction every Windows since Vista keeps for old programs.
func TestTheLiveAliasPortReadsAReparsePointItself(t *testing.T) {
	junction := filepath.Join(os.Getenv("SystemDrive")+`\`, "Documents and Settings")
	if info, err := os.Lstat(junction); err != nil || info.Mode()&os.ModeSymlink == 0 && info.Mode()&os.ModeIrregular == 0 {
		t.Skipf("no junction at %s here", junction)
	}
	if _, err := LiveAppAlias()(junction); !errors.Is(err, ErrNotAnAppAlias) {
		t.Errorf("the junction was not handed to the parser: %v", err)
	}
}

// AN ALIAS THIS MACHINE HAS GIVES ITS PACKAGE - skipped where WindowsApps holds
// none, which a build machine may well do.
func TestTheLiveAliasPortReadsAnAliasThisMachineHas(t *testing.T) {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "WindowsApps")
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".exe") {
			continue
		}
		pkg, err := LiveAppAlias()(filepath.Join(dir, entry.Name()))
		if err != nil || !strings.Contains(pkg, "_") {
			t.Fatalf("%s: got %q, %v", entry.Name(), pkg, err)
		}
		t.Logf("%s belongs to %s", entry.Name(), pkg)
		return
	}
	t.Skipf("no app execution alias in %s", dir)
}

// A DEVICE IS REFUSED BEFORE ITS FIRST READ - ADR114. Opening NUL succeeds at
// once on Windows, and a console device opened the same way waits in the read.
func TestADeviceIsRefusedBeforeItIsRead(t *testing.T) {
	_, err := liveSource("NUL")
	var refused *NotRegular
	if !errors.As(err, &refused) {
		t.Errorf("the null device was opened for reading: %v", err)
	}
}
