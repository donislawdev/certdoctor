package dns

import (
	"os"
	"strings"
	"testing"
)

// TestALibraryIsLoadedFromTheSystemDirectoryAndNotFromBesideUs is P3-3.
//
// A BARE NAME GOES THROUGH THE LOADER'S SEARCH ORDER, whose first directory is
// the one holding the executable - so a copy planted beside certdoctor.exe would
// be loaded instead. The exception is a KnownDLL, which the loader takes from a
// section mapped at boot and never searches for. Read from this machine's
// registry 2026-08-27, under Session Manager KnownDLLs: 37 entries, kernel32.dll
// among them and iphlpapi.dll NOT. So the call in the renderer is safe as
// written and this one was not.
func TestALibraryIsLoadedFromTheSystemDirectoryAndNotFromBesideUs(t *testing.T) {
	library, err := systemLibrary("iphlpapi.dll")
	if err != nil {
		t.Fatalf("the system directory could not be established: %v", err)
	}

	name := library.Name
	if !strings.HasSuffix(strings.ToLower(name), `\iphlpapi.dll`) {
		t.Errorf("the library is named %q, which does not end in the file that was asked for", name)
	}
	// AN ABSOLUTE PATH IS THE WHOLE POINT. A name with no directory in it is
	// exactly the state this function exists to leave behind.
	if !strings.Contains(name, `\`) || len(name) < 4 || name[1] != ':' {
		t.Errorf("the library is named %q, which is not an absolute path", name)
	}
	// AND IT IS THE SYSTEM'S OWN DIRECTORY rather than one we made up. SystemRoot
	// is read HERE, in the test, precisely because the code under test refuses to
	// trust it.
	if root := os.Getenv("SystemRoot"); root != "" {
		if !strings.HasPrefix(strings.ToLower(name), strings.ToLower(root)) {
			t.Errorf("the library at %q is not under %q", name, root)
		}
	}
	// It has to actually load, or this is a well formed path to nothing.
	if err := library.Load(); err != nil {
		t.Errorf("the library at %q did not load: %v", name, err)
	}
}

// TestOnlyAStringValueIsReadBackAsAString is P3-4.
//
// The kind was asked for and thrown away, so a value stored as REG_BINARY or
// REG_DWORD came back through UTF16ToString as whatever those bytes happen to
// spell - and this function's answers become resolver addresses, which go into
// the set of places this program may connect to.
func TestOnlyAStringValueIsReadBackAsAString(t *testing.T) {
	for _, c := range []struct {
		name string
		kind uint32
		want bool
	}{
		{"REG_SZ", 1, true},
		{"REG_EXPAND_SZ", 2, true},
		{"REG_BINARY", 3, false},
		{"REG_DWORD", 4, false},
		// UTF16ToString stops at the first NUL, so a multi string would come back
		// as the first of several and look like a whole answer.
		{"REG_MULTI_SZ", 7, false},
		{"REG_NONE", 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := stringKind(c.kind); got != c.want {
				t.Errorf("registry type %d (%s) answered %v, want %v", c.kind, c.name, got, c.want)
			}
		})
	}
}

// TestWindowsRecordsNoNameSourcesAndThatIsNotAFailure covers the Windows half of
// a port whose absence is the ordinary state of a working machine.
//
// Nothing failed: there is no nsswitch.conf on Windows, so the honest answer is
// that nothing DECLARED anything. An error here would put a failure in the report
// about a system behaving normally, which is the trap this whole layer is built
// around.
func TestWindowsRecordsNoNameSourcesAndThatIsNotAFailure(t *testing.T) {
	got, err := NameSources(nil)
	if err != nil {
		t.Fatalf("a machine with no such file reported %v", err)
	}
	if got.Declared {
		t.Errorf("Windows declared name sources: %+v", got)
	}
}
