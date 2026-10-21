package trust

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// aPythonOnTheWindowsStores is the row the python probe writes on Windows when
// the list the stores gave it refused the chain - a row with no path.
func aPythonOnTheWindowsStores() report.TrustStore {
	s := aRefusedStore(report.RuntimePython, `C:\Python313\python.exe`, "")
	s.StoreForm = report.StoreSystem
	s.SelectedBy = []string{"PATH", "python"}
	return s
}

// aPythonReadingAFile is the row on Linux when Python reads the distribution's
// bundle, spelled as the platform store's row spells it.
func aPythonReadingAFile() report.TrustStore {
	s := aRefusedStore(report.RuntimePython, "/usr/bin/python3", "/etc/ssl/certs/ca-certificates.crt")
	s.SelectedBy = []string{"PATH", "python3"}
	return s
}

// ON WINDOWS PYTHON GETS THIS ACCOUNT'S ROOT STORE - ADR112 part 4, decided by
// the owner - the same line the platform's own row for this account gets, with
// no administrator and a caveat of its own.
func TestPythonOnTheWindowsStoresGetsThisAccountsRootStore(t *testing.T) {
	fix, why := fixFor(aPythonOnTheWindowsStores(), true, false, aMachine())
	if fix == nil || why != "" {
		t.Fatalf("no command (%q)", why)
	}
	platform, _ := fixFor(aPlatformStore(report.InstanceCurrentUser), true, false, aMachine())
	if fix.Command != platform.Command {
		t.Errorf("python got %q and the platform's row for this account %q", fix.Command, platform.Command)
	}
	if fix.RequiresElevation || fix.Elevation != "" {
		t.Errorf("this account's own store asked for elevation: %+v", fix)
	}
	if !strings.Contains(fix.Caveat, "confirmation") || !strings.Contains(fix.Caveat, "TLS context") {
		t.Errorf("the caveat does not say what happens and when Python sees it: %q", fix.Caveat)
	}
	if fix.Caveat == platform.Caveat {
		t.Error("python carries the platform row's caveat, which speaks of services rather than of Python")
	}
}

// THE STORES ARE WINDOWS'S, SO THE COMMAND IS TOO. A row with no file anywhere
// else is a Python reading only the platform's hashed directory, and a certificate
// counts there under a name this program does not compute - OBS186.
func TestPythonReadingNoFileElsewhereGetsNoCommand(t *testing.T) {
	fix, why := fixFor(aPythonOnTheWindowsStores(), true, false, posix())
	if fix != nil || why != "" {
		t.Errorf("a python row with no file outside Windows got %+v (%q)", fix, why)
	}
}

// ON LINUX THE CERTIFICATE GOES INTO THE FILE PYTHON READS - the append git, curl
// and the platform's row get, with root asked for outside this account's files.
func TestPythonReadingAFileGetsTheAppend(t *testing.T) {
	fix, why := fixFor(aPythonReadingAFile(), true, false, posix())
	if fix == nil || why != "" {
		t.Fatalf("no command (%q)", why)
	}
	if want := `cat '<certificate.pem>' >> '/etc/ssl/certs/ca-certificates.crt'`; fix.Command != want {
		t.Errorf("got %q, wanted %q", fix.Command, want)
	}
	if !fix.RequiresElevation || fix.Elevation == "" {
		t.Errorf("a file outside this account's own files did not ask for root: %+v", fix)
	}
	if !strings.Contains(fix.Caveat, "update-ca-certificates") {
		t.Errorf("the caveat does not name what drops the certificate again: %q", fix.Caveat)
	}

	// THE POSITIVE TWIN OF THE GATE: a file row with no path is no file.
	pathless := aPythonReadingAFile()
	pathless.StorePath = ""
	if fix, why := fixFor(pathless, true, false, posix()); fix != nil || why != "" {
		t.Errorf("a file row with no path got %+v (%q)", fix, why)
	}
}

// A PATH A SHELL WOULD READ AS AN INSTRUCTION GETS NO COMMAND, and the row says
// so - ADR59, the same for python as for every file row.
func TestPythonsFileAShellWouldMisreadGetsNoCommand(t *testing.T) {
	store := aPythonReadingAFile()
	store.StorePath = "/etc/ssl/a\nb.pem"
	if fix, why := fixFor(store, true, false, posix()); fix != nil || why != unwritablePath {
		t.Errorf("got %+v (%q)", fix, why)
	}
}

// THE THREE GATES COME FIRST FOR PYTHON TOO - a refusal for an expired chain
// gets nothing, whatever the store.
func TestPythonMeetsTheSameGatesFirst(t *testing.T) {
	store := aPythonOnTheWindowsStores()
	store.TrustFailure = report.Expired
	if fix, _ := fixFor(store, true, false, aMachine()); fix != nil {
		t.Errorf("an expired chain got %+v", fix)
	}
	if fix, _ := fixFor(aPythonOnTheWindowsStores(), false, false, aMachine()); fix != nil {
		t.Errorf("an incomplete chain nothing closed got %+v", fix)
	}
}
