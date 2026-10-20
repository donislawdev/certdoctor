package trust

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// aNodeStore is the row the node probe writes when its list refused the chain -
// the list compiled into the binary, so a row with no path.
func aNodeStore() report.TrustStore {
	s := aRefusedStore(report.RuntimeNode, `C:\Program Files\nodejs\node.exe`, "")
	s.StoreForm = report.StoreBuiltin
	s.SelectedBy = []string{"PATH"}
	return s
}

// readingExtra is the same row when node read certificates from the file
// NODE_EXTRA_CA_CERTS names - the probe says so in selected_by.
func readingExtra() report.TrustStore {
	s := aNodeStore()
	s.SelectedBy = []string{"PATH", "NODE_EXTRA_CA_CERTS"}
	return s
}

// closedByThePlatform is the row the probe writes when NODE_USE_SYSTEM_CA=1
// would make this node trust the chain.
func closedByThePlatform() report.TrustStore {
	s := aNodeStore()
	s.PlatformListCloses = true
	return s
}

// WHERE THE PLATFORM'S LIST WOULD CLOSE THE CHAIN, THE COMMAND TURNS IT ON -
// ADR111 part 7, command one - with nothing to fill in, and ahead of the file
// NODE_EXTRA_CA_CERTS names even where node read that file.
func TestNodeTurnsOnThePlatformListWhereItWouldClose(t *testing.T) {
	windows := aMachine()
	windows.NodeExtraCACerts = `C:\Users\jdoe\certs\extra.pem`
	cases := []struct {
		name    string
		store   report.TrustStore
		machine Machine
		want    string
	}{
		{"on Windows", closedByThePlatform(), aMachine(), "setx NODE_USE_SYSTEM_CA 1"},
		{"elsewhere", closedByThePlatform(), posix(), "export NODE_USE_SYSTEM_CA=1"},
		{"ahead of the file node read", func() report.TrustStore {
			s := closedByThePlatform()
			s.SelectedBy = []string{"PATH", "NODE_EXTRA_CA_CERTS"}
			return s
		}(), windows, "setx NODE_USE_SYSTEM_CA 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := c.store
			var why string
			store.Fix, why = fixFor(store, true, false, c.machine)
			if store.Fix == nil || store.Fix.Command != c.want || why != "" {
				t.Fatalf("got %+v and %q, want %q", store.Fix, why, c.want)
			}
			if store.Fix.Placeholders == nil || len(store.Fix.Placeholders) != 0 || store.Fix.RequiresElevation {
				t.Errorf("placeholders %v, elevated %v, want an empty list and no elevation", store.Fix.Placeholders,
					store.Fix.RequiresElevation)
			}
			for _, says := range []string{"already running", "no v23", "v22.19.0"} {
				if !strings.Contains(store.Fix.Caveat, says) {
					t.Errorf("the caveat does not mention %q: %q", says, store.Fix.Caveat)
				}
			}
			finding := report.Finding{Kind: report.FindingTrustStore, Summary: "node refused", Source: report.SourceDetected,
				TrustStore: &store}
			if broken := finding.Breach(); broken != "" {
				t.Errorf("the contract refused it: %s", broken)
			}
		})
	}
}

// WHERE NOTHING IS SET, THE COMMAND SETS THE VARIABLE - ADR111 part 7, command
// three - spelled for the platform, with the placeholder quoted as everywhere.
func TestNodeGetsTheVariableWhereNothingIsSet(t *testing.T) {
	cases := []struct {
		machine Machine
		want    string
	}{
		{aMachine(), `setx NODE_EXTRA_CA_CERTS "<certificate.pem>"`},
		{posix(), `export NODE_EXTRA_CA_CERTS='<certificate.pem>'`},
	}
	for _, c := range cases {
		fix, why := fixFor(aNodeStore(), true, false, c.machine)
		if fix == nil {
			t.Fatalf("no command on %s: %q", c.machine.OS, why)
		}
		if fix.Command != c.want || fix.RequiresElevation {
			t.Errorf("on %s the command is %q (elevated %v), want %q unelevated", c.machine.OS, fix.Command,
				fix.RequiresElevation, c.want)
		}
		if !strings.Contains(fix.Caveat, "already running") {
			t.Errorf("the caveat does not say a running node keeps the old value: %q", fix.Caveat)
		}
	}
}

// WHERE THE VARIABLE NAMES A FILE NODE READ, THE CERTIFICATE GOES INTO IT -
// command two - and elevation is answered for that file like for any other.
func TestNodeAddsToTheFileTheVariableNames(t *testing.T) {
	windows := aMachine()
	windows.NodeExtraCACerts = `C:\Users\jdoe\certs\extra.pem`
	linux := posix()
	linux.NodeExtraCACerts = "/etc/ssl/extra.pem"
	cases := []struct {
		machine  Machine
		want     string
		elevated bool
	}{
		{windows, `cmd /c copy /b "C:\Users\jdoe\certs\extra.pem"+"<certificate.pem>" "C:\Users\jdoe\certs\extra.pem"`, false},
		{linux, `cat '<certificate.pem>' >> '/etc/ssl/extra.pem'`, true},
	}
	for _, c := range cases {
		store := readingExtra()
		store.Fix, _ = fixFor(store, true, false, c.machine)
		if store.Fix == nil || store.Fix.Command != c.want || store.Fix.RequiresElevation != c.elevated {
			t.Fatalf("on %s the command is %+v, want %q elevated %v", c.machine.OS, store.Fix, c.want, c.elevated)
		}
		finding := report.Finding{Kind: report.FindingTrustStore, Summary: "node refused", Source: report.SourceDetected,
			TrustStore: &store}
		if broken := finding.Breach(); broken != "" {
			t.Errorf("the contract refused it: %s", broken)
		}
	}
}

// A VARIABLE ALREADY SET IS NEVER SET AGAIN. Pointing Node at another file
// drops what the first one gave it, so where node read nothing from the file
// named, and where the name is relative, the row says why there is no command.
func TestNodeIsNeverPointedAtAnotherFile(t *testing.T) {
	cases := []struct {
		name  string
		store report.TrustStore
		extra string
		says  string
	}{
		{"a file node read nothing from", aNodeStore(), "/etc/ssl/missing.pem", "read no certificate"},
		{"a relative name", readingExtra(), "certs/extra.pem", "relative path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := posix()
			m.NodeExtraCACerts = c.extra
			fix, why := fixFor(c.store, true, false, m)
			if fix != nil || !strings.Contains(why, c.says) || !strings.Contains(why, c.extra) {
				t.Errorf("got %+v and %q, want no command and a reason naming %q", fix, why, c.extra)
			}
		})
	}
}

// A FILE NAME QUOTING CANNOT MAKE LITERAL GETS NO COMMAND - ADR59, the rule
// every other append keeps. On Windows "%" expands inside the quotes.
func TestAnExtraFileNameThisProgramCannotWriteGetsNoCommand(t *testing.T) {
	m := aMachine()
	m.NodeExtraCACerts = `C:\Users\jdoe\%TEMP%\extra.pem`
	fix, why := fixFor(readingExtra(), true, false, m)
	if fix != nil || why != unwritablePath {
		t.Errorf("got %+v and %q, want no command and the sentence saying why", fix, why)
	}
}

// THE GATES IN FRONT STILL STAND, and a node row of another form - one the
// distribution's build defers with - gets nothing from this template. Each row
// says the platform's list would close the chain, so the gates are shown to
// stand ahead of that command too.
func TestANodeRowPassesTheSameGates(t *testing.T) {
	if fix, _ := fixFor(closedByThePlatform(), false, false, aMachine()); fix != nil {
		t.Error("a chain the server left incomplete earned a node command")
	}
	expired := closedByThePlatform()
	expired.TrustFailure = report.Expired
	if fix, _ := fixFor(expired, true, false, aMachine()); fix != nil {
		t.Error("an expired chain earned a node command")
	}
	system := closedByThePlatform()
	system.StoreForm = report.StoreSystem
	if fix, why := fixFor(system, true, false, aMachine()); fix != nil || why != "" {
		t.Errorf("a node row on the platform's store got %+v %q", fix, why)
	}
}

func TestAbsoluteOnEachPlatform(t *testing.T) {
	cases := []struct {
		platform, path string
		want           bool
	}{
		{"windows", `C:\certs\extra.pem`, true},
		{"windows", `C:/certs/extra.pem`, true},
		{"windows", `\\server\share\extra.pem`, true},
		{"windows", `C:extra.pem`, false},
		{"windows", `certs\extra.pem`, false},
		{"windows", `/certs/extra.pem`, false},
		{"linux", "/etc/ssl/extra.pem", true},
		{"linux", "certs/extra.pem", false},
	}
	for _, c := range cases {
		if got := absoluteOn(c.platform, c.path); got != c.want {
			t.Errorf("absoluteOn(%s, %q) = %v, want %v", c.platform, c.path, got, c.want)
		}
	}
}
