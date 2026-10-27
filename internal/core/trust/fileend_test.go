package trust

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// An append joins bytes and nothing else, so a file whose last line has no line
// break would come out with the old END line and the new BEGIN line as one line,
// and neither block read - ADR114 B13, decided by the owner.
//
// EVERY PATH THAT APPENDS IS WALKED, because the check lives in the one function
// that writes an append and a path reaching around it would look identical from
// its own tests.
func TestAnAppendWaitsForTheFileToEndWithALineBreak(t *testing.T) {
	nodeOnLinux := posix()
	nodeOnLinux.NodeExtraCACerts = "/etc/ssl/extra.pem"
	appends := []struct {
		name    string
		store   report.TrustStore
		machine Machine
	}{
		{"curl", aBundleStore(), posix()},
		{"git on Windows", aRefusedStore("git", `C:\Program Files\Git`,
			`C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt`), aMachine()},
		{"python reading a file", aPythonReadingAFile(), posix()},
		{"the Linux platform store", aLinuxPlatformStore(), posix()},
		{"node adding to the file its variable names", readingExtra(), nodeOnLinux},
	}
	for _, a := range appends {
		t.Run(a.name, func(t *testing.T) {
			// THE POSITIVE TWIN FIRST - OBS56. A generator withholding every append
			// would pass each case below.
			if fix, why := fixFor(a.store, true, false, a.machine); fix == nil || why != "" {
				t.Fatalf("a file ending with a line break got no command (%q), so the cases below prove nothing", why)
			}
			for _, c := range []struct {
				end  report.FileEnd
				want string
			}{
				{report.FileEndMidLine, endsMidLine},
				{report.FileEndUnseen, endUnseen},
			} {
				store := a.store
				store.FileEnd = c.end
				fix, why := fixFor(store, true, false, a.machine)
				if fix != nil {
					t.Errorf("FileEnd %d still got the command %q", c.end, fix.Command)
				}
				if why != c.want {
					t.Errorf("FileEnd %d said %q, want %q", c.end, why, c.want)
				}
			}
		})
	}
}

// A COMMAND THAT DOES NOT APPEND DOES NOT ASK. keytool, certutil and the node
// variables write no bytes after anybody's last line, so a row whose end was
// never seen keeps its command.
func TestACommandThatDoesNotAppendIgnoresTheFileEnd(t *testing.T) {
	rows := []struct {
		name  string
		store report.TrustStore
	}{
		{"java", aJavaStore()},
		{"the Windows platform store", aPlatformStore(report.InstanceLocalMachine)},
		{"python on the Windows stores", aPythonOnTheWindowsStores()},
		{"node setting its variable", aNodeStore()},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			store := r.store
			store.FileEnd = report.FileEndMidLine
			if fix, why := fixFor(store, true, false, aMachine()); fix == nil {
				t.Errorf("a command that appends nothing was withheld over the end of a file (%q)", why)
			}
		})
	}
}

// The path is asked before the end, so a path no shell reads safely says that -
// it is the one of the two a person cannot repair by editing the file.
func TestAnUnwritablePathIsSaidBeforeTheFileEnd(t *testing.T) {
	store := aRefusedStore("curl", `C:\curl`, `C:\certs\%USERNAME%\ca.crt`)
	store.FileEnd = report.FileEndMidLine
	if _, why := fixFor(store, true, false, aMachine()); why != unwritablePath {
		t.Errorf("got %q, want the sentence about the path", why)
	}
}

// The sentence reaches the row through the layer, the one place a withheld
// command is said - the same seam ADR59 uses.
func TestAFileEndingMidLineSaysSoOnItsRow(t *testing.T) {
	no := false
	refused := aStore("curl", "/usr/bin/curl", &no, "")
	refused.FileEnd = report.FileEndMidLine
	in := probesOf(func(context.Context, [][]byte) ([]report.TrustStore, error) {
		return []report.TrustStore{refused}, nil
	})
	for _, finding := range Ask(context.Background(), in).Findings {
		if finding.Kind != report.FindingTrustStore {
			continue
		}
		if finding.TrustStore.Fix != nil {
			t.Errorf("a command was written for a file ending mid-line: %q", finding.TrustStore.Fix.Command)
		}
		if !strings.HasSuffix(finding.Summary, " - "+endsMidLine) {
			t.Errorf("the row does not say why it has no command: %q", finding.Summary)
		}
	}
}
