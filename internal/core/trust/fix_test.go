package trust

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The remediation command, which is the one thing this program produces that
// somebody RUNS.
//
// EVERY TEST HERE HAS A POSITIVE TWIN ON THE SAME FIXTURE - OBS56. A generator
// that returned nil for everything would satisfy every "no command here" test in
// this file, and would look exactly like a careful one.

// aRefusedStore is a store that read its anchors and found none that signed what
// arrived - the only failure a command addresses.
func aRefusedStore(runtime, instance, path string) report.TrustStore {
	no := false
	return report.TrustStore{
		Runtime:              runtime,
		Instance:             instance,
		StorePath:            path,
		StoreForm:            report.StoreFile,
		TrustAnchorCount:     150,
		TrustsPresentedChain: &no,
		TrustFailure:         report.UnknownAuthority,
		SelectedBy:           []string{},
	}
}

func aJavaStore() report.TrustStore {
	return aRefusedStore("java", `C:\Program Files\OpenJDK\jdk-25`, `C:\Program Files\OpenJDK\jdk-25\lib\security\cacerts`)
}

func aBundleStore() report.TrustStore {
	return aRefusedStore("curl", "/usr/bin/curl", "/etc/ssl/certs/ca-certificates.crt")
}

func posix() Machine { return Machine{OS: "linux", Home: "/home/jdoe"} }

// TestEveryDeclaredRuntimeCanBeFixed is the registry test, and it is what stops a
// probe arriving with no template and nobody noticing.
//
// A runtime this program can DIAGNOSE and cannot ADVISE is half a feature, and
// the half that is missing is the half the product is named for. It fails at the
// moment a fourth descriptor is declared, which is exactly when somebody is in a
// position to write the template.
func TestEveryDeclaredRuntimeCanBeFixed(t *testing.T) {
	for _, descriptor := range All() {
		t.Run(descriptor.ID, func(t *testing.T) {
			store := aRefusedStore(descriptor.Runtime, `C:\somewhere\install`, `C:\somewhere\install\store.crt`)
			fix := fixFor(store, true, aMachine())
			if fix == nil {
				t.Fatalf("runtime %q is asked by a probe and has no remediation template, so its rows can be "+
					"diagnosed and never acted on", descriptor.Runtime)
			}
			if fix.Command == "" {
				t.Error("the template produced an empty command")
			}
			for _, placeholder := range fix.Placeholders {
				if !strings.Contains(fix.Command, placeholder) {
					t.Errorf("the command does not contain the placeholder %q it declares", placeholder)
				}
			}
		})
	}
}

// TestTheThreeGatesEachStopACommandOnTheirOwn walks the conditions one at a
// time, so that a generator satisfying two of the three still fails here.
func TestTheThreeGatesEachStopACommandOnTheirOwn(t *testing.T) {
	// The positive twin first. Without it every case below passes on a function
	// that never returns anything.
	if fixFor(aJavaStore(), true, aMachine()) == nil {
		t.Fatal("a store that refused a complete chain for want of a signer got no command, and that is the one case there is a command for")
	}

	cases := []struct {
		name     string
		store    func() report.TrustStore
		complete bool
		why      string
	}{
		{
			// MEASURED ON THE BENCH 2026-08-19. A server withholding its
			// intermediate turns every row red and the fault is the server's - a
			// command here edits a store that is perfectly fine.
			name:     "the server did not send its intermediate",
			store:    aJavaStore,
			complete: false,
			why:      "the chain was incomplete, so the fault is the server's",
		},
		{
			name: "the certificate expired",
			store: func() report.TrustStore {
				s := aJavaStore()
				s.TrustFailure = report.Expired
				return s
			},
			complete: true,
			why:      "importing a certificate does not move a clock",
		},
		{
			name: "the failure is one this program does not classify",
			store: func() report.TrustStore {
				s := aJavaStore()
				s.TrustFailure = report.OtherFailure
				return s
			},
			complete: true,
			why:      "an unclassified failure is not a licence to guess",
		},
		{
			// THE MEASURED TRAP, 2026-08-02: Schannel ignores CURL_CA_BUNDLE, so
			// a file-shaped command aimed at a platform store does nothing at all.
			name: "the store is the platform's own",
			store: func() report.TrustStore {
				s := aBundleStore()
				s.StoreForm = report.StoreSystem
				s.StorePath = ""
				return s
			},
			complete: true,
			why:      "a platform store has no file to name",
		},
		{
			name: "the store is called a file and has no path",
			store: func() report.TrustStore {
				s := aBundleStore()
				s.StorePath = ""
				return s
			},
			complete: true,
			why:      "docs/20 rule 6 wants the real path and there is none",
		},
		{
			name: "a runtime with a probe and no template",
			store: func() report.TrustStore {
				s := aBundleStore()
				s.Runtime = "node"
				return s
			},
			complete: true,
			why:      "a guessed command is worse than no command",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if fix := fixFor(c.store(), c.complete, aMachine()); fix != nil {
				t.Errorf("a command was produced where %s: %q", c.why, fix.Command)
			}
		})
	}
}

// TestTheJavaCommandNamesTheKeytoolBesideTheStore is ADR50 in the one place it
// would be easiest to forget.
//
// A bare "keytool" is resolved by PATH, and PATH names ONE of the six Java
// installs measured on this machine. The command would look right and, on five
// rows out of six, run a different installation's tool.
func TestTheJavaCommandNamesTheKeytoolBesideTheStore(t *testing.T) {
	fix := fixFor(aJavaStore(), true, aMachine())
	if fix == nil {
		t.Fatal("no command for a Java store that refused the chain")
	}
	if !strings.Contains(fix.Command, `C:\Program Files\OpenJDK\jdk-25\bin\keytool`) {
		t.Errorf("the command does not name this installation's own keytool: %q", fix.Command)
	}
	if !strings.Contains(fix.Command, `C:\Program Files\OpenJDK\jdk-25\lib\security\cacerts`) {
		t.Errorf("the command does not name the real store path, and a template path is worth nothing: %q", fix.Command)
	}
	// A path with a space in it that is not quoted becomes two arguments, and
	// "Program Files" is on every Windows machine this tool will meet.
	if !strings.Contains(fix.Command, `"C:\Program Files\OpenJDK\jdk-25\lib\security\cacerts"`) {
		t.Errorf("the store path is not quoted, so a space in it splits the command: %q", fix.Command)
	}
}

// TestTheSeparatorComesFromThePathRatherThanTheBuild keeps this generator honest
// about a machine it is not running on.
func TestTheSeparatorComesFromThePathRatherThanTheBuild(t *testing.T) {
	store := aRefusedStore("java", "/usr/lib/jvm/jdk-21", "/usr/lib/jvm/jdk-21/lib/security/cacerts")
	fix := fixFor(store, true, posix())
	if fix == nil {
		t.Fatal("no command for a posix Java store")
	}
	if !strings.Contains(fix.Command, "/usr/lib/jvm/jdk-21/bin/keytool") {
		t.Errorf("a posix store produced a command with the wrong separator: %q", fix.Command)
	}
	if strings.Contains(fix.Command, `\`) {
		t.Errorf("a posix command carries a backslash: %q", fix.Command)
	}
}

// TestABundleIsAppendedRatherThanReplaced is the rule every command in this file
// obeys, and it is the difference between fixing one site and breaking the rest.
//
// Pointing a runtime at ANOTHER bundle grants the trust that was asked for and
// silently withdraws every other trust that runtime had. The person finds out
// days later, on a different site, and has no reason to connect the two.
func TestABundleIsAppendedRatherThanReplaced(t *testing.T) {
	forbidden := []string{"CURL_CA_BUNDLE=", "--cacert", "http.sslCAInfo", "sslBackend"}

	for _, machine := range []Machine{aMachine(), posix()} {
		for _, runtime := range []string{"curl", "git"} {
			store := aBundleStore()
			store.Runtime = runtime
			fix := fixFor(store, true, machine)
			if fix == nil {
				t.Fatalf("no command for a %s bundle on %s", runtime, machine.OS)
			}
			if !strings.Contains(fix.Command, "/etc/ssl/certs/ca-certificates.crt") {
				t.Errorf("the command does not name the real bundle: %q", fix.Command)
			}
			for _, banned := range forbidden {
				if strings.Contains(fix.Command, banned) {
					t.Errorf("the %s command on %s redirects the runtime instead of adding to its store (%q): %q",
						runtime, machine.OS, banned, fix.Command)
				}
			}
		}
	}
}

// TestTheAppendCommandFitsThePlatform pins the measured half of this file.
//
// The Windows form was measured on 2026-08-19 rather than reasoned about: "copy
// /b a+b a" appended byte for byte, 59 plus 59 came out 118, with no byte order
// mark and no newline translation. A ">>" redirection would have been written by
// whichever shell the person happens to be in, and Windows PowerShell 5.1 writes
// UTF-16 - which turns a certificate bundle into a file no TLS library reads.
func TestTheAppendCommandFitsThePlatform(t *testing.T) {
	windows := fixFor(aBundleStore(), true, aMachine())
	if windows == nil || !strings.Contains(windows.Command, "copy /b") {
		t.Errorf("the Windows command is not the measured one: %#v", windows)
	}
	if windows != nil && strings.Contains(windows.Command, ">>") {
		t.Errorf("the Windows command redirects, and the shell that does it may write UTF-16: %q", windows.Command)
	}

	elsewhere := fixFor(aBundleStore(), true, posix())
	if elsewhere == nil || !strings.Contains(elsewhere.Command, "cat ") || !strings.Contains(elsewhere.Command, ">>") {
		t.Errorf("the posix command is not an append: %#v", elsewhere)
	}
}

// TestElevationIsAnsweredAndSaysWhy covers docs/20 rule 5 in both directions,
// including the direction that costs somebody a failed command.
func TestElevationIsAnsweredAndSaysWhy(t *testing.T) {
	cases := []struct {
		name    string
		store   report.TrustStore
		machine Machine
		wants   bool
	}{
		{
			name:    "a store inside this account's own files",
			store:   aRefusedStore("curl", "/usr/bin/curl", "/home/jdoe/.certs/bundle.crt"),
			machine: posix(),
			wants:   false,
		},
		{
			name:    "a store shared by the whole machine",
			store:   aBundleStore(),
			machine: posix(),
			wants:   true,
		},
		{
			// THE UNKNOWN CASE ANSWERS YES, and that direction is the decision.
			// Being warned about rights nobody needed costs a moment; not being
			// warned costs a failed command and the suspicion the tool was wrong
			// about everything else.
			name:    "a machine that could not say where home is",
			store:   aRefusedStore("curl", "/usr/bin/curl", "/home/jdoe/.certs/bundle.crt"),
			machine: Machine{OS: "linux"},
			wants:   true,
		},
		{
			// THE MEASURED SEGMENT TRAP - the same one the git and java probes
			// carry a test for. "bobby" begins with "bob" as TEXT.
			name:    "a neighbouring account whose name starts the same way",
			store:   aRefusedStore("curl", "/usr/bin/curl", "/home/bobby/.certs/bundle.crt"),
			machine: Machine{OS: "linux", Home: "/home/bob"},
			wants:   true,
		},
		{
			// Windows paths are compared without regard to case, because the
			// filesystem is - and the store path and the home directory reach
			// this program from two different places.
			name:    "a windows home in a different case",
			store:   aRefusedStore("curl", `C:\Users\JDoe\certs\bundle.crt`, `C:\Users\JDoe\certs\bundle.crt`),
			machine: Machine{OS: "windows", Home: `c:\users\jdoe`},
			wants:   false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fix := fixFor(c.store, true, c.machine)
			if fix == nil {
				t.Fatal("no command at all")
			}
			if fix.RequiresElevation != c.wants {
				t.Errorf("elevation reported as %v, want %v", fix.RequiresElevation, c.wants)
			}
			if fix.RequiresElevation && fix.Elevation == "" {
				t.Error("elevation is demanded and not explained, which is rule 5 half done")
			}
			if !fix.RequiresElevation && fix.Elevation != "" {
				t.Errorf("no elevation needed and a reason given anyway: %q", fix.Elevation)
			}
		})
	}
}

// TestEveryCommandSaysWhatOutlivesIt - a certificate added to a store a package
// manager owns is removed by the next update, and somebody who was not told that
// concludes the tool was wrong the first time.
func TestEveryCommandSaysWhatOutlivesIt(t *testing.T) {
	for _, store := range []report.TrustStore{aJavaStore(), aBundleStore()} {
		fix := fixFor(store, true, aMachine())
		if fix == nil {
			t.Fatalf("no command for %s", store.Runtime)
		}
		if fix.Caveat == "" {
			t.Errorf("the %s command says nothing about what undoes it", store.Runtime)
		}
	}
}

// TestAProducedCommandSatisfiesTheContract closes the loop between the generator
// and the validator, which are in two packages and could drift apart.
func TestAProducedCommandSatisfiesTheContract(t *testing.T) {
	for _, store := range []report.TrustStore{aJavaStore(), aBundleStore()} {
		store.Fix = fixFor(store, true, aMachine())
		finding := report.Finding{
			Kind:       report.FindingTrustStore,
			Summary:    "a store that refused the chain",
			Source:     report.SourceDetected,
			TrustStore: &store,
		}
		if broken := finding.Breach(); broken != "" {
			t.Errorf("a command this package produced was refused by the contract: %s", broken)
		}
	}
}
