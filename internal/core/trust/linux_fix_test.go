package trust

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The command for the Linux platform store - ADR104. The row is a FILE there,
// the bundle the distribution keeps, so the command is the append git and curl
// get - and never the distribution's own tool, which was measured taking away
// what it did not add.

// aLinuxPlatformStore is the row the system-store probe writes on Linux when the
// bundle refused the chain for want of a signer.
func aLinuxPlatformStore() report.TrustStore {
	return aRefusedStore(report.RuntimeSystemStore, "debian", "/etc/ssl/certs/ca-certificates.crt")
}

func TestTheLinuxPlatformStoreGetsTheAppend(t *testing.T) {
	fix, unwritable := fixFor(aLinuxPlatformStore(), true, false, posix())
	if fix == nil {
		t.Fatalf("no command for the Linux platform store (%q)", unwritable)
	}
	if want := `cat '<certificate.pem>' >> '/etc/ssl/certs/ca-certificates.crt'`; fix.Command != want {
		t.Errorf("command %q, want %q", fix.Command, want)
	}
	if !fix.RequiresElevation || fix.Elevation == "" {
		t.Error("the bundle belongs to every account and the command does not say it needs elevated rights")
	}
	if len(fix.Placeholders) != 1 || fix.Placeholders[0] != certificatePlaceholder {
		t.Errorf("placeholders %q, want only the certificate", fix.Placeholders)
	}
	// THE CAVEAT CARRIES THE THREE MEASURED FACTS a person needs before relying
	// on the append: the rebuild drops it, the Debian tool reads only *.crt, and
	// RHEL keeps its sources elsewhere.
	for _, want := range []string{"update-ca-certificates", "*.crt", "/etc/pki/ca-trust/source/anchors"} {
		if !strings.Contains(fix.Caveat, want) {
			t.Errorf("the caveat does not mention %q: %q", want, fix.Caveat)
		}
	}

	store := aLinuxPlatformStore()
	store.Fix = fix
	finding := report.Finding{Kind: report.FindingTrustStore, Summary: "a row", Source: report.SourceDetected, TrustStore: &store}
	if broken := finding.Breach(); broken != "" {
		t.Errorf("the contract refuses the row with its command: %s", broken)
	}
}

// THE DISTRIBUTION'S TOOL IS NOT THE COMMAND - decided by the owner 2026-10-15
// on probe S24: in five images out of five it dropped a certificate appended by
// hand. A command that takes away is the one thing no command here may do.
func TestTheLinuxCommandNeverRebuildsTheBundle(t *testing.T) {
	fix, _ := fixFor(aLinuxPlatformStore(), true, false, posix())
	if fix == nil {
		t.Fatal("the positive twin produced no command, so this proves nothing")
	}
	for _, banned := range []string{"update-ca-certificates", "update-ca-trust", "cp ", "SSL_CERT_FILE"} {
		if strings.Contains(fix.Command, banned) {
			t.Errorf("the command contains %q: %q", banned, fix.Command)
		}
	}
}

// The cases where the Linux branch must NOT reach, each against a positive twin.
func TestTheLinuxCommandIsWrittenOnlyForWhatTheProbeWrites(t *testing.T) {
	if fix, _ := fixFor(aLinuxPlatformStore(), true, false, posix()); fix == nil {
		t.Fatal("the positive twin produced no command, so every case below proves nothing")
	}
	cases := []struct {
		name    string
		store   func() report.TrustStore
		machine Machine
	}{
		{
			// The probe writes this shape on Linux only - macOS is M3.
			name:    "a file row on macOS",
			store:   aLinuxPlatformStore,
			machine: Machine{OS: "darwin", Home: "/Users/jdoe"},
		},
		{
			// No bundle anywhere: the probe writes a row with no path, and there is
			// nothing to append to.
			name: "the row with no bundle",
			store: func() report.TrustStore {
				s := aLinuxPlatformStore()
				s.StoreForm, s.StorePath = report.StoreSystem, ""
				return s
			},
			machine: posix(),
		},
		{
			name: "a file row with no path",
			store: func() report.TrustStore {
				s := aLinuxPlatformStore()
				s.StorePath = ""
				return s
			},
			machine: posix(),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if fix, _ := fixFor(c.store(), true, false, c.machine); fix != nil {
				t.Errorf("a command was produced: %q", fix.Command)
			}
		})
	}
}

// The first two gates hold on this row as on every other - ADR103 opened one
// gate for the platform store, and ADR104 opened none.
func TestTheLinuxPlatformStoreStillPassesTheFirstTwoGates(t *testing.T) {
	if fix, _ := fixFor(aLinuxPlatformStore(), false, false, posix()); fix != nil {
		t.Errorf("an incomplete chain nothing here closed earned a command: %q", fix.Command)
	}
	if fix, _ := fixFor(aLinuxPlatformStore(), false, true, posix()); fix == nil {
		t.Error("a chain another store here closed earned no command, and that is ADR55's case")
	}
	expired := aLinuxPlatformStore()
	expired.TrustFailure = report.Expired
	if fix, _ := fixFor(expired, true, false, posix()); fix != nil {
		t.Errorf("an expired certificate earned a command: %q", fix.Command)
	}
}

// A path a shell would read as an instruction gets no command and says why -
// the same rule every file command here follows, ADR59.
func TestALinuxBundlePathThisProgramCannotWriteSafelyGetsNoCommand(t *testing.T) {
	store := aLinuxPlatformStore()
	store.StorePath = "/etc/ssl/certs/\nca.crt"
	fix, unwritable := fixFor(store, true, false, posix())
	if fix != nil || unwritable != unwritablePath {
		t.Errorf("got %v and %q, want no command and the sentence saying why", fix, unwritable)
	}
}

// THE BLIND SPOT OF TestEveryDeclaredRuntimeCanBeFixed, CLOSED. That test hands
// the platform store the Windows shape, so a Linux row with no command would
// pass it. This one asks with the shape each platform's probe writes.
func TestThePlatformStoreCanBeFixedOnEveryPlatformItIsRead(t *testing.T) {
	cases := map[string]struct {
		store   report.TrustStore
		machine Machine
	}{
		"windows": {aPlatformStore(report.InstanceLocalMachine), aMachine()},
		"linux":   {aLinuxPlatformStore(), posix()},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if fix, _ := fixFor(c.store, true, false, c.machine); fix == nil || fix.Command == "" {
				t.Errorf("the platform store on %s can be diagnosed and never acted on", name)
			}
		})
	}
}
