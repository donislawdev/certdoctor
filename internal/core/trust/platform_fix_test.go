package trust

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The command for the platform's OWN store - ADR103, the one exception to the
// file gate. Every negative below has its positive twin on the same fixture,
// OBS56: a generator that refused the platform store outright would pass every
// "no command here" case and look careful doing it.

// TestThePlatformStoreGetsACommandForEachOfItsTwoInstances is the positive
// half, and it pins what each instance is told.
func TestThePlatformStoreGetsACommandForEachOfItsTwoInstances(t *testing.T) {
	cases := []struct {
		instance string
		command  string
		elevated bool
	}{
		// THE MACHINE'S STORE is read by every account and every service, so
		// changing it needs an administrator.
		{report.InstanceLocalMachine, `certutil -addstore Root "<certificate.pem>"`, true},
		// THIS ACCOUNT'S STORE needs nobody's permission but its own.
		{report.InstanceCurrentUser, `certutil -user -addstore Root "<certificate.pem>"`, false},
	}
	for _, c := range cases {
		t.Run(c.instance, func(t *testing.T) {
			fix, unwritable := fixFor(aPlatformStore(c.instance), true, false, aMachine())
			if fix == nil {
				t.Fatalf("no command for the %s platform store (%q)", c.instance, unwritable)
			}
			if fix.Command != c.command {
				t.Errorf("command %q, want %q", fix.Command, c.command)
			}
			if fix.RequiresElevation != c.elevated {
				t.Errorf("requires elevation %v, want %v", fix.RequiresElevation, c.elevated)
			}
			if c.elevated && fix.Elevation == "" {
				t.Error("the command needs an administrator and does not say why")
			}
			if len(fix.Placeholders) != 1 || fix.Placeholders[0] != certificatePlaceholder {
				t.Errorf("placeholders %q, want only the certificate", fix.Placeholders)
			}
		})
	}
}

// TestTheUserStoreCommandSaysWindowsWillAsk is the caveat that stops the
// confirmation dialog surprising somebody, and the one that says a service does
// not see this account's store.
func TestTheUserStoreCommandSaysWindowsWillAsk(t *testing.T) {
	fix, _ := fixFor(aPlatformStore(report.InstanceCurrentUser), true, false, aMachine())
	if fix == nil {
		t.Fatal("no command for this account's store")
	}
	for _, want := range []string{"confirmation", "services"} {
		if !strings.Contains(fix.Caveat, want) {
			t.Errorf("the caveat does not mention %q: %q", want, fix.Caveat)
		}
	}
}

// TestThePlatformCommandIsWrittenOnlyForWhatTheProbeWrites walks the cases where
// the exception must NOT reach.
func TestThePlatformCommandIsWrittenOnlyForWhatTheProbeWrites(t *testing.T) {
	if fix, _ := fixFor(aPlatformStore(report.InstanceLocalMachine), true, false, aMachine()); fix == nil {
		t.Fatal("the positive twin produced no command, so every case below proves nothing")
	}
	cases := []struct {
		name    string
		store   func() report.TrustStore
		machine Machine
	}{
		{
			// The command is certutil, which exists on one platform.
			name:    "not on Windows",
			store:   func() report.TrustStore { return aPlatformStore(report.InstanceLocalMachine) },
			machine: posix(),
		},
		{
			// A location nobody here wrote is a store nobody here can name.
			name:    "an instance the probe never produces",
			store:   func() report.TrustStore { return aPlatformStore("Enterprise") },
			machine: aMachine(),
		},
		{
			// The runtime alone does not open the exception - the row has to be
			// the platform store's own shape.
			name: "the platform runtime on a file-shaped row",
			store: func() report.TrustStore {
				s := aPlatformStore(report.InstanceLocalMachine)
				s.StoreForm = report.StoreFile
				s.StorePath = `C:\somewhere\store.crt`
				return s
			},
			machine: aMachine(),
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

// TestThePlatformStoreStillPassesTheFirstTwoGates is the proof that ADR103
// opened ONE gate and not three. A server that withheld its intermediate, and a
// certificate out of date, get no command on this store either.
func TestThePlatformStoreStillPassesTheFirstTwoGates(t *testing.T) {
	if fix, _ := fixFor(aPlatformStore(report.InstanceLocalMachine), true, false, aMachine()); fix == nil {
		t.Fatal("the positive twin produced no command, so the gates below prove nothing")
	}
	if fix, _ := fixFor(aPlatformStore(report.InstanceLocalMachine), false, false, aMachine()); fix != nil {
		t.Errorf("an incomplete chain nothing here closed earned a command: %q", fix.Command)
	}
	expired := aPlatformStore(report.InstanceLocalMachine)
	expired.TrustFailure = report.Expired
	if fix, _ := fixFor(expired, true, false, aMachine()); fix != nil {
		t.Errorf("an expired certificate earned a command: %q", fix.Command)
	}
}
