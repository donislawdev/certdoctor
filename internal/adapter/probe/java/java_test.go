package java

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
)

// hostSpelling is the twin of the one in probe/binaries_test.go, where the
// comment explains why all four of these test packages need it.
func hostSpelling(path string) string {
	return strings.ReplaceAll(path, `\`, string(filepath.Separator))
}

// The Windows tree these fixtures describe, spelled for the host. Only the
// separator follows the platform - the shape stays Windows, because that is the
// machine being described.
var (
	jdk25      = hostSpelling(`C:\jdk-25`)
	jdk25Store = hostSpelling(`C:\jdk-25\lib\security\cacerts`)
	jdk25Tool  = hostSpelling(`C:\jdk-25\bin\keytool.exe`)
	jdk25Javac = hostSpelling(`C:\jdk-25\bin\javac.exe`)
	jre8       = hostSpelling(`C:\jre8`)
	jre8Store  = hostSpelling(`C:\jre8\lib\security\cacerts`)
	jre8Tool   = hostSpelling(`C:\jre8\bin\keytool.exe`)
)

func sourceOf(paths ...string) func(string) (io.ReadCloser, error) {
	key := func(path string) string { return filepath.Clean(path) }

	present := map[string]bool{}
	for _, path := range paths {
		present[key(path)] = true
	}
	return func(path string) (io.ReadCloser, error) {
		if !present[key(path)] {
			return nil, errors.New("no such file")
		}
		return io.NopCloser(strings.NewReader("")), nil
	}
}

// A DIRECTORY IS NOT AN INSTALLATION - ADR48 part 2. Measured on this machine:
// two directories named latest, in both bitnesses, with no store inside.
func TestADirectoryWithoutAStoreIsNotAnInstall(t *testing.T) {
	source := sourceOf(
		jdk25Store, jdk25Tool, jdk25Javac,
		// THE latest DIRECTORY IS GIVEN A keytool ON PURPOSE. Without one it would be
		// rejected by the SECOND gate - no tool to read a store with - and the missing
		// store would never be the reason. The mutation register caught exactly that:
		// a fixture where two gates can both refuse proves neither of them.
		hostSpelling(`C:\Program Files\Java\latest\bin\keytool.exe`),
	)
	found := find(source, []string{jdk25, hostSpelling(`C:\Program Files\Java\latest`)})
	if len(found) != 1 {
		t.Fatalf("found %d installs, want 1 - latest has no store", len(found))
	}
	if found[0].Variant != "jdk" {
		t.Errorf("variant %q, want jdk - javac is present", found[0].Variant)
	}
}

// THE VARIANT COMES FROM STRUCTURE, NOT FROM THE NAME. javac is in a JDK and not
// in a JRE - measured on both - so the row says which it is without reading a
// directory name, which is inviolable rule 19 turned on our own filesystem.
func TestAStoreWithoutJavacIsAJRE(t *testing.T) {
	source := sourceOf(jre8Store, jre8Tool)
	found := find(source, []string{jre8})
	if len(found) != 1 || found[0].Variant != "jre" {
		t.Fatalf("got %+v, want one jre", found)
	}
}

// An installation whose keytool is missing cannot be read at all, so it is not
// an install this probe can speak for.
func TestAStoreWithNoKeytoolIsNotAnInstall(t *testing.T) {
	source := sourceOf(hostSpelling(`C:\broken\lib\security\cacerts`))
	if found := find(source, []string{hostSpelling(`C:\broken`)}); len(found) != 0 {
		t.Errorf("found %+v, want none - there is no keytool to read the store with", found)
	}
}

func TestTheBitnessComesFromThePath(t *testing.T) {
	source := sourceOf(
		hostSpelling(`C:\Program Files (x86)\Java\jre8\lib\security\cacerts`),
		hostSpelling(`C:\Program Files (x86)\Java\jre8\bin\keytool.exe`),
	)
	found := find(source, []string{hostSpelling(`C:\Program Files (x86)\Java\jre8`)})
	if len(found) != 1 || found[0].Architecture != "x86" {
		t.Fatalf("got %+v, want one x86 install", found)
	}
}

// A NON-ZERO EXIT IS RECOGNISED BY ITS CODE AND NEVER BY ITS MESSAGE - inviolable
// rule 19. A wrong store password, a locked file and a corrupt store all arrive
// this way, and which one it was is somebody else's sentence in a language we do
// not choose.
func TestAKeytoolThatRefusesIsUnknownWithAReason(t *testing.T) {
	install := Install{Root: `C:\jdk`, Store: `C:\jdk\store`, Keytool: `C:\jdk\keytool.exe`}
	run := func(context.Context, string, ...string) (probe.Output, error) {
		return probe.Output{ExitCode: 1, Stderr: "keystore password was incorrect"}, nil
	}
	store := storeFor(context.Background(), run, install, [][]byte{{0x30}}, "", nil, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Error("a store that would not open produced a verdict about trust")
	}
	if store.NotAssessed == "" {
		t.Error("a store that would not open gave no reason")
	}
	if strings.Contains(store.NotAssessed, "password was incorrect") {
		t.Errorf("the reason quotes the tool own message: %q", store.NotAssessed)
	}
	// IT HAS TO BE THE PROBE SAYING "I COULD NOT READ THIS", not the verifier
	// downstream saying "this store holds nothing". Both end without a verdict,
	// and a person sent to the wrong one looks at the wrong file - OBS56.
	if !strings.Contains(store.NotAssessed, "could not be read") {
		t.Errorf("the reason did not come from the probe that failed to read: %q", store.NotAssessed)
	}
}

// JAVA_HOME NAMES ONE OF SIX ON THIS MACHINE - measured - so it may enrich a row
// and may never find one. An install nothing selects is perfectly real.
func TestSelectionNamesJavaHomeAndPathWithoutFindingAnything(t *testing.T) {
	// SPELLED FOR THE HOST because selectedBy matches PATH by SEGMENT, and a
	// segment needs a separator the platform recognises - left Windows-spelled
	// this whole tree is one element off Windows and the PATH half silently
	// stops being asked, which is how this passed here and failed on two other
	// platforms.
	root := hostSpelling(`C:\jdk-25`)
	install := Install{Root: root}

	by := selectedBy(install, root, []string{hostSpelling(`C:\jdk-25\bin`)})
	if len(by) != 2 || by[0] != "JAVA_HOME" || by[1] != "PATH" {
		t.Errorf("got %v, want both JAVA_HOME and PATH", by)
	}
	// The neighbouring-install trap, same as the git probe.
	if got := selectedBy(install, "", []string{hostSpelling(`C:\jdk-250\bin`)}); len(got) != 0 {
		t.Errorf("a neighbouring install claimed this one's place on PATH: %v", got)
	}
	if got := selectedBy(install, "", nil); got == nil || len(got) != 0 {
		t.Errorf("got %v, want an empty list that is not nil", got)
	}
}

// THE WHOLE PROBE, END TO END, because everything above tests a piece of it and
// a build could wire those pieces to nothing while every one of them stayed
// green. Measured shape: six installs on this machine, each its own row.
func TestTheProbeReturnsOneRowPerInstall(t *testing.T) {
	source := sourceOf(
		jdk25Store, jdk25Tool, jdk25Javac,
		jre8Store, jre8Tool,
	)
	run := func(context.Context, string, ...string) (probe.Output, error) {
		return probe.Output{ExitCode: 1}, nil
	}

	stores, err := Probe(source, run, []string{jdk25, jre8, hostSpelling(`C:\nothing`)}, jdk25, nil, atNoon)(context.Background(), [][]byte{{0x30}})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if len(stores) != 2 {
		t.Fatalf("%d rows, want one per install", len(stores))
	}
	if stores[0].Variant != "jdk" || stores[1].Variant != "jre" {
		t.Errorf("variants %q and %q", stores[0].Variant, stores[1].Variant)
	}
	if len(stores[0].SelectedBy) == 0 {
		t.Error("JAVA_HOME named the first install and the row does not say so")
	}
}

// NO JAVA IS NOT AN ERROR - docs/20 rule 1. A machine without it sits outside
// the matrix, and "there is no Java here" is not a fact about trust.
func TestAMachineWithNoJavaIsNotAnError(t *testing.T) {
	stores, err := Probe(sourceOf(), nil, []string{`C:\nothing`}, "", nil, atNoon)(context.Background(), nil)
	if err != nil {
		t.Errorf("a machine without Java produced an error: %v", err)
	}
	if len(stores) != 0 {
		t.Errorf("%d rows for a machine with no Java", len(stores))
	}
}

// A runner that cannot start the program at all is different from one that ran
// and refused: the first is our inability to ask, the second is an answer.
func TestARunnerThatCannotStartIsUnknownWithAReason(t *testing.T) {
	install := Install{Root: `C:\jdk`, Store: `C:\jdk\store`, Keytool: `C:\jdk\keytool.exe`}
	run := func(context.Context, string, ...string) (probe.Output, error) {
		return probe.Output{}, errors.New("executable file not found")
	}
	store := storeFor(context.Background(), run, install, [][]byte{{0x30}}, "", nil, atNoon())
	if store.NotAssessed == "" || store.TrustsPresentedChain != nil {
		t.Errorf("a probe that could not run still produced a verdict: %+v", store)
	}
}

// atNoon is the clock these tests hand to the verifier.
//
// A FIXED INSTANT RATHER THAN time.Now, because the question this clock decides
// is whether a certificate is out of date - and a test whose answer depends on
// the day it runs is a test that will one day fail for a reason nobody planted.
func atNoon() time.Time { return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) }
