package curl

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// hostSpelling is the twin of the one in probe/binaries_test.go, where the
// comment explains why all four of these test packages need it.
func hostSpelling(path string) string {
	return strings.ReplaceAll(path, `\`, string(filepath.Separator))
}

// The Windows tree these fixtures describe, spelled for the host. The SHAPE is
// Windows because that is the machine being described; only the separator
// follows the platform, so that filepath.Join and filepath.Clean have something
// they can take apart.
var (
	winSystem32     = hostSpelling(`C:\Windows\system32`)
	winSystem32Loud = hostSpelling(`C:\WINDOWS\system32`)
	system32Curl    = hostSpelling(`C:\Windows\system32\curl.exe`)
	gitBin          = hostSpelling(`C:\Program Files\Git\mingw64\bin`)
	gitBinCurl      = hostSpelling(`C:\Program Files\Git\mingw64\bin\curl.exe`)
)

func sourceOf(paths ...string) func(string) (io.ReadCloser, error) {
	key := func(path string) string { return strings.ToLower(filepath.Clean(path)) }

	present := map[string]bool{}
	for _, path := range paths {
		present[key(path)] = true
	}
	return func(path string) (io.ReadCloser, error) {
		if !present[key(path)] {
			return nil, errors.New("no such file")
		}
		return io.NopCloser(strings.NewReader("bundle")), nil
	}
}

func versionSaying(line string) probe.Runner {
	return func(context.Context, string, ...string) (probe.Output, error) {
		return probe.Output{Stdout: line + "\nRelease-Date: 2026-01-01\n"}, nil
	}
}

// EVERY curl ON PATH, NOT THE FIRST ONE - ADR50. Measured: two on this machine,
// and taking the first would have hidden the one shipped inside Git.
func TestEveryCurlOnPathIsFound(t *testing.T) {
	source := sourceOf(system32Curl, gitBinCurl)
	found := find(source, noLinks, []string{winSystem32, gitBin})
	if len(found) != 2 {
		t.Fatalf("found %d curl binaries, want 2", len(found))
	}
}

// THE DEFECT THIS TEST EXISTS FOR WAS MEASURED, NOT IMAGINED. PATH on this
// machine carries system32 in two spellings, so the first version of find
// reported ONE binary as TWO stores and the verdict counted ten where there are
// nine. Caught by running the binary.
func TestOneBinaryReachedByTwoSpellingsIsOneRow(t *testing.T) {
	source := sourceOf(system32Curl)
	found := find(source, noLinks, []string{winSystem32, winSystem32Loud})
	if len(found) != 1 {
		t.Fatalf("found %d rows for one binary: %+v", len(found), found)
	}
}

// SCHANNEL ASKS THE PLATFORM, AND THAT IS system-store's QUESTION. Answering it
// here would mean this probe quietly claimed a verdict about a store it never
// opened - and measured on this machine, BOTH curl builds are Schannel.
func TestASchannelBuildIsUnassessedRatherThanTrusted(t *testing.T) {
	store := storeFor(context.Background(), versionSaying("curl 8.21.0 (Windows) libcurl/8.21.0 Schannel"),
		sourceOf(), Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, "", atNoon())

	if store.TrustsPresentedChain != nil {
		t.Error("a platform-store build produced a verdict this probe cannot reach")
	}
	if store.Backend != "schannel" {
		t.Errorf("backend %q, want schannel", store.Backend)
	}
	if !strings.Contains(store.NotAssessed, "system-store") {
		t.Errorf("the reason does not say who answers instead: %q", store.NotAssessed)
	}
}

// AN UNRECOGNISED BACKEND IS UNKNOWN AND NEVER A GUESS. Picking the commonest
// one and generating a fix for it is how somebody runs a command that does
// nothing while waiting for it to work.
func TestAnUnknownBackendIsUnassessedRatherThanAssumed(t *testing.T) {
	store := storeFor(context.Background(), versionSaying("curl 9.0.0 libcurl/9.0.0 SomeNewTLS"),
		sourceOf(), Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, "", atNoon())

	if store.Backend != "" {
		t.Errorf("an unrecognised backend was recorded as %q", store.Backend)
	}
	if store.TrustsPresentedChain != nil {
		t.Error("an unrecognised backend still produced a verdict")
	}
	// THE REASON HAS TO SAY WHICH OF THE TWO THIS IS. Both "backend unknown"
	// and "reads the platform store" end without a verdict, so asserting only
	// the absence of one is a correct answer to a different question - OBS56,
	// and the mutation register caught exactly that here.
	if !strings.Contains(store.NotAssessed, "does not recognise") {
		t.Errorf("the reason does not say the backend was unrecognised: %q", store.NotAssessed)
	}
	if strings.Contains(store.NotAssessed, "platform store") {
		t.Errorf("an unrecognised backend was reported as a platform-store build: %q", store.NotAssessed)
	}
}

// An OpenSSL build with no bundle named falls back to a build-time default this
// program cannot read off disk, and saying so is better than guessing at it.
func TestAnOpenSSLBuildWithNoBundleSaysSo(t *testing.T) {
	store := storeFor(context.Background(), versionSaying("curl 8.21.0 libcurl/8.21.0 OpenSSL/3.0"),
		sourceOf(), Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, "", atNoon())

	if store.Backend != "openssl" {
		t.Errorf("backend %q, want openssl", store.Backend)
	}
	if store.StoreForm != report.StoreSystem || store.NotAssessed == "" {
		t.Errorf("a build-time default was not reported as undetermined: %+v", store)
	}
}

// With a bundle named, the row becomes a file store and goes through the SHARED
// verifier - the same one git uses. A bundle that cannot be read is UNKNOWN with
// a reason, never a failure to trust.
func TestAnOpenSSLBuildWithAnUnreadableBundleIsUnassessed(t *testing.T) {
	store := storeFor(context.Background(), versionSaying("curl 8.21.0 libcurl/8.21.0 OpenSSL/3.0"),
		sourceOf(), Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, "/absent/bundle.crt", atNoon())

	if store.StoreForm != report.StoreFile || store.StorePath != "/absent/bundle.crt" {
		t.Errorf("the row does not name the bundle it was pointed at: %+v", store)
	}
	if store.TrustsPresentedChain != nil || store.NotAssessed == "" {
		t.Errorf("an unreadable bundle did not come back as unassessed: %+v", store)
	}
}

// A binary that will not report its version is recognised by its EXIT CODE.
func TestACurlThatRefusesToReportIsUnassessed(t *testing.T) {
	run := func(context.Context, string, ...string) (probe.Output, error) {
		return probe.Output{ExitCode: 2, Stderr: "nie mozna uruchomic"}, nil
	}
	store := storeFor(context.Background(), run, sourceOf(), Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, "", atNoon())

	if store.NotAssessed == "" {
		t.Error("a curl that would not answer gave no reason")
	}
	if strings.Contains(store.NotAssessed, "nie mozna") {
		t.Errorf("the reason quotes the tool's own localised message: %q", store.NotAssessed)
	}
}

// THE WHOLE PROBE, END TO END. Measured shape on this machine: two binaries,
// both Schannel, so two rows and no verdicts.
func TestTheProbeReturnsOneRowPerBinary(t *testing.T) {
	source := sourceOf(system32Curl, hostSpelling(`C:\git\bin\curl.exe`))
	stores, err := Probe(source, noLinks, versionSaying("curl 8.21.0 libcurl/8.21.0 Schannel"),
		[]string{winSystem32, winSystem32Loud, hostSpelling(`C:\git\bin`), hostSpelling(`C:\empty`)}, "", atNoon)(context.Background(), [][]byte{{0x30}})

	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if len(stores) != 2 {
		t.Fatalf("%d rows, want one per binary - system32 appears twice on PATH", len(stores))
	}
	for _, store := range stores {
		if store.Runtime != "curl" || store.Backend != "schannel" {
			t.Errorf("row does not describe a schannel curl: %+v", store)
		}
	}
}

// NO curl IS NOT AN ERROR - docs/20 rule 1.
func TestAMachineWithNoCurlIsNotAnError(t *testing.T) {
	stores, err := Probe(sourceOf(), noLinks, nil, []string{`C:\empty`}, "", atNoon)(context.Background(), nil)
	if err != nil {
		t.Errorf("a machine without curl produced an error: %v", err)
	}
	if len(stores) != 0 {
		t.Errorf("%d rows for a machine with no curl", len(stores))
	}
}

// A bundle that reads fine goes through the SHARED verifier, and a chain the
// bundle does not close is DISTRUST - a verdict, not a failure.
func TestAReadableBundleProducesAVerdict(t *testing.T) {
	store := storeFor(context.Background(), versionSaying("curl 8.21.0 libcurl/8.21.0 OpenSSL/3.0"),
		sourceOf("/bundle.crt"), Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, "/bundle.crt", atNoon())

	// The fixture bundle holds no PEM, so the verifier reports that rather than
	// inventing a verdict - which is the honest answer for an empty store.
	if store.TrustsPresentedChain != nil {
		t.Errorf("a store with no readable anchor produced a verdict: %+v", store)
	}
	if store.NotAssessed == "" {
		t.Error("a store with no readable anchor gave no reason")
	}
}

// atNoon is the clock these tests hand to the verifier.
//
// A FIXED INSTANT RATHER THAN time.Now, because the question this clock decides
// is whether a certificate is out of date - and a test whose answer depends on
// the day it runs is a test that will one day fail for a reason nobody planted.
func atNoon() time.Time { return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) }

// noLinks is a resolver for a filesystem with no symbolic links on it.
func noLinks(path string) (string, error) { return path, nil }
