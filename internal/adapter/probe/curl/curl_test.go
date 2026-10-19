package curl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
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

// SCHANNEL ASKS THE PLATFORM, AND THE ANSWER IS THE PLATFORM ROW'S. This probe
// never opens that store, so it claims no trust of its own - it names the row
// that answers, and the trust layer hands it that row's answer. ADR108 part 4,
// and which row was measured with probe S25 on 2026-10-20: a root held in this
// account's Root store alone was trusted by both builds on this machine.
func TestASchannelBuildJudgesByThisAccountsStore(t *testing.T) {
	store := storeFor(context.Background(), versionSaying(schannelLine),
		sourceOf(), Install{Path: `C:\curl.exe`}, [][]byte{leafNaming(t, []string{"http://crl.test/a.crl"}, nil)},
		Environment{}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Error("a platform-store build produced a verdict this probe cannot reach")
	}
	if store.Backend != "schannel" {
		t.Errorf("backend %q, want schannel", store.Backend)
	}
	if store.DefersTo == nil || *store.DefersTo != (report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: report.InstanceCurrentUser}) {
		t.Fatalf("the row does not name this account's store as its answer: %+v", store.DefersTo)
	}
	if !strings.Contains(store.NotAssessed, "system-store CurrentUser") {
		t.Errorf("the reason does not say who answers instead: %q", store.NotAssessed)
	}
}

// schannelLine is the first line of curl --version on the owner's machine,
// measured 2026-10-20 for the binary in system32.
const schannelLine = "curl 8.21.0 (Windows) libcurl/8.21.0 Schannel zlib/1.3.2 WinIDN WinLDAP"

// leafNaming is a certificate whose only interesting fields are where it says
// its revocation can be checked.
func leafNaming(t *testing.T, crl, ocsp []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "partner.test"},
		NotBefore:             atNoon().Add(-time.Hour),
		NotAfter:              atNoon().Add(time.Hour),
		CRLDistributionPoints: crl,
		OCSPServer:            ocsp,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// THE MEASURED REFUSAL - probe S25: a leaf naming nowhere to check failed on
// both builds with CRYPT_E_NO_REVOCATION_CHECK, with the root trusted. The row
// refuses for itself and still names the store, so the signer line counts that
// store once.
func TestASchannelBuildRefusesALeafThatNamesNowhereToCheck(t *testing.T) {
	store := storeFor(context.Background(), versionSaying(schannelLine),
		sourceOf(), Install{Path: `C:\curl.exe`}, [][]byte{leafNaming(t, nil, nil)}, Environment{}, atNoon())

	if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain {
		t.Fatalf("a leaf naming nowhere to check was not refused: %+v", store)
	}
	if store.TrustFailure != report.NoRevocationInfo {
		t.Errorf("the refusal says %q", store.TrustFailure)
	}
	if store.DefersTo == nil {
		t.Error("the refusing row stopped naming the store it judges by")
	}
}

// A JUDGEMENT, PINNED SO IT IS NOT CHANGED BY ACCIDENT: S25 served revocation
// lists only, and a responder is taken to be an address too.
func TestAnOCSPResponderCountsAsSomewhereToCheck(t *testing.T) {
	store := storeFor(context.Background(), versionSaying(schannelLine),
		sourceOf(), Install{Path: `C:\curl.exe`}, [][]byte{leafNaming(t, nil, []string{"http://ocsp.test"})}, Environment{}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Errorf("a leaf naming a responder was judged here: %+v", store)
	}
}

// A certificate Go cannot read is not a certificate naming nowhere - nothing
// was learned, so the row neither refuses nor takes a store's answer.
func TestALeafThatCannotBeReadLeavesTheRowUnassessed(t *testing.T) {
	store := storeFor(context.Background(), versionSaying(schannelLine),
		sourceOf(), Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, Environment{}, atNoon())

	if store.TrustsPresentedChain != nil || store.DefersTo != nil {
		t.Errorf("an unreadable leaf still produced an answer or a store to take one from: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, "could not be read") {
		t.Errorf("the reason does not say the certificate could not be read: %q", store.NotAssessed)
	}
}

// BRACKETS MARK THE BACKENDS A BUILD DID NOT SELECT - lib/vtls/vtls.c,
// multissl_version, in curl 8.21.0. Schannel is asked first, so before this a
// file-reading build that merely carries Schannel read as Schannel.
func TestTheSelectedBackendIsTheOneOutsideTheBrackets(t *testing.T) {
	cases := map[string]string{
		"curl 8.21.0 (x86_64-w64-mingw32) libcurl/8.21.0 OpenSSL/3.5.7 (Schannel) zlib/1.3.2": "openssl",
		"curl 8.21.0 (x86_64-w64-mingw32) libcurl/8.21.0 Schannel (OpenSSL/3.5.7) zlib/1.3.2": "schannel",
		schannelLine: "schannel",
	}
	for line, want := range cases {
		got, err := backendOf(context.Background(), versionSaying(line), Install{Path: `C:\curl.exe`})
		if err != nil || got != want {
			t.Errorf("%q read as %q (%v), want %q", line, got, err, want)
		}
	}
}

// A CONFIGURATION FILE CAN NAME A CA FILE OR TURN REVOCATION OFF, and this
// program does not read it - so a row that finds one takes no store's answer.
func TestAConfigurationFileStopsTheRowTakingTheStoresAnswer(t *testing.T) {
	profile := hostSpelling(`C:\Users\jdoe`)
	curlrc := filepath.Join(profile, ".curlrc")
	store := storeFor(context.Background(), versionSaying(schannelLine),
		sourceOf(curlrc), Install{Path: system32Curl}, [][]byte{leafNaming(t, nil, nil)},
		Environment{Homes: map[string]string{"USERPROFILE": profile}}, atNoon())

	if store.TrustsPresentedChain != nil || store.DefersTo != nil {
		t.Fatalf("a row with a configuration file in reach still answered: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, curlrc) {
		t.Errorf("the reason does not name the file: %q", store.NotAssessed)
	}
}

// curl's own order, read in src/tool_findfile.c of 8.21.0 - including the turn
// a reader would not guess: once a place holding "curlrc" is reached, every later
// place is asked for ".curlrc" alone and later places without a dot are skipped.
func TestTheConfigurationFileIsLookedForInCurlsOwnOrder(t *testing.T) {
	j := filepath.Join
	home, profile, data, xdg := hostSpelling(`C:\h`), hostSpelling(`C:\p`), hostSpelling(`C:\a`), hostSpelling(`C:\x`)
	binary := gitBinCurl

	withoutXDG := configCandidates(map[string]string{"HOME": home, "USERPROFILE": profile, "APPDATA": data}, binary)
	wantWithout := []string{
		j(home, ".curlrc"), j(home, "_curlrc"),
		j(profile, ".curlrc"), j(profile, "_curlrc"),
		j(data, ".curlrc"), j(data, "_curlrc"),
		j(profile, "Application Data", ".curlrc"), j(profile, "Application Data", "_curlrc"),
		j(home, ".config", "curlrc"),
		j(gitBin, ".curlrc"), j(gitBin, "_curlrc"),
	}
	if strings.Join(withoutXDG, "|") != strings.Join(wantWithout, "|") {
		t.Errorf("without XDG_CONFIG_HOME:\n got %v\nwant %v", withoutXDG, wantWithout)
	}

	withXDG := configCandidates(map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home, "USERPROFILE": profile, "APPDATA": ""}, binary)
	wantWith := []string{
		j(xdg, "curlrc"),
		j(home, ".curlrc"),
		j(profile, ".curlrc"),
		j(profile, "Application Data", ".curlrc"),
		j(gitBin, ".curlrc"), j(gitBin, "_curlrc"),
	}
	if strings.Join(withXDG, "|") != strings.Join(wantWith, "|") {
		t.Errorf("with XDG_CONFIG_HOME:\n got %v\nwant %v", withXDG, wantWith)
	}
}

// A place on another machine is not opened - inviolable rule 16 - and whether a
// file waits there is then unknown, which the row says.
func TestAConfigurationFileOnAnotherMachineIsNotLookedPast(t *testing.T) {
	share := hostSpelling(`\\files\home\jdoe`)
	source := func(path string) (io.ReadCloser, error) {
		return nil, &file.RemotePath{Path: path}
	}
	found, unreadable := configFile(source, configCandidates(map[string]string{"HOME": share}, system32Curl))
	if found != "" || !strings.Contains(unreadable, "not on this machine") {
		t.Errorf("a place on another machine was looked past: found %q, said %q", found, unreadable)
	}
}

// A directory named like the file opens and does not read, and curl passes it
// over - so does this.
func TestADirectoryNamedLikeTheFileIsPassedOver(t *testing.T) {
	profile := hostSpelling(`C:\Users\jdoe`)
	directory := filepath.Join(profile, ".curlrc")
	beside := filepath.Join(winSystem32, ".curlrc")
	source := func(path string) (io.ReadCloser, error) {
		switch path {
		case directory:
			return io.NopCloser(failingReader{}), nil
		case beside:
			return io.NopCloser(strings.NewReader("")), nil
		}
		return nil, errors.New("no such file")
	}
	found, _ := configFile(source, configCandidates(map[string]string{"USERPROFILE": profile}, system32Curl))
	if found != beside {
		t.Errorf("found %q, want the empty file beside the binary - a directory is not a configuration file", found)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("is a directory") }

// THE OTHER PLATFORM BACKENDS ASK THE PLATFORM TOO, and a bundle in the
// environment does not change that - a row read from it would be a verdict
// about a file the build never opens. Nothing here measured which store such a
// build reads, so it names none and says so.
func TestAnotherPlatformBackendIsNotJudgedByABundle(t *testing.T) {
	store := storeFor(context.Background(), versionSaying("curl 8.21.0 (x86_64-apple-darwin) libcurl/8.21.0 SecureTransport"),
		sourceOf("/bundle.crt"), Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{CABundle: "/bundle.crt"}, atNoon())

	if store.StoreForm != report.StoreSystem || store.StorePath != "" {
		t.Errorf("a platform build was pointed at the bundle in the environment: %+v", store)
	}
	if store.TrustsPresentedChain != nil || store.DefersTo != nil {
		t.Errorf("a platform build nothing measured produced an answer: %+v", store)
	}
	if !strings.Contains(store.NotAssessed, "platform store") {
		t.Errorf("the reason does not say the platform answers: %q", store.NotAssessed)
	}
}

// AN UNRECOGNISED BACKEND IS UNKNOWN AND NEVER A GUESS. Picking the commonest
// one and generating a fix for it is how somebody runs a command that does
// nothing while waiting for it to work.
func TestAnUnknownBackendIsUnassessedRatherThanAssumed(t *testing.T) {
	store := storeFor(context.Background(), versionSaying("curl 9.0.0 libcurl/9.0.0 SomeNewTLS"),
		sourceOf(), Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, Environment{}, atNoon())

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
		sourceOf(), Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{}, atNoon())

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
		sourceOf(), Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{CABundle: "/absent/bundle.crt"}, atNoon())

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
	store := storeFor(context.Background(), run, sourceOf(), Install{Path: `C:\curl.exe`}, [][]byte{{0x30}}, Environment{}, atNoon())

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
		[]string{winSystem32, winSystem32Loud, hostSpelling(`C:\git\bin`), hostSpelling(`C:\empty`)}, Environment{}, atNoon)(context.Background(), [][]byte{{0x30}})

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
	stores, err := Probe(sourceOf(), noLinks, nil, []string{`C:\empty`}, Environment{}, atNoon)(context.Background(), nil)
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
		sourceOf("/bundle.crt"), Install{Path: "/usr/bin/curl"}, [][]byte{{0x30}}, Environment{CABundle: "/bundle.crt"}, atNoon())

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
