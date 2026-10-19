package git

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// hostSpelling is the twin of the one in probe/binaries_test.go, where the
// comment explains why all four of these test packages need it.
func hostSpelling(path string) string {
	return strings.ReplaceAll(path, `\`, string(filepath.Separator))
}

// The Windows install tree these fixtures describe, spelled for the host.
//
// THE SHAPE STAYS WINDOWS AND ONLY THE SEPARATOR FOLLOWS THE PLATFORM. What
// these tests exercise is path ARITHMETIC - filepath.Dir walking up from a
// config, segment matching against PATH - and that arithmetic needs separators
// the platform can take apart. Left Windows-spelled, filepath.Dir answers "."
// off Windows because the whole path is one element, and six tests here failed
// on exactly that while passing on the machine they were written on.
var (
	gitRoot      = hostSpelling(`C:\Program Files\Git`)
	gitCmdDir    = hostSpelling(`C:\Program Files\Git\cmd`)
	gitCmdExe    = hostSpelling(`C:\Program Files\Git\cmd\git.exe`)
	gitMingwDir  = hostSpelling(`C:\Program Files\Git\mingw64\bin`)
	gitMingwExe  = hostSpelling(`C:\Program Files\Git\mingw64\bin\git.exe`)
	gitSysConfig = hostSpelling(`C:\Program Files\Git\etc\gitconfig`)
)

// sourceOf turns a map into the file port, so these tests touch no disk.
//
// PATHS ARE COMPARED AFTER filepath.Clean BECAUSE THE PROBE STORES THEM THAT
// WAY. On Windows Clean also turns forward slashes into backslashes, and git
// configs on this machine are written with forward slashes - so a fixture keyed
// on the raw string would miss on Windows and hit on Linux, which is a test that
// passes for the wrong reason on one of them.
//
// IT IS THE HOST'S FILESYSTEM AND NOT A WINDOWS ONE, AND THAT DISTINCTION WAS
// MEASURED ON 2026-09-02. An earlier repair had this fake fold a backslash into
// the host separator, which made every Windows path resolve on Linux - including
// the raw entries of the production systemConfigs list, which conjured a third
// git installation out of a machine that has two. A fake more permissive than
// the disk it stands for invents subjects the code will never meet.
func sourceOf(files map[string]string) func(string) (io.ReadCloser, error) {
	key := func(path string) string { return filepath.Clean(path) }

	cleaned := make(map[string]string, len(files))
	for path, body := range files {
		cleaned[key(path)] = body
	}
	return func(path string) (io.ReadCloser, error) {
		body, ok := cleaned[key(path)]
		if !ok {
			return nil, errors.New("no such file")
		}
		return io.NopCloser(strings.NewReader(body)), nil
	}
}

// THE FALLBACK STILL NEEDS A FILE THAT IS THERE. Git for Windows can be
// installed without putting anything on PATH, so a system config with no binary
// beside it is a real installation - but a config that is NOT there is not one,
// and a row invented from a name would be a claim about a store nobody has,
// which is what ADR48 part 2 refuses for Java.
func TestAnInstallFoundOnlyByItsConfigIsStillFound(t *testing.T) {
	source := sourceOf(map[string]string{gitSysConfig: "[http]\n"})
	found := find(source, noLinks, []string{
		gitSysConfig,
		hostSpelling(`C:\Program Files (x86)\Git\etc\gitconfig`),
	}, nil)
	if len(found) != 1 {
		t.Fatalf("found %d installs, want 1 - the second config is not there", len(found))
	}
	if found[0].Root != gitRoot || found[0].Instance != gitRoot {
		t.Errorf("got %+v, want the install directory as both root and identity", found[0])
	}
	if found[0].OnPath {
		t.Error("an install nothing on PATH points at was reported as reachable by a typed command")
	}
	if found[0].Architecture != "x64" {
		t.Errorf("architecture %q, want x64", found[0].Architecture)
	}
}

// Two installs differing ONLY by "(x86)" have separate stores and separate
// answers, so the row has to say which one it is.
func TestTheBitnessComesFromThePath(t *testing.T) {
	source := sourceOf(map[string]string{`C:\Program Files (x86)\Git\etc\gitconfig`: "[http]\n"})
	found := find(source, noLinks, []string{`C:\Program Files (x86)\Git\etc\gitconfig`}, nil)
	if len(found) != 1 || found[0].Architecture != "x86" {
		t.Fatalf("got %+v, want one x86 install", found)
	}
}

// TestAGitWithNoConfigurationAtAllStillGetsARow is OBS72, and it is the whole
// point of this slice.
//
// MEASURED IN THE BENCH IMAGE 2026-08-19 AND AGAIN 2026-09-02: git 2.54.0 there
// has no config file at any level - "git config --list --show-origin" prints
// nothing and /etc/gitconfig does not exist - while /usr/bin/git sits there
// reading whatever store libcurl was built with. Proving installation by the
// CONFIGURATION dropped that git out of the matrix beside the runtimes that are
// genuinely absent. Inviolable rule 15 asks for an UNKNOWN carrying a reason,
// and there was not even a row for one to stand in.
func TestAGitWithNoConfigurationAtAllStillGetsARow(t *testing.T) {
	source := sourceOf(map[string]string{"/usr/bin/git": "ELF"})

	found := find(source, noLinks, systemConfigs, []string{"/usr/bin"})
	if len(found) != 1 {
		t.Fatalf("found %d installs, want 1 - the binary is there and the config is not", len(found))
	}
	if found[0].Instance != filepath.Clean("/usr/bin/git") {
		t.Errorf("the install is called %q, and the binary is what a person can act on", found[0].Instance)
	}
	if found[0].SystemConfig != "" {
		t.Errorf("a config was claimed at %q, and this machine has none", found[0].SystemConfig)
	}

	stores, err := Probe(source, noLinks, nil, []string{"/usr/bin"}, atNoon)(t.Context(), [][]byte{{0x30}})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if len(stores) != 1 {
		t.Fatalf("got %d rows, want 1", len(stores))
	}
	if stores[0].TrustsPresentedChain != nil {
		t.Error("a git whose store is compiled into libcurl produced a verdict about trust")
	}
	if !strings.Contains(stores[0].NotAssessed, "libcurl") {
		t.Errorf("the row does not say what decides the store: %q", stores[0].NotAssessed)
	}
}

// THE SYSTEM CONFIG IS FOUND NEXT TO THE BINARY, AND THE TWO DEPTHS ARE
// MEASURED - 2026-09-02, by asking each binary itself with
// "git config --list --show-origin --system". C:\Program Files\Git\cmd\git.exe
// answered with the config one directory up; C:\Program Files\Git\mingw64\bin\
// git.exe answered with the SAME file, two directories up, because its own
// mingw64\etc\gitconfig does not exist. Two up is also what reaches
// /etc/gitconfig from /usr/bin/git.
func TestTheSystemConfigIsFoundNextToTheBinary(t *testing.T) {
	source := sourceOf(map[string]string{
		gitCmdExe:    "MZ",
		gitMingwExe:  "MZ",
		gitSysConfig: "[http]\n\tsslBackend = openssl\n",
	})

	found := find(source, noLinks, nil, []string{gitCmdDir, gitMingwDir})
	if len(found) != 2 {
		t.Fatalf("found %d installs, want one per binary: %+v", len(found), found)
	}
	for _, install := range found {
		if install.SystemConfig != gitSysConfig {
			t.Errorf("%s reads %q, and both binaries answered with the same file", install.Instance, install.SystemConfig)
		}
		if !install.OnPath {
			t.Errorf("%s was found by walking PATH and does not say so", install.Instance)
		}
	}
}

// A CONFIG ALREADY CLAIMED BY A BINARY IS NOT A SECOND INSTALLATION. On this
// machine both git.exe name C:\Program Files\Git\etc\gitconfig, which is also
// in the fallback list - and without this the matrix would report three gits
// where there are two.
func TestAConfigAlreadyClaimedByABinaryIsNotASecondInstall(t *testing.T) {
	source := sourceOf(map[string]string{
		gitCmdExe:    "MZ",
		gitSysConfig: "[http]\n",
	})

	// THE FALLBACK LIST IS NAMED HERE RATHER THAN TAKEN FROM PRODUCTION, and
	// the reason is not tidiness. systemConfigs carries Windows and Unix
	// spellings in one list, while this fixture follows the host separator - so
	// off Windows the production entry could never match and the collision this
	// test is about would not happen at all. The rule under test is that a
	// config already claimed by a binary is not a second installation, and
	// naming the colliding path states it more plainly than borrowing a list
	// whose other entries have nothing to do with this scenario.
	found := find(source, noLinks, []string{gitSysConfig}, []string{gitCmdDir})
	if len(found) != 1 {
		t.Fatalf("found %d installs, want 1: %+v", len(found), found)
	}
	if !found[0].OnPath {
		t.Errorf("the surviving install is the config-only one: %+v", found[0])
	}
}

// A CONFIG FOUND NEXT TO A BINARY IS A SYSTEM CONFIG EVEN WHEN THE LIST HAS
// NEVER HEARD OF IT, and the level is the field that decides whether a
// colleague needs the same fix or the opposite one.
func TestAConfigFoundNextToABinaryIsReportedAtSystemLevel(t *testing.T) {
	config := hostSpelling(`C:\Program Files\Git\mingw64\etc\gitconfig`)
	source := sourceOf(map[string]string{
		gitMingwExe: "MZ",
		config:      "[http]\n\tsslBackend = openssl\n",
	})

	found := find(source, noLinks, nil, []string{gitMingwDir})
	if len(found) != 1 || found[0].SystemConfig != config {
		t.Fatalf("got %+v, want the config one directory up", found)
	}
	settings := readSettings(source, found[0].SystemConfig, nil)
	if settings.Backend != "openssl" || settings.BackendLevel != "system" {
		t.Errorf("backend %q at %q, want openssl at system", settings.Backend, settings.BackendLevel)
	}
}

// A BINARY FOUND BY WALKING PATH ANSWERS selected_by WITHOUT LOOKING AGAIN, and
// saying so is not what ADR48 part 4 bans: the ban is on letting PATH pick ONE
// installation, and this walked all of them.
func TestABinaryFoundOnPathIsSelectedByPath(t *testing.T) {
	got := selectedBy(Install{Instance: "/usr/bin/git", Root: "/usr/bin", OnPath: true}, nil)
	if len(got) != 1 || got[0] != "PATH" {
		t.Errorf("got %v, want PATH", got)
	}
}

func TestTheConfigParserReadsOnlyWhatItUnderstands(t *testing.T) {
	const config = `
# a comment
; another one
[core]
	autocrlf = true
[http]
	sslBackend = openssl
	sslCAInfo = C:/bundle.crt
`
	values, _ := parse(sourceOf(map[string]string{"cfg": config}), "cfg")
	if values["http.sslbackend"] != "openssl" {
		t.Errorf("backend %q, want openssl - keys are lower cased so case in the file cannot change the answer", values["http.sslbackend"])
	}
	if values["http.sslcainfo"] != "C:/bundle.crt" {
		t.Errorf("bundle %q", values["http.sslcainfo"])
	}
	if values["core.autocrlf"] != "true" {
		t.Errorf("a key outside [http] was lost, and the parser is meant to be general: %q", values["core.autocrlf"])
	}
	if _, present := values["sslbackend"]; present {
		t.Error("a key was recorded without its section, which would collide across sections")
	}
}

func TestAMissingConfigIsNotAnError(t *testing.T) {
	if got, _ := parse(sourceOf(nil), "absent"); len(got) != 0 {
		t.Errorf("a missing file produced %v", got)
	}
}

// GIT'S OWN PRECEDENCE: system first, then global, and later wins. The level
// travels with the value because it changes the advice - measured, on this
// machine the deciding value is at SYSTEM level, so a colleague whose install
// chose schannel needs the opposite fix.
func TestGlobalConfigOverridesSystemAndTheLevelIsRecorded(t *testing.T) {
	system := systemConfigs[0]
	source := sourceOf(map[string]string{
		system: "[http]\n\tsslBackend = openssl\n\tsslCAInfo = C:/system.crt\n",
		// AN INVENTED ACCOUNT NAME, from the list in personal_test.go. A fixture
		// proving precedence works with any name at all, so a real one would
		// prove nothing extra and publish something instead.
		"/home/jdoe/.gitconfig": "[http]\n\tsslCAInfo = C:/mine.crt\n",
	})

	settings := readSettings(source, system, []string{"/home/jdoe/.gitconfig"})
	if settings.Backend != "openssl" || settings.BackendLevel != "system" {
		t.Errorf("backend %q at %q, want openssl at system", settings.Backend, settings.BackendLevel)
	}
	if settings.CAInfo != "C:/mine.crt" || settings.CAInfoLevel != "global" {
		t.Errorf("bundle %q at %q, want the global one to win", settings.CAInfo, settings.CAInfoLevel)
	}
}

// anchorAndLeaf mints a tiny chain so verification can be exercised without a
// network and without a fixture nobody can regenerate.
func anchorAndLeaf(t *testing.T) (anchorPEM []byte, leafDER []byte) {
	t.Helper()

	anchorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no key: %v", err)
	}
	anchorTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certdoctor test anchor"},
		NotBefore:             atNoon().Add(-time.Hour),
		NotAfter:              atNoon().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	anchorDER, err := x509.CreateCertificate(rand.Reader, anchorTemplate, anchorTemplate, &anchorKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatalf("no anchor: %v", err)
	}
	anchor, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		t.Fatalf("anchor will not parse: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "partner.test"},
		DNSNames:     []string{"partner.test"},
		NotBefore:    atNoon().Add(-time.Hour),
		NotAfter:     atNoon().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTemplate, anchor, &leafKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatalf("no leaf: %v", err)
	}

	var bundle bytes.Buffer
	if err := pem.Encode(&bundle, &pem.Block{Type: "CERTIFICATE", Bytes: anchorDER}); err != nil {
		t.Fatalf("no bundle: %v", err)
	}
	return bundle.Bytes(), leafDER
}

func settingsFor(bundle string) Settings {
	return Settings{Backend: "openssl", BackendLevel: "system", CAInfo: bundle, CAInfoLevel: "system"}
}

func TestABundleHoldingTheAnchorTrustsTheChain(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{"/bundle.crt": string(anchorPEM)})

	store := storeFor(source, Install{Instance: "/usr/bin/git", Root: "/usr/bin", Architecture: "x64"}, settingsFor("/bundle.crt"), [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain == nil {
		t.Fatalf("no verdict was reached: %s", store.NotAssessed)
	}
	if !*store.TrustsPresentedChain {
		t.Error("a bundle holding the issuing anchor did not trust the chain")
	}
	if store.TrustAnchorCount != 1 {
		t.Errorf("counted %d anchors, want 1", store.TrustAnchorCount)
	}
	if store.Backend != "openssl" || store.StoreForm.String() != "file" {
		t.Errorf("the row does not describe a file store from openssl: %+v", store)
	}
}

// DISTRUST IS A VERDICT, not a failure - it is the answer the matrix exists to
// produce, and it must never be confused with a store that could not be read.
func TestABundleWithoutTheAnchorDoesNotTrustTheChain(t *testing.T) {
	otherPEM, _ := anchorAndLeaf(t)
	_, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{"/bundle.crt": string(otherPEM)})

	store := storeFor(source, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settingsFor("/bundle.crt"), [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain == nil {
		t.Fatalf("an unrelated bundle produced no verdict: %s", store.NotAssessed)
	}
	if *store.TrustsPresentedChain {
		t.Error("a bundle holding an unrelated anchor trusted the chain")
	}
	if store.NotAssessed != "" {
		t.Errorf("a reached verdict also carries a reason it could not be reached: %q", store.NotAssessed)
	}
}

// AN UNREADABLE BUNDLE IS UNKNOWN WITH A REASON, NEVER A FAILURE TO TRUST -
// inviolable rule 15. It is also a real diagnosis: the file port refuses a path
// that would leave this machine, so "your bundle is on a file server" arrives
// here as exactly this row.
func TestAnUnreadableBundleIsUnknownRatherThanDistrust(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	store := storeFor(sourceOf(nil), Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settingsFor("/gone.crt"), [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Fatal("a bundle that could not be read produced a verdict about trust")
	}
	if !strings.Contains(store.NotAssessed, "could not be read") {
		t.Errorf("the row does not say why: %q", store.NotAssessed)
	}
}

func TestABundleWithNoCertificatesSaysSo(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{"/bundle.crt": "not a certificate at all\n"})
	store := storeFor(source, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settingsFor("/bundle.crt"), [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Fatal("an empty bundle produced a verdict")
	}
	if !strings.Contains(store.NotAssessed, "no certificate") {
		t.Errorf("the row does not say why: %q", store.NotAssessed)
	}
}

// THE ANSWER BELONGS TO ANOTHER PROBE AND THE ROW SAYS SO. Claiming trust here
// would mean this probe silently answered a question about the Windows store.
func TestSchannelDefersToTheSystemStoreProbe(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	settings := Settings{Backend: "schannel", BackendLevel: "system"}
	store := storeFor(sourceOf(nil), Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settings, [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Fatal("the git probe answered a question about the platform store")
	}
	if !strings.Contains(store.NotAssessed, "system-store") {
		t.Errorf("the row does not name who answers instead: %q", store.NotAssessed)
	}
}

func TestAnUnknownBackendIsNamedRatherThanGuessed(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	settings := Settings{Backend: "nss", BackendLevel: "global"}
	store := storeFor(sourceOf(nil), Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settings, [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Fatal("an unknown backend produced a verdict")
	}
	if !strings.Contains(store.NotAssessed, "nss") || !strings.Contains(store.NotAssessed, "global") {
		t.Errorf("the row names neither the backend nor where it was set: %q", store.NotAssessed)
	}
}

// TestNoBackendNamedIsTheORDINARYCaseAndSaysSo.
//
// MEASURED 2026-08-19: git 2.54.0 in a Debian based image has NO gitconfig at
// any level, so http.sslBackend is simply absent - and that is how most
// installations outside Windows arrive. The row used to answer "a backend this
// program does not know how to follow", which reported OUR ignorance as a fact
// about somebody's machine: the shape OBS67 records. What is unreadable here is
// the bundle libcurl was compiled with, and the row says that instead.
func TestNoBackendNamedIsTheOrdinaryCaseAndSaysSo(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	store := storeFor(sourceOf(nil), Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, Settings{}, [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Fatal("a git naming no backend produced a verdict about trust")
	}
	if strings.Contains(store.NotAssessed, "does not know how to follow") {
		t.Errorf("an absent backend is reported as an unrecognised one: %q", store.NotAssessed)
	}
	if !strings.Contains(store.NotAssessed, "libcurl") {
		t.Errorf("the row does not say what decides the store instead: %q", store.NotAssessed)
	}
}

func TestOpensslWithNoBundleNamedSaysWhatItWouldRead(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	settings := Settings{Backend: "openssl", BackendLevel: "system"}
	store := storeFor(sourceOf(nil), Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settings, [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Fatal("openssl with no bundle named produced a verdict")
	}
	if !strings.Contains(store.NotAssessed, "build-time default") {
		t.Errorf("the row does not say what it would have read: %q", store.NotAssessed)
	}
}

// A runtime that is not here sits OUTSIDE the matrix - docs/20 rule 1 - and that
// is not an error.
func TestNoInstallFoundIsNotAnError(t *testing.T) {
	probe := Probe(sourceOf(nil), noLinks, nil, nil, atNoon)
	stores, err := probe(t.Context(), [][]byte{{0x30}})
	if err != nil {
		t.Fatalf("git not being installed came back as an error: %v", err)
	}
	if len(stores) != 0 {
		t.Errorf("got %d rows for a machine with no git", len(stores))
	}
}

func TestTheProbeProducesOneRowPerInstall(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{
		systemConfigs[0]: "[http]\n\tsslBackend = openssl\n\tsslCAInfo = /bundle.crt\n",
		"/bundle.crt":    string(anchorPEM),
	})

	stores, err := Probe(source, noLinks, nil, nil, atNoon)(t.Context(), [][]byte{leafDER})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if len(stores) != 1 {
		t.Fatalf("got %d rows, want 1", len(stores))
	}
	if stores[0].SelectedBy == nil {
		t.Error("the row carries a nil selection list, and an empty one is the answer")
	}
	f := report.Finding{Kind: report.FindingTrustStore, Summary: "one row", Source: report.SourceDetected, TrustStore: &stores[0]}
	if breach := f.Breach(); breach != "" {
		t.Errorf("the probe produced a row the contract refuses: %s", breach)
	}
}

// ONE ROW PER BINARY, AND THE COST IS NAMED RATHER THAN HIDDEN - ADR74.
// Measured on this machine 2026-09-02: the two git.exe on PATH belong to ONE
// Git for Windows install and read the same bundle, so a person sees two rows
// saying the same thing. Folding them together was refused because the key
// would have to be the store, and in the bench image two DIFFERENT gits both
// have no config at all - so the fold would hide one of them, which is the
// silence this whole slice removes.
func TestEveryGitOnPathGetsItsOwnRow(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{
		gitCmdExe:     "MZ",
		gitMingwExe:   "MZ",
		gitSysConfig:  "[http]\n\tsslBackend = openssl\n\tsslCAInfo = /bundle.crt\n",
		"/bundle.crt": string(anchorPEM),
	})

	stores, err := Probe(source, noLinks, nil, []string{gitCmdDir, gitMingwDir}, atNoon)(t.Context(), [][]byte{leafDER})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if len(stores) != 2 {
		t.Fatalf("got %d rows, want one per binary", len(stores))
	}
	if stores[0].Instance == stores[1].Instance {
		t.Errorf("two rows carry the same identity %q, and a row nobody can attribute is a row nobody can act on", stores[0].Instance)
	}
	for _, store := range stores {
		if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
			t.Errorf("%s did not trust a chain its own bundle anchors: %s", store.Instance, store.NotAssessed)
		}
	}
}

// THE TRAP THIS FUNCTION EXISTS TO AVOID. "C:\Program Files\Git2\cmd" starts
// with "C:\Program Files\Git" as TEXT, so a prefix comparison would credit one
// installation with another one's presence on PATH - and the row would then tell
// somebody that the git they type is the one this report describes.
func TestPathSelectionMatchesOnASegmentAndNotOnText(t *testing.T) {
	install := Install{Root: gitRoot}

	if got := selectedBy(install, []string{hostSpelling(`C:\Program Files\Git2\cmd`)}); len(got) != 0 {
		t.Errorf("a neighbouring install claimed this one's place on PATH: %v", got)
	}
	if got := selectedBy(install, []string{gitCmdDir}); len(got) != 1 || got[0] != "PATH" {
		t.Errorf("the install on PATH was not recognised: %v", got)
	}
	// The root itself on PATH counts too.
	if got := selectedBy(install, []string{gitRoot}); len(got) != 1 {
		t.Errorf("the root on PATH was not recognised: %v", got)
	}
}

// AN EMPTY LIST IS AN ANSWER, NEVER A GAP - and it must not be nil, because the
// contract says nil is a statement about us rather than about the machine.
func TestAnInstallNothingSelectsGetsAnEmptyListRatherThanNil(t *testing.T) {
	got := selectedBy(Install{Root: `C:\Program Files\Git`}, []string{`C:\Windows\system32`})
	if got == nil {
		t.Fatal("an install nothing selects produced nil, which reads as nobody looked")
	}
	if len(got) != 0 {
		t.Errorf("got %v, want an empty list", got)
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

// TestAConfigThatCouldNotBeReadToTheEndIsNotReadAsEmpty is P3-1.
//
// bufio.Scanner stops on a line longer than its buffer and says so only when
// asked, and nobody asked. A config whose reading stopped halfway then looked
// exactly like a config that sets nothing - so the row would say git uses its
// built-in default, and a remediation command could name the wrong file, all
// from a read that never finished.
func TestAConfigThatCouldNotBeReadToTheEndIsNotReadAsEmpty(t *testing.T) {
	// One line longer than bufio.Scanner's own buffer.
	huge := "[http]\n\tsslCAInfo = " + strings.Repeat("x", 80*1024) + "\n"
	source := sourceOf(map[string]string{"/etc/gitconfig": huge})

	values, err := parse(source, "/etc/gitconfig")
	if err == nil {
		t.Fatal("a line this program could not read came back as a config with nothing in it")
	}
	if len(values) != 0 {
		t.Errorf("the half-read config still produced %d value(s)", len(values))
	}

	// THE TWIN. An ordinary config still parses and still reports no error, or
	// this rule would turn every machine's git into an unassessed row.
	ordinary := sourceOf(map[string]string{"/etc/gitconfig": "[http]\n\tsslBackend = openssl\n"})
	values, err = parse(ordinary, "/etc/gitconfig")
	if err != nil {
		t.Fatalf("an ordinary config reported %v", err)
	}
	if values["http.sslbackend"] != "openssl" {
		t.Errorf("an ordinary config parsed to %v", values)
	}

	// AND A FILE THAT IS NOT THERE IS STILL NOT A FAILURE TO READ ONE. Absence is
	// the ordinary state of a global gitconfig.
	if _, err = parse(sourceOf(nil), "/nowhere"); err != nil {
		t.Errorf("a config that does not exist reported %v", err)
	}
}
