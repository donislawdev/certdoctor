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
	"io/fs"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/probe"
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
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
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

	stores, err := Probe(source, noLinks, noFiles, nil, []string{"/usr/bin"}, Environment{}, atNoon)(t.Context(), [][]byte{{0x30}})
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
	settings := readSettings(source, found[0].SystemConfig, Environment{})
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
	entries, _, err := parseConfig([]byte(config))
	if err != nil {
		t.Fatalf("an ordinary config was refused: %v", err)
	}
	values := map[string]string{}
	for _, e := range entries {
		values[e.key] = e.value
	}
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
	settings := readSettings(sourceOf(nil), "/absent", Environment{Home: Variable{Value: "/home/jdoe", Set: true}})
	if settings.Unreadable != "" || settings.CAInfoLevel != "" {
		t.Errorf("missing files produced %+v", settings)
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

	settings := readSettings(source, system, Environment{Home: Variable{Value: "/home/jdoe", Set: true}})
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

	store := storeFor(t.Context(), probe.Ports{Source: source}, noFiles, Install{Instance: "/usr/bin/git", Root: "/usr/bin", Architecture: "x64"}, settingsFor("/bundle.crt"), Environment{}, [][]byte{leafDER}, atNoon())

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

	store := storeFor(t.Context(), probe.Ports{Source: source}, noFiles, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settingsFor("/bundle.crt"), Environment{}, [][]byte{leafDER}, atNoon())

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
	store := storeFor(t.Context(), probe.Ports{Source: sourceOf(nil)}, noFiles, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settingsFor("/gone.crt"), Environment{}, [][]byte{leafDER}, atNoon())

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
	store := storeFor(t.Context(), probe.Ports{Source: source}, noFiles, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settingsFor("/bundle.crt"), Environment{}, [][]byte{leafDER}, atNoon())

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
	store := storeFor(t.Context(), probe.Ports{Source: sourceOf(nil)}, noFiles, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settings, Environment{}, [][]byte{leafDER}, atNoon())

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
	store := storeFor(t.Context(), probe.Ports{Source: sourceOf(nil)}, noFiles, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settings, Environment{}, [][]byte{leafDER}, atNoon())

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
	store := storeFor(t.Context(), probe.Ports{Source: sourceOf(nil)}, noFiles, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, Settings{}, Environment{}, [][]byte{leafDER}, atNoon())

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
	store := storeFor(t.Context(), probe.Ports{Source: sourceOf(nil)}, noFiles, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settings, Environment{}, [][]byte{leafDER}, atNoon())

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
	probe := Probe(sourceOf(nil), noLinks, noFiles, nil, nil, Environment{}, atNoon)
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

	stores, err := Probe(source, noLinks, noFiles, nil, nil, Environment{}, atNoon)(t.Context(), [][]byte{leafDER})
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

	stores, err := Probe(source, noLinks, noFiles, nil, []string{gitCmdDir, gitMingwDir}, Environment{}, atNoon)(t.Context(), [][]byte{leafDER})
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
	const config = "[http]\n\tsslCAInfo = /a.crt\n"
	source := func(path string) (io.ReadCloser, error) {
		if filepath.Clean(path) != filepath.Clean("/etc/gitconfig") {
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
		}
		return io.NopCloser(io.MultiReader(strings.NewReader(config), iotest.ErrReader(errors.New("device gone")))), nil
	}
	settings := readSettings(source, "/etc/gitconfig", Environment{})
	if !strings.Contains(settings.Unreadable, "device gone") || settings.CAInfoLevel != "" {
		t.Errorf("a read that stopped halfway came back as %+v", settings)
	}

	// THE TWIN. An ordinary config still reads and reports nothing wrong, or
	// this rule would turn every machine's git into an unassessed row.
	settings = readSettings(sourceOf(map[string]string{"/etc/gitconfig": config}), "/etc/gitconfig", Environment{})
	if settings.Unreadable != "" || settings.CAInfo != "/a.crt" {
		t.Errorf("an ordinary config read as %+v", settings)
	}
}

// THE PORT IS A LOOKUP BECAUSE SET-AND-EMPTY IS AN ANSWER - http.c of git 2.54.0
// acts on getenv returning anything at all, and S26 measured an empty
// GIT_SSL_NO_VERIFY switching verification off.
func TestTheEnvironmentIsReadThroughTheLookupItIsHanded(t *testing.T) {
	asked := map[string]bool{}
	env := EnvironmentFrom(func(name string) (string, bool) {
		asked[name] = true
		switch name {
		case "GIT_SSL_NO_VERIFY", "GIT_SSL_CAINFO":
			return "", true
		}
		return "", false
	}, "linux")
	if !env.NoVerify || env.CAInfo != (Variable{Set: true}) || env.CAPath.Set || env.Platform != "linux" {
		t.Errorf("read %+v, want empty-and-set told apart from unset", env)
	}
	want := []string{"GIT_SSL_NO_VERIFY", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "HOME", "HOMEDRIVE", "HOMEPATH",
		"USERPROFILE", "SystemRoot", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
		"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"}
	for _, name := range want {
		if !asked[name] {
			t.Errorf("the lookup was never asked for %s", name)
		}
	}
	if len(asked) != len(want) {
		t.Errorf("the lookup was asked for %d variables, want the %d git reads: %v", len(asked), len(want), asked)
	}
}

// GIT_SSL_CAINFO WINS OVER http.sslCAInfo - the defect ADR110 part 1 found: Git
// for Windows with sslBackend=openssl and a CA file in its configuration got a
// verdict about that file while GIT_SSL_CAINFO sent git to another one.
func TestGitSSLCAInfoWinsOverTheConfiguration(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{"/env.crt": string(anchorPEM), "/config.crt": "no certificate here"})

	store := storeFor(t.Context(), probe.Ports{Source: source}, noFiles, Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settingsFor("/config.crt"),
		Environment{CAInfo: Variable{Value: "/env.crt", Set: true}}, [][]byte{leafDER}, atNoon())
	if store.StorePath != filepath.Clean("/env.crt") || store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
		t.Errorf("got %+v, want the verdict of the file GIT_SSL_CAINFO names", store)
	}
}

// An empty GIT_SSL_CAINFO is handed to libcurl as a file name, so the configured
// file is not what git reads - and what it reads instead was not established.
func TestAnEmptyGitSSLCAInfoIsNotTheConfiguredFile(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	store := storeFor(t.Context(), probe.Ports{Source: sourceOf(map[string]string{"/config.crt": string(anchorPEM)})}, noFiles,
		Install{Instance: "/usr/bin/git", Root: "/usr/bin"}, settingsFor("/config.crt"),
		Environment{CAInfo: Variable{Set: true}}, [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain != nil || store.StorePath != "" || !strings.Contains(store.NotAssessed, "set and empty") {
		t.Errorf("got %+v, want undetermined saying the variable is empty", store)
	}
}

// A DIRECTORY HANDED TO libcurl LEAVES THE ROW WITHOUT A VERDICT, and the
// environment names it over the configuration.
func TestADirectoryHandedToLibcurlLeavesTheRowUndetermined(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{"/bundle.crt": string(anchorPEM)})
	install := Install{Instance: "/usr/bin/git", Root: "/usr/bin"}
	settings := settingsFor("/bundle.crt")
	settings.CAPath, settings.CAPathLevel = "/config/certs", "global"

	store := storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, settings, Environment{}, [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "http.sslCAPath") {
		t.Errorf("configured directory: got %+v, want undetermined naming http.sslCAPath", store)
	}
	store = storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, settings, Environment{CAPath: Variable{Value: "/env/certs", Set: true}},
		[][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "GIT_SSL_CAPATH") {
		t.Errorf("directory from the environment: got %+v, want undetermined naming GIT_SSL_CAPATH", store)
	}
}

// A GIT THAT DOES NOT VERIFY ASKS NO STORE, whichever backend it names, and a
// value git would stop on is said to be unread rather than guessed.
func TestVerificationSwitchedOffAsksNoStore(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{"/bundle.crt": string(anchorPEM)})
	install := Install{Instance: "/usr/bin/git", Root: "/usr/bin"}
	with := func(value, level string) Settings {
		s := settingsFor("/bundle.crt")
		s.Verify, s.VerifyLevel = value, level
		return s
	}
	off := map[string]struct {
		settings Settings
		env      Environment
		want     string
	}{
		"GIT_SSL_NO_VERIFY":                    {settingsFor("/bundle.crt"), Environment{NoVerify: true}, "GIT_SSL_NO_VERIFY"},
		"GIT_SSL_NO_VERIFY on schannel":        {Settings{Backend: "schannel"}, Environment{NoVerify: true}, "does not verify"},
		"sslVerify false":                      {with("false", "global"), Environment{}, "does not verify"},
		"sslVerify empty":                      {with("", "system"), Environment{}, "does not verify"},
		"sslVerify zero":                       {with("0", "system"), Environment{}, "does not verify"},
		"sslVerify Off":                        {with("Off", "system"), Environment{}, "does not verify"},
		"sslVerify with a suffix git stops on": {with("1k", "system"), Environment{}, "does not read as true or false"},
	}
	for name, c := range off {
		store := storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, c.settings, c.env, [][]byte{leafDER}, atNoon())
		if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, c.want) {
			t.Errorf("%s: got %+v, want undetermined saying %q", name, store, c.want)
		}
	}
	// THE TWIN: verification on, in any spelling git reads as true, leaves the
	// file to decide.
	for _, value := range []string{"true", "Yes", "on", "1", "-3"} {
		store := storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, with(value, "system"), Environment{}, [][]byte{leafDER}, atNoon())
		if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
			t.Errorf("sslVerify %q: got %+v, want the bundle's verdict", value, store)
		}
	}
}

// A key standing alone is true to git, so it overrides an earlier false.
func TestAKeyStandingAloneIsTrue(t *testing.T) {
	source := sourceOf(map[string]string{
		"/etc/gitconfig":        "[http]\n\tsslVerify = false\n",
		"/home/jdoe/.gitconfig": "[http]\n\tsslVerify\n",
	})
	settings := readSettings(source, "/etc/gitconfig", Environment{Home: Variable{Value: "/home/jdoe", Set: true}})
	if settings.Verify != "true" || settings.VerifyLevel != "global" {
		t.Errorf("sslVerify %q at %q, want the bare global key read as true", settings.Verify, settings.VerifyLevel)
	}
	if why := verificationOff(settings, Environment{}); why != "" {
		t.Errorf("verification reported off: %q", why)
	}
}

// NO BACKEND NAMED AND A FILE NAMED: on Linux the file is read, measured by S26
// for git on GnuTLS and on OpenSSL. Elsewhere nothing was measured, and the row
// stays what it was.
func TestAFileNamedWithNoBackendIsReadOnLinuxAlone(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	source := sourceOf(map[string]string{"/bundle.crt": string(anchorPEM)})
	install := Install{Instance: "/usr/bin/git", Root: "/usr/bin"}
	settings := Settings{CAInfo: "/bundle.crt", CAInfoLevel: "system"}

	store := storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, settings, Environment{Platform: "linux"}, [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain || store.StoreForm != report.StoreFile {
		t.Errorf("on Linux: got %+v, want the file's verdict", store)
	}
	store = storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, settings, Environment{Platform: "windows"}, [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "libcurl") {
		t.Errorf("on Windows: got %+v, want the row it always was", store)
	}
	store = storeFor(t.Context(), probe.Ports{Source: source}, noFiles, install, Settings{}, Environment{Platform: "linux"}, [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "compiled into it") {
		t.Errorf("nothing named on Linux: got %+v, want the build-time sentence", store)
	}
}

// NOTHING NAMED ON LINUX, NO BACKEND NAMED: the distribution's own git defers to
// the platform store - ADR110, measured by S26 for the Debian and Alpine
// packages. An install found without a binary has no package to ask about, and
// a NAMED backend never defers, even the one the library was built with.
func TestTheDistributionsGitNamingNothingDefersToThePlatformStore(t *testing.T) {
	source := sourceOf(map[string]string{
		"/etc/os-release":                    "ID=debian\n",
		"/var/lib/dpkg/info/git.list":        "/usr/bin/git\n",
		"/etc/ssl/certs/ca-certificates.crt": "bundle",
	})
	ports := probe.Ports{Source: source}
	linux := Environment{Platform: "linux"}
	onPath := Install{Instance: "/usr/bin/git", Root: "/usr/bin", OnPath: true}

	store := storeFor(t.Context(), ports, noFiles, onPath, Settings{}, linux, [][]byte{{0x30}}, atNoon())
	want := report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: "debian"}
	if store.DefersTo == nil || *store.DefersTo != want || store.StorePath != "" || store.TrustsPresentedChain != nil {
		t.Errorf("got %+v, want a row deferring to system-store debian", store)
	}

	byConfig := Install{Instance: "/", Root: "/", SystemConfig: "/etc/gitconfig"}
	store = storeFor(t.Context(), ports, noFiles, byConfig, Settings{}, linux, [][]byte{{0x30}}, atNoon())
	if store.DefersTo != nil || !strings.HasSuffix(store.NotAssessed, "no git binary was found for this install, so "+
		"whether it is debian's own build was not established") {
		t.Errorf("an install found by its configuration: got %q", store.NotAssessed)
	}

	named := Settings{Backend: "openssl", BackendLevel: "system"}
	store = storeFor(t.Context(), ports, noFiles, onPath, named, linux, [][]byte{{0x30}}, atNoon())
	if store.DefersTo != nil || !strings.HasPrefix(store.NotAssessed, "git is set to use openssl") {
		t.Errorf("a named backend: got %q", store.NotAssessed)
	}

	// A DIRECTORY NAMED ALONE names something too, so the row says what it
	// names rather than deferring.
	directory := Environment{Platform: "linux", CAPath: Variable{Value: "/etc/ssl/certs", Set: true}}
	store = storeFor(t.Context(), ports, noFiles, onPath, Settings{}, directory, [][]byte{{0x30}}, atNoon())
	if store.DefersTo != nil || !strings.Contains(store.NotAssessed, "GIT_SSL_CAPATH names the directory") {
		t.Errorf("a directory named: got %q", store.NotAssessed)
	}
}

// A REFUSAL BY THE NAMED FILE IS WEIGHED AGAINST THE BUILD'S DIRECTORIES -
// decided by the owner 2026-10-20 on S26: git from the Debian and Alpine
// packages trusted a root kept only in /etc/ssl/certs while http.sslCAInfo named
// a file without it. On Windows nothing was measured, so the refusal stands.
func TestARefusalByTheNamedFileIsWeighedAgainstTheBuildsDirectories(t *testing.T) {
	ours, leafDER := anchorAndLeaf(t)
	other, _ := anchorAndLeaf(t)
	source := sourceOf(map[string]string{"/bundle.crt": string(other), "/etc/ssl/certs/ours.pem": string(ours)})
	files := listOf(map[string][]string{"/etc/ssl/certs": {"/etc/ssl/certs/ours.pem"}})
	install := Install{Instance: "/usr/bin/git", Root: "/usr/bin"}

	store := storeFor(t.Context(), probe.Ports{Source: source}, files, install, settingsFor("/bundle.crt"), Environment{Platform: "linux"}, [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "/etc/ssl/certs") ||
		!strings.Contains(store.NotAssessed, "http.sslCAInfo") {
		t.Errorf("on Linux: got %+v, want undetermined naming the directory and the key", store)
	}
	store = storeFor(t.Context(), probe.Ports{Source: source}, files, install, settingsFor("/bundle.crt"), Environment{Platform: "windows"}, [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain || store.TrustFailure != report.UnknownAuthority {
		t.Errorf("on Windows: got %+v, want the file's refusal to stand", store)
	}
}

// listOf is the directory port over a fixed set of directories.
func listOf(dirs map[string][]string) func(string) ([]string, error) {
	return func(path string) ([]string, error) {
		names, ok := dirs[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return names, nil
	}
}

// noFiles is a machine with no directory a build could read beside its file.
func noFiles(string) ([]string, error) { return nil, fs.ErrNotExist }
