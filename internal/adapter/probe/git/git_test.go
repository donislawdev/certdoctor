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

// sourceOf turns a map into the file port, so these tests touch no disk.
//
// PATHS ARE COMPARED AFTER filepath.Clean BECAUSE THE PROBE STORES THEM THAT
// WAY. On Windows Clean also turns forward slashes into backslashes, and git
// configs on this machine are written with forward slashes - so a fixture keyed
// on the raw string would miss on Windows and hit on Linux, which is a test that
// passes for the wrong reason on one of them.
func sourceOf(files map[string]string) func(string) (io.ReadCloser, error) {
	cleaned := make(map[string]string, len(files))
	for path, body := range files {
		cleaned[filepath.Clean(path)] = body
	}
	return func(path string) (io.ReadCloser, error) {
		body, ok := cleaned[filepath.Clean(path)]
		if !ok {
			return nil, errors.New("no such file")
		}
		return io.NopCloser(strings.NewReader(body)), nil
	}
}

// A DIRECTORY IS NOT AN INSTALLATION - ADR48 part 2. Measured on this machine
// for Java: two Program Files\Java\latest directories with no store inside. A
// row invented from a name would be a claim about a store nobody has.
func TestOnlyAReadableConfigCountsAsAnInstall(t *testing.T) {
	source := sourceOf(map[string]string{`C:\Program Files\Git\etc\gitconfig`: "[http]\n"})
	found := find(source, []string{
		`C:\Program Files\Git\etc\gitconfig`,
		`C:\Program Files (x86)\Git\etc\gitconfig`,
	})
	if len(found) != 1 {
		t.Fatalf("found %d installs, want 1 - the second config is not there", len(found))
	}
	if found[0].Root != `C:\Program Files\Git` {
		t.Errorf("root %q, want the install directory", found[0].Root)
	}
	if found[0].Architecture != "x64" {
		t.Errorf("architecture %q, want x64", found[0].Architecture)
	}
}

// Two installs differing ONLY by "(x86)" have separate stores and separate
// answers, so the row has to say which one it is.
func TestTheBitnessComesFromThePath(t *testing.T) {
	source := sourceOf(map[string]string{`C:\Program Files (x86)\Git\etc\gitconfig`: "[http]\n"})
	found := find(source, []string{`C:\Program Files (x86)\Git\etc\gitconfig`})
	if len(found) != 1 || found[0].Architecture != "x86" {
		t.Fatalf("got %+v, want one x86 install", found)
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
	values := parse(sourceOf(map[string]string{"cfg": config}), "cfg")
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
	if got := parse(sourceOf(nil), "absent"); len(got) != 0 {
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

	settings := readSettings(source, []string{system, "/home/jdoe/.gitconfig"})
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
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
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
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
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

	store := storeFor(source, Install{Root: "/git", Architecture: "x64"}, settingsFor("/bundle.crt"), [][]byte{leafDER})

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

	store := storeFor(source, Install{Root: "/git"}, settingsFor("/bundle.crt"), [][]byte{leafDER})

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
	store := storeFor(sourceOf(nil), Install{Root: "/git"}, settingsFor("/gone.crt"), [][]byte{leafDER})

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
	store := storeFor(source, Install{Root: "/git"}, settingsFor("/bundle.crt"), [][]byte{leafDER})

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
	store := storeFor(sourceOf(nil), Install{Root: "/git"}, settings, [][]byte{leafDER})

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
	store := storeFor(sourceOf(nil), Install{Root: "/git"}, settings, [][]byte{leafDER})

	if store.TrustsPresentedChain != nil {
		t.Fatal("an unknown backend produced a verdict")
	}
	if !strings.Contains(store.NotAssessed, "nss") || !strings.Contains(store.NotAssessed, "global") {
		t.Errorf("the row names neither the backend nor where it was set: %q", store.NotAssessed)
	}
}

func TestOpensslWithNoBundleNamedSaysWhatItWouldRead(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	settings := Settings{Backend: "openssl", BackendLevel: "system"}
	store := storeFor(sourceOf(nil), Install{Root: "/git"}, settings, [][]byte{leafDER})

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
	probe := Probe(sourceOf(nil), nil)
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

	stores, err := Probe(source, nil)(t.Context(), [][]byte{leafDER})
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
