package systemstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The Linux platform store - ADR104 - on a disk made of maps, so every rule is
// checked on every platform the tests run on. The layout is the real one: its
// paths are only keys here.

// fakeDisk is a disk where a path holds bytes, an error, or nothing at all, and
// that remembers every path anybody asked for.
type fakeDisk struct {
	files   map[string][]byte
	errs    map[string]error
	dirs    map[string][]string
	dirErrs map[string]error
	reads   []string
	listed  []string
}

func newDisk() *fakeDisk {
	return &fakeDisk{files: map[string][]byte{}, errs: map[string]error{}, dirs: map[string][]string{}, dirErrs: map[string]error{}}
}

func absent(path string) error { return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist} }

func (d *fakeDisk) source(path string) (io.ReadCloser, error) {
	d.reads = append(d.reads, path)
	if err, ok := d.errs[path]; ok {
		return nil, err
	}
	if data, ok := d.files[path]; ok {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	return nil, absent(path)
}

func (d *fakeDisk) list(path string) ([]string, error) {
	d.listed = append(d.listed, path)
	if err, ok := d.dirErrs[path]; ok {
		return nil, err
	}
	if names, ok := d.dirs[path]; ok {
		return names, nil
	}
	return nil, absent(path)
}

func pemOf(certificates ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certificates {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

const (
	debianBundle = "/etc/ssl/certs/ca-certificates.crt"
	rhelBundle   = "/etc/pki/tls/certs/ca-bundle.crt"
	alpineLink   = "/etc/ssl/cert.pem"
	certsDir     = "/etc/ssl/certs"
	pkiDir       = "/etc/pki/tls/certs"
)

// runOn asks the probe once and checks the row against the contract, so no test
// below can pass on a row the report would refuse.
func runOn(t *testing.T, d *fakeDisk, l layout, chain [][]byte) report.TrustStore {
	t.Helper()
	stores, err := bundleProbe(d.source, d.list, l, func() time.Time { return testClock })(context.Background(), chain)
	if err != nil || len(stores) != 1 {
		t.Fatalf("%d row(s), error %v - want exactly one row and no error", len(stores), err)
	}
	store := stores[0]
	finding := report.Finding{Kind: report.FindingTrustStore, Summary: "a row", Source: report.SourceDetected, TrustStore: &store}
	if broken := finding.Breach(); broken != "" {
		t.Errorf("the contract refuses this row: %s", broken)
	}
	if store.Runtime != report.RuntimeSystemStore || store.SelectedBy == nil || len(store.SelectedBy) != 0 {
		t.Errorf("runtime %q, selected by %v - want the platform store, selected by nothing", store.Runtime, store.SelectedBy)
	}
	return store
}

func isTrusted(s report.TrustStore) bool {
	return s.TrustsPresentedChain != nil && *s.TrustsPresentedChain && s.NotAssessed == ""
}

func isRefused(s report.TrustStore, failure report.TrustFailure) bool {
	return s.TrustsPresentedChain != nil && !*s.TrustsPresentedChain && s.TrustFailure == failure && s.NotAssessed == ""
}

func isUndetermined(s report.TrustStore, says string) bool {
	return s.TrustsPresentedChain == nil && s.TrustFailure == "" && s.TrustAnchorCount == 0 &&
		strings.Contains(s.NotAssessed, says)
}

// THE FIRST BUNDLE ON GO'S LIST IS THE STORE, and the ones after it are never
// read - a second file is a store this row does not speak for.
func TestTheFirstBundleOnGosListIsTheStore(t *testing.T) {
	ours, other := anAuthority(t, "ours"), anAuthority(t, "other")
	leaf := aLeaf(t, ours, leafOptions{})

	d := newDisk()
	d.files[debianBundle] = pemOf(ours.certificate, other.certificate)
	d.files[rhelBundle] = pemOf(other.certificate)
	store := runOn(t, d, linuxLayout, [][]byte{leaf.Raw})
	if !isTrusted(store) || store.StorePath != debianBundle || store.StoreForm != report.StoreFile {
		t.Fatalf("got trusted=%v path %q form %q (%q), want the first bundle trusting it", isTrusted(store),
			store.StorePath, store.StoreForm, store.NotAssessed)
	}
	if store.TrustAnchorCount != 2 {
		t.Errorf("%d anchors counted, want the 2 in the bundle", store.TrustAnchorCount)
	}

	d = newDisk()
	d.files[debianBundle] = pemOf(other.certificate)
	d.files[rhelBundle] = pemOf(ours.certificate)
	store = runOn(t, d, linuxLayout, [][]byte{leaf.Raw})
	if !isRefused(store, report.UnknownAuthority) || store.StorePath != debianBundle {
		t.Errorf("got %+v, want the first bundle refusing - the second one holds the signer and is not this store", store)
	}
	if slices.Contains(d.reads, rhelBundle) {
		t.Error("the second bundle on the list was read, so the row was built from a file nobody here asked about")
	}
}

// A MISSING BUNDLE IS PASSED OVER, and the path the row names is the one that
// exists - on Alpine a link Go reaches last.
func TestALaterBundleIsTheStoreWhenTheEarlierOnesAreMissing(t *testing.T) {
	ours := anAuthority(t, "ours")
	d := newDisk()
	d.files[alpineLink] = pemOf(ours.certificate)
	store := runOn(t, d, linuxLayout, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
	if !isTrusted(store) || store.StorePath != alpineLink {
		t.Errorf("got path %q (%q), want %s trusting the chain", store.StorePath, store.NotAssessed, alpineLink)
	}
}

// A BUNDLE THAT EXISTS AND CANNOT BE READ IS THE STORE, UNREAD - not a reason to
// move on. Go moves on, OpenSSL does not, and the next file would be a store
// some programs here never read, reported as the one they do.
func TestABundleThatCannotBeReadIsNotSkipped(t *testing.T) {
	ours := anAuthority(t, "ours")
	d := newDisk()
	d.errs[debianBundle] = &fs.PathError{Op: "open", Path: debianBundle, Err: fs.ErrPermission}
	d.files[rhelBundle] = pemOf(ours.certificate)
	store := runOn(t, d, linuxLayout, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
	if !isUndetermined(store, "could not be read") || store.StorePath != debianBundle {
		t.Errorf("got %+v, want the first bundle named as unreadable", store)
	}
	if slices.Contains(d.reads, rhelBundle) {
		t.Error("the next bundle was read in its place")
	}
}

// NO BUNDLE ANYWHERE - measured in debian:trixie-slim and ubuntu:24.04 - is
// undetermined, says what is missing, and names no path because there is none.
func TestNoBundleAnywhereIsUndeterminedAndSaysWhatIsMissing(t *testing.T) {
	ours := anAuthority(t, "ours")
	d := newDisk()
	store := runOn(t, d, linuxLayout, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
	if !isUndetermined(store, "ca-certificates") || store.StoreForm != report.StoreSystem || store.StorePath != "" {
		t.Errorf("got %+v, want an undetermined row with no path that names the package", store)
	}
	for _, path := range linuxLayout.bundles {
		if !slices.Contains(d.reads, path) {
			t.Errorf("%s was never asked for, so the row cannot say there is no bundle", path)
		}
	}
}

// A TRUSTED CHAIN LEAVES THE DIRECTORIES UNREAD - a directory can add a signer
// and never take one away, so the bundle is already the answer.
func TestATrustedChainLeavesTheDirectoriesUnread(t *testing.T) {
	ours := anAuthority(t, "ours")
	d := newDisk()
	d.files[debianBundle] = pemOf(ours.certificate)
	d.dirs[certsDir] = []string{certsDir + "/ours.pem"}
	store := runOn(t, d, linuxLayout, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
	if !isTrusted(store) {
		t.Fatalf("got %+v, want trusted", store)
	}
	if len(d.listed) != 0 {
		t.Errorf("the directories %v were listed for a chain the bundle already trusts", d.listed)
	}
}

// A REFUSAL STANDS when the directories hold nothing that closes the chain - and
// both of Go's directories were looked at, with a dangling link passed over the
// way it is an ordinary leftover there.
func TestARefusalStandsWhenTheDirectoriesCloseNothing(t *testing.T) {
	ours, other := anAuthority(t, "ours"), anAuthority(t, "other")
	d := newDisk()
	d.files[debianBundle] = pemOf(other.certificate)
	d.dirs[certsDir] = []string{certsDir + "/other.pem", certsDir + "/dangling.pem"}
	d.files[certsDir+"/other.pem"] = pemOf(other.certificate)
	store := runOn(t, d, linuxLayout, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
	if !isRefused(store, report.UnknownAuthority) {
		t.Fatalf("got %+v, want a refusal for want of a signer", store)
	}
	if store.TrustAnchorCount != 1 {
		t.Errorf("%d anchors counted, want the bundle's 1 - the directories are evidence, not the store", store.TrustAnchorCount)
	}
	if !slices.Equal(d.listed, linuxLayout.directories.Paths) {
		t.Errorf("listed %v, want both of Go's directories in order", d.listed)
	}
}

// The row says how the bundle it read ends, from the bytes it read - ADR114 B13.
// The command appends to that file, and a file ending mid-line gets none.
func TestTheRowSaysHowTheBundleEnds(t *testing.T) {
	ours, other := anAuthority(t, "ours"), anAuthority(t, "other")
	cases := []struct {
		name   string
		bundle []byte
		want   report.FileEnd
	}{
		{"ending with a line feed", pemOf(other.certificate), report.FileEndLineBreak},
		{"ending mid-line", bytes.TrimSuffix(pemOf(other.certificate), []byte("\n")), report.FileEndMidLine},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDisk()
			d.files[debianBundle] = c.bundle
			store := runOn(t, d, linuxLayout, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
			if !isRefused(store, report.UnknownAuthority) {
				t.Fatalf("got %+v, want a refusal for want of a signer", store)
			}
			if store.FileEnd != c.want {
				t.Errorf("FileEnd %d, want %d", store.FileEnd, c.want)
			}
		})
	}
}

// A CERTIFICATE ONLY A DIRECTORY HOLDS turns the refusal into undetermined, and
// the sentence names the directory that closed it - decided by the owner
// 2026-10-15, because some programs here trust that chain and some do not.
func TestACertificateOnlyADirectoryHoldsLeavesTheAnswerToTheProgram(t *testing.T) {
	ours, other := anAuthority(t, "ours"), anAuthority(t, "other")
	for _, directory := range linuxLayout.directories.Paths {
		t.Run(directory, func(t *testing.T) {
			d := newDisk()
			d.files[debianBundle] = pemOf(other.certificate)
			d.dirs[directory] = []string{directory + "/ours.pem"}
			d.files[directory+"/ours.pem"] = pemOf(ours.certificate)
			store := runOn(t, d, linuxLayout, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
			if !isUndetermined(store, "depends on the program") || !strings.Contains(store.NotAssessed, directory) {
				t.Errorf("got %+v, want undetermined naming %s", store, directory)
			}
		})
	}
}

// A DIRECTORY THAT CANNOT BE READ leaves the refusal unproven - whether as a
// whole or one entry in it. A FAIL here would rest on files nobody looked at.
func TestADirectoryThatCannotBeReadLeavesTheRefusalUnproven(t *testing.T) {
	ours, other := anAuthority(t, "ours"), anAuthority(t, "other")
	denied := &fs.PathError{Op: "open", Path: certsDir, Err: fs.ErrPermission}
	cases := map[string]func(d *fakeDisk){
		"the directory": func(d *fakeDisk) { d.dirErrs[certsDir] = denied },
		"one entry of it": func(d *fakeDisk) {
			d.dirs[certsDir] = []string{certsDir + "/x.pem"}
			d.errs[certsDir+"/x.pem"] = denied
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			d := newDisk()
			d.files[debianBundle] = pemOf(other.certificate)
			spoil(d)
			store := runOn(t, d, linuxLayout, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
			if !isUndetermined(store, "could not be read in full") {
				t.Errorf("got %+v, want undetermined", store)
			}
		})
	}
}

// PAST EITHER CEILING THE ROW SAYS IT DID NOT LOOK, and it does not look - a
// directory over the entry ceiling has none of its entries opened.
func TestADirectoryPastItsCeilingIsNotRead(t *testing.T) {
	ours, other := anAuthority(t, "ours"), anAuthority(t, "other")
	small := linuxLayout
	small.directories.EntryCeiling, small.directories.ByteCeiling = 2, 4096

	d := newDisk()
	d.files[debianBundle] = pemOf(other.certificate)
	d.dirs[certsDir] = []string{certsDir + "/a", certsDir + "/b", certsDir + "/c"}
	store := runOn(t, d, small, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
	if !isUndetermined(store, "more than this program reads") {
		t.Errorf("over the entry ceiling: got %+v, want undetermined", store)
	}
	if slices.Contains(d.reads, certsDir+"/a") {
		t.Error("an entry of a directory over the ceiling was opened")
	}

	d = newDisk()
	d.files[debianBundle] = pemOf(other.certificate)
	d.dirs[certsDir] = []string{certsDir + "/big"}
	d.files[certsDir+"/big"] = bytes.Repeat([]byte("x"), 4096)
	store = runOn(t, d, small, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
	if !isUndetermined(store, "more than this program reads") {
		t.Errorf("over the byte ceiling: got %+v, want undetermined", store)
	}

	// The twin: exactly at both ceilings is read, and the refusal stands.
	d = newDisk()
	bundle := pemOf(other.certificate)
	d.files[debianBundle] = bundle
	d.dirs[certsDir] = []string{certsDir + "/a", certsDir + "/b"}
	d.files[certsDir+"/a"] = []byte("x")
	d.files[certsDir+"/b"] = bytes.Repeat([]byte("x"), 4096-len(bundle)-3)
	store = runOn(t, d, small, [][]byte{aLeaf(t, ours, leafOptions{}).Raw})
	if !isRefused(store, report.UnknownAuthority) {
		t.Errorf("at both ceilings: got %+v, want the refusal to stand", store)
	}
}

// A REFUSAL A DIRECTORY CANNOT OVERTURN IS NOT WEIGHED AGAINST ONE - a
// certificate out of date stays out of date whatever else is installed.
func TestAnExpiredChainIsNotWeighedAgainstTheDirectories(t *testing.T) {
	ours := anAuthority(t, "ours")
	d := newDisk()
	d.files[debianBundle] = pemOf(ours.certificate)
	expired := aLeaf(t, ours, leafOptions{notBefore: testClock.Add(-48 * time.Hour), notAfter: testClock.Add(-24 * time.Hour)})
	store := runOn(t, d, linuxLayout, [][]byte{expired.Raw})
	if !isRefused(store, report.Expired) {
		t.Errorf("got %+v, want refused as expired", store)
	}
	if len(d.listed) != 0 {
		t.Errorf("the directories %v were listed for a refusal they cannot change", d.listed)
	}
}

// A CANCELLED RUN READS NOTHING, and a forgotten port is said as our defect
// rather than read as a machine with nothing installed.
func TestACancelledRunOrAMissingPortReadsNothing(t *testing.T) {
	d := newDisk()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stores, _ := bundleProbe(d.source, d.list, linuxLayout, time.Now)(ctx, [][]byte{{1}})
	if len(stores) != 1 || !strings.Contains(stores[0].NotAssessed, "not asked") || len(d.reads) != 0 {
		t.Errorf("cancelled: got %+v after reading %v", stores, d.reads)
	}
	stores, _ = bundleProbe(nil, d.list, linuxLayout, time.Now)(context.Background(), [][]byte{{1}})
	if len(stores) != 1 || !strings.Contains(stores[0].NotAssessed, "built without") {
		t.Errorf("no source: got %+v", stores)
	}
	stores, _ = bundleProbe(d.source, nil, linuxLayout, time.Now)(context.Background(), [][]byte{{1}})
	if len(stores) != 1 || !strings.Contains(stores[0].NotAssessed, "built without") {
		t.Errorf("no listing: got %+v", stores)
	}
}

// The instance reaches the row - the reader in package probe is not decoration.
func TestTheRowCarriesTheDistribution(t *testing.T) {
	ours := anAuthority(t, "ours")
	d := newDisk()
	d.files["/etc/os-release"] = []byte("ID=alpine\n")
	d.files[debianBundle] = pemOf(ours.certificate)
	if store := runOn(t, d, linuxLayout, [][]byte{aLeaf(t, ours, leafOptions{}).Raw}); store.Instance != "alpine" {
		t.Errorf("instance %q, want alpine", store.Instance)
	}
}

// THE LAYOUT IS GO'S OWN LIST, pinned, so a change to it is a decision rather
// than a drift. Source: src/crypto/x509/root_linux.go of Go 1.27.2.
func TestTheLinuxLayoutIsGosOwnList(t *testing.T) {
	bundles := []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/cert.pem",
	}
	if !slices.Equal(linuxLayout.bundles, bundles) {
		t.Errorf("bundles %v, want Go's %v", linuxLayout.bundles, bundles)
	}
	if !slices.Equal(linuxLayout.directories.Paths, []string{certsDir, pkiDir}) {
		t.Errorf("directories %v", linuxLayout.directories.Paths)
	}
	if !slices.Equal(linuxLayout.releases, []string{"/etc/os-release", "/usr/lib/os-release"}) {
		t.Errorf("releases %v, want os-release(5)'s precedence", linuxLayout.releases)
	}
	if linuxLayout.directories.EntryCeiling != 4096 || linuxLayout.directories.ByteCeiling != 64<<20 {
		t.Errorf("ceilings %d and %d", linuxLayout.directories.EntryCeiling, linuxLayout.directories.ByteCeiling)
	}
}
