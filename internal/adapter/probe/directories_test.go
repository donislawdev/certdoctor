package probe

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The rule is exercised here, where it lives, and once more through each row
// that asks it - the platform store, curl and git each pin the words they put
// around it.

const (
	certsDir = "/etc/ssl/certs"
	pkiDir   = "/etc/pki/tls/certs"
)

// testSentences mark which of the three sentences a row was given.
var testSentences = DirectorySentences{
	Closes:     "closes in %s",
	Unreadable: "unreadable %s: %v",
	TooLarge:   "too large %s",
}

// disk is the two ports over a map, recording what was listed and opened.
type disk struct {
	files   map[string][]byte
	errs    map[string]error
	dirs    map[string][]string
	dirErrs map[string]error
	listed  []string
	reads   []string
}

func newDisk() *disk {
	return &disk{files: map[string][]byte{}, errs: map[string]error{}, dirs: map[string][]string{}, dirErrs: map[string]error{}}
}

func (d *disk) source(path string) (io.ReadCloser, error) {
	d.reads = append(d.reads, path)
	if err := d.errs[path]; err != nil {
		return nil, err
	}
	data, ok := d.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (d *disk) list(path string) ([]string, error) {
	d.listed = append(d.listed, path)
	if err := d.dirErrs[path]; err != nil {
		return nil, err
	}
	names, ok := d.dirs[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return names, nil
}

// refusedBy judges the chain with a bundle that lacks its signer, which is the
// one refusal the directories are asked about.
func refusedBy(t *testing.T, bundle, leaf []byte) report.TrustStore {
	t.Helper()
	var store report.TrustStore
	Verify(&store, bundle, [][]byte{leaf}, atNoon())
	if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain || store.TrustFailure != report.UnknownAuthority {
		t.Fatalf("the fixture is not a refusal for want of a signer: %+v", store)
	}
	return store
}

func weigh(store *report.TrustStore, d *disk, dirs CADirectories, bundle, leaf []byte) {
	WeighDirectories(store, d.source, d.list, dirs, bundle, [][]byte{leaf}, atNoon(), testSentences)
}

// A CERTIFICATE ONLY A DIRECTORY HOLDS turns the refusal into a row without a
// verdict, naming the directory - in either of Go's two, and with the count
// gone, because the contract refuses a row that counts a store it did not judge.
func TestACertificateOnlyADirectoryHoldsLeavesTheRowWithoutAVerdict(t *testing.T) {
	ours, leaf := anchorAndLeaf(t)
	other, _ := anchorAndLeaf(t)
	for _, directory := range LinuxCADirectories.Paths {
		t.Run(directory, func(t *testing.T) {
			d := newDisk()
			d.dirs[directory] = []string{directory + "/ours.pem"}
			d.files[directory+"/ours.pem"] = ours
			store := refusedBy(t, other, leaf)
			weigh(&store, d, LinuxCADirectories, other, leaf)
			if store.TrustsPresentedChain != nil || store.TrustFailure != "" || store.TrustAnchorCount != 0 {
				t.Errorf("the refusal survived in part: %+v", store)
			}
			if want := fmt.Sprintf(testSentences.Closes, directory); store.NotAssessed != want {
				t.Errorf("said %q, want %q", store.NotAssessed, want)
			}
		})
	}
}

// A REFUSAL STANDS when the directories hold nothing that closes the chain -
// both are listed in Go's order, a dangling link is passed over as the ordinary
// leftover it is, and a directory that is not there is not a failure.
func TestARefusalStandsWhenTheDirectoriesCloseNothing(t *testing.T) {
	_, leaf := anchorAndLeaf(t)
	other, _ := anchorAndLeaf(t)
	d := newDisk()
	d.dirs[certsDir] = []string{certsDir + "/other.pem", certsDir + "/dangling.pem"}
	d.files[certsDir+"/other.pem"] = other
	store := refusedBy(t, other, leaf)
	weigh(&store, d, LinuxCADirectories, other, leaf)
	if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain || store.NotAssessed != "" {
		t.Errorf("got %+v, want the refusal to stand", store)
	}
	if !slices.Equal(d.listed, LinuxCADirectories.Paths) {
		t.Errorf("listed %v, want both of Go's directories in order", d.listed)
	}
}

// ONLY A REFUSAL FOR WANT OF A SIGNER IS WEIGHED. A directory adds signers and
// never takes one away, so a chain the bundle trusts is already the answer, and
// an expired chain is refused whatever the directories hold.
func TestOnlyARefusalForWantOfASignerIsWeighed(t *testing.T) {
	ours, leaf := anchorAndLeaf(t)
	stale, staleLeaf := chainValid(t, atNoon().Add(-48*time.Hour), atNoon().Add(-24*time.Hour))
	d := newDisk()
	d.dirs[certsDir] = []string{certsDir + "/ours.pem", certsDir + "/stale.pem"}
	d.files[certsDir+"/ours.pem"] = ours
	d.files[certsDir+"/stale.pem"] = stale

	var trusted report.TrustStore
	Verify(&trusted, ours, [][]byte{leaf}, atNoon())
	weigh(&trusted, d, LinuxCADirectories, ours, leaf)
	if trusted.TrustsPresentedChain == nil || !*trusted.TrustsPresentedChain {
		t.Errorf("a trusted chain was turned into %+v", trusted)
	}

	var expired report.TrustStore
	Verify(&expired, stale, [][]byte{staleLeaf}, atNoon())
	weigh(&expired, d, LinuxCADirectories, stale, staleLeaf)
	if expired.TrustFailure == report.UnknownAuthority || expired.NotAssessed != "" {
		t.Errorf("an expired chain was weighed: %+v", expired)
	}

	var unjudged report.TrustStore
	weigh(&unjudged, d, LinuxCADirectories, nil, leaf)
	if unjudged.NotAssessed != "" {
		t.Errorf("a row with no verdict was weighed: %+v", unjudged)
	}
	if len(d.listed) != 0 {
		t.Errorf("listed %v for rows that are not refusals for want of a signer", d.listed)
	}
}

// A DIRECTORY THAT CANNOT BE READ leaves the refusal unproven - as a whole or
// one entry of it. A refusal resting on files nobody looked at is not one.
func TestADirectoryThatCannotBeReadLeavesTheRefusalUnproven(t *testing.T) {
	_, leaf := anchorAndLeaf(t)
	other, _ := anchorAndLeaf(t)
	denied := &fs.PathError{Op: "open", Path: certsDir, Err: fs.ErrPermission}
	cases := map[string]func(d *disk){
		"the directory": func(d *disk) { d.dirErrs[certsDir] = denied },
		"one entry of it": func(d *disk) {
			d.dirs[certsDir] = []string{certsDir + "/x.pem"}
			d.errs[certsDir+"/x.pem"] = denied
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			d := newDisk()
			spoil(d)
			store := refusedBy(t, other, leaf)
			weigh(&store, d, LinuxCADirectories, other, leaf)
			if store.TrustsPresentedChain != nil || !strings.HasPrefix(store.NotAssessed, "unreadable "+certsDir) ||
				!strings.Contains(store.NotAssessed, "permission") {
				t.Errorf("got %+v, want undetermined naming the directory and the error", store)
			}
		})
	}
}

// PAST EITHER CEILING THE ROW SAYS IT DID NOT LOOK, and it does not look - a
// directory over the entry ceiling has none of its entries opened. Exactly at
// both ceilings is read.
func TestADirectoryPastItsCeilingIsNotRead(t *testing.T) {
	_, leaf := anchorAndLeaf(t)
	other, _ := anchorAndLeaf(t)
	small := CADirectories{Paths: []string{certsDir}, EntryCeiling: 2, ByteCeiling: 4096}

	d := newDisk()
	d.dirs[certsDir] = []string{certsDir + "/a", certsDir + "/b", certsDir + "/c"}
	store := refusedBy(t, other, leaf)
	weigh(&store, d, small, other, leaf)
	if store.NotAssessed != fmt.Sprintf(testSentences.TooLarge, certsDir) {
		t.Errorf("over the entry ceiling: got %+v", store)
	}
	if slices.Contains(d.reads, certsDir+"/a") {
		t.Error("an entry of a directory over the ceiling was opened")
	}

	d = newDisk()
	d.dirs[certsDir] = []string{certsDir + "/big"}
	d.files[certsDir+"/big"] = bytes.Repeat([]byte("x"), 4096)
	store = refusedBy(t, other, leaf)
	weigh(&store, d, small, other, leaf)
	if store.NotAssessed != fmt.Sprintf(testSentences.TooLarge, certsDir) {
		t.Errorf("over the byte ceiling: got %+v", store)
	}

	// The twin: exactly at both ceilings is read, and the refusal stands.
	d = newDisk()
	d.dirs[certsDir] = []string{certsDir + "/a", certsDir + "/b"}
	d.files[certsDir+"/a"] = []byte("x")
	d.files[certsDir+"/b"] = bytes.Repeat([]byte("x"), 4096-len(other)-3)
	store = refusedBy(t, other, leaf)
	weigh(&store, d, small, other, leaf)
	if store.NotAssessed != "" || store.TrustsPresentedChain == nil {
		t.Errorf("exactly at both ceilings: got %+v, want the refusal to stand", store)
	}
}

// ONLY LINUX GETS DIRECTORIES, because only Linux was measured - S26.
func TestDirectoriesAreReadOnLinuxAlone(t *testing.T) {
	if got := CADirectoriesOn("linux"); !slices.Equal(got.Paths, []string{certsDir, pkiDir}) ||
		got.EntryCeiling != 4096 || got.ByteCeiling != 64<<20 {
		t.Errorf("linux got %+v, want Go's two directories and the measured ceilings", got)
	}
	for _, platform := range []string{"windows", "darwin", ""} {
		if got := CADirectoriesOn(platform); len(got.Paths) != 0 {
			t.Errorf("%q got %v", platform, got.Paths)
		}
	}
}

// The words a libcurl row gets name what named the file and the tool, and every
// one of them is a format that takes exactly what WeighDirectories hands it.
func TestTheLibcurlSentencesNameWhatNamedTheFile(t *testing.T) {
	say := LibcurlDirectorySentences("GIT_SSL_CAINFO", "git")
	for _, sentence := range []string{
		fmt.Sprintf(say.Closes, certsDir),
		fmt.Sprintf(say.Unreadable, certsDir, fs.ErrPermission),
		fmt.Sprintf(say.TooLarge, certsDir),
	} {
		if !strings.Contains(sentence, "GIT_SSL_CAINFO") || !strings.Contains(sentence, certsDir) || strings.Contains(sentence, "%!") {
			t.Errorf("sentence %q", sentence)
		}
	}
	if !strings.Contains(fmt.Sprintf(say.Closes, certsDir), "a git built to read that directory") {
		t.Errorf("the closing sentence does not name the tool: %q", say.Closes)
	}
}
