package probe

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"go/build"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// refusingAlso puts the key of one certificate on goRefuses for one test. The
// keys Go refuses belong to certificates nobody here holds a private key for,
// so a test makes its own refused key instead.
//
// THE LIST IS SHARED AND THIS CHANGES IT, which is safe only because no test in
// this package calls t.Parallel. One that does turns this into a race, and then
// the list has to become an argument of verify.
func refusingAlso(t *testing.T, der []byte) {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("the certificate to refuse will not parse: %v", err)
	}
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	key := hex.EncodeToString(sum[:])
	goRefuses[key] = true
	t.Cleanup(func() { delete(goRefuses, key) })
}

// constrainedChain is a root allowed to sign only under example.com, an
// intermediate under it and a leaf for partner.test. Every version of Go
// refuses it with neither an unknown authority nor a date - the shape the
// refusal of Go's own list takes.
func constrainedChain(t *testing.T) (rootDER, intermediateDER, leafDER []byte) {
	t.Helper()
	from, to := atNoon().Add(-time.Hour), atNoon().Add(time.Hour)
	rootDER, rootKey := mint(t, "certdoctor constrained root", 1, nil, nil, true, from, to,
		func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"example.com"} })
	intermediateDER, intermediateKey := mint(t, "certdoctor intermediate", 2, rootDER, rootKey, true, from, to)
	leafDER, _ = mint(t, "partner.test", 3, intermediateDER, intermediateKey, false, from, to)
	return rootDER, intermediateDER, leafDER
}

// TestARefusalGoMayHaveMadeIsNotPinnedOnTheStore - ADR113. Wherever the key
// sits - on the leaf, on an intermediate the server sent, or only in the store -
// a refusal Go's list could have made leaves the row without a verdict, because
// the program judged carries no such list.
func TestARefusalGoMayHaveMadeIsNotPinnedOnTheStore(t *testing.T) {
	for _, where := range []string{"leaf", "presented intermediate", "store"} {
		t.Run(where, func(t *testing.T) {
			rootDER, intermediateDER, leafDER := constrainedChain(t)
			refusingAlso(t, map[string][]byte{
				"leaf": leafDER, "presented intermediate": intermediateDER, "store": rootDER,
			}[where])

			var store report.TrustStore
			Verify(&store, bundleOf(t, rootDER), [][]byte{leafDER, intermediateDER}, atNoon())

			if store.TrustsPresentedChain != nil || store.TrustFailure != "" {
				t.Fatalf("a refusal Go's list may have made was pinned on the store: failure %q", store.TrustFailure)
			}
			if store.NotAssessed != refusedByGo || store.TrustAnchorCount != 0 {
				t.Errorf("not assessed %q with %d anchors counted, want the sentence and none",
					store.NotAssessed, store.TrustAnchorCount)
			}
		})
	}
}

// TestARefusalTheListCannotHaveMadeStands - ADR113. Go finds no path to an
// unknown authority before its list is ever applied, so a refused key beside
// that refusal changes nothing, and the row keeps the reason a person can act on.
func TestARefusalTheListCannotHaveMadeStands(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	unrelatedAnchor, _ := anchorAndLeaf(t)
	refusingAlso(t, leafDER)

	var store report.TrustStore
	Verify(&store, unrelatedAnchor, [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain || store.TrustFailure != report.UnknownAuthority {
		t.Errorf("an unknown authority beside a refused key became failure %q, not assessed %q",
			store.TrustFailure, store.NotAssessed)
	}
}

// TestTheKeysAreTheOnesThisGoRefuses holds the copy in goRefuses to the list in
// the Go library running this test - ADR113. A release that adds a key, drops
// one or moves the list turns this red, which is the point: the copy is a claim
// about Go, and inviolable rule 18 wants it checked where it is made.
func TestTheKeysAreTheOnesThisGoRefuses(t *testing.T) {
	path := filepath.Join(build.Default.GOROOT, "src", "crypto", "x509", "verify.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the Go library's verifier could not be read at %s: %v", path, err)
	}
	_, list, found := strings.Cut(string(source), "var distrustedSPKIHashes = map[string]struct{}{")
	if !found {
		t.Fatalf("%s holds no distrustedSPKIHashes any more - read it again, then goRefuses and ADR113", path)
	}
	list, _, _ = strings.Cut(list, "\n}")
	var theirs []string
	for _, match := range regexp.MustCompile(`"([0-9a-f]{64})"`).FindAllStringSubmatch(list, -1) {
		theirs = append(theirs, match[1])
	}
	slices.Sort(theirs)
	ours := slices.Sorted(maps.Keys(goRefuses))
	if len(ours) == 0 || !slices.Equal(ours, theirs) {
		t.Errorf("goRefuses holds %d keys and the Go at %s refuses %d:\nours   %v\ntheirs %v",
			len(ours), build.Default.GOROOT, len(theirs), ours, theirs)
	}
}
