package probe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// anchorAndLeaf mints a tiny chain so verification is exercised without a
// network and without a fixture nobody can regenerate.
func anchorAndLeaf(t *testing.T) (anchorPEM, leafDER []byte) {
	t.Helper()
	return chainValid(t, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
}

// chainValid mints the same chain inside a window the caller chooses, so that
// "out of date" and "not yet in date" can be produced on purpose rather than
// waited for. It is the SAME minting code as the default above rather than a
// copy of it - the shape OBS50 records, applied to a fixture.
func chainValid(t *testing.T, notBefore, notAfter time.Time) (anchorPEM, leafDER []byte) {
	t.Helper()
	anchorDER, anchorKey := mint(t, "certdoctor test anchor", 1, nil, nil, true, notBefore, notAfter)
	leafDER, _ = mint(t, "partner.test", 2, anchorDER, anchorKey, false, notBefore, notAfter)
	return bundleOf(t, anchorDER), leafDER
}

// mint makes one certificate, signed by a parent or by itself when there is
// none.
//
// ONE MINTING FUNCTION RATHER THAN ONE PER FIXTURE. Three shapes are needed here
// - a self-signed anchor, an intermediate under it, and a leaf under that - and
// three copies of this code would be three places where a validity window or a
// key usage could drift apart, which is the shape OBS50 records.
//
// tweak is how a test asks for a shape the three defaults do not cover - a name
// constraint, say. It is variadic so that every existing call keeps reading as
// the ordinary case.
func mint(t *testing.T, commonName string, serial int64, parentDER []byte, parentKey *ecdsa.PrivateKey,
	isCA bool, notBefore, notAfter time.Time, tweak ...func(*x509.Certificate)) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no key for %s: %v", commonName, err)
	}
	return mintFor(t, key, commonName, serial, parentDER, parentKey, isCA, notBefore, notAfter, tweak...), key
}

// mintFor is mint for a key the caller already holds - two certificates for one
// key and one name are how an authority signed by two others looks.
func mintFor(t *testing.T, key *ecdsa.PrivateKey, commonName string, serial int64, parentDER []byte,
	parentKey *ecdsa.PrivateKey, isCA bool, notBefore, notAfter time.Time, tweak ...func(*x509.Certificate)) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign
	} else {
		template.DNSNames = []string{commonName}
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	for _, apply := range tweak {
		apply(template)
	}

	parent, signer := template, key
	if parentDER != nil {
		issuer, err := x509.ParseCertificate(parentDER)
		if err != nil {
			t.Fatalf("issuer for %s will not parse: %v", commonName, err)
		}
		parent, signer = issuer, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("no certificate for %s: %v", commonName, err)
	}
	return der
}

// bundleOf writes certificates out the way a trust store on disk holds them.
func bundleOf(t *testing.T, ders ...[]byte) []byte {
	t.Helper()
	var bundle bytes.Buffer
	for _, der := range ders {
		if err := pem.Encode(&bundle, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatalf("no bundle: %v", err)
		}
	}
	return bundle.Bytes()
}

func TestAStoreHoldingTheIssuingAnchorTrustsTheChain(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	var store report.TrustStore
	Verify(&store, anchorPEM, [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain == nil {
		t.Fatalf("no verdict: %s", store.NotAssessed)
	}
	if !*store.TrustsPresentedChain {
		t.Error("a store holding the issuing anchor did not trust the chain")
	}
	if store.TrustAnchorCount != 1 {
		t.Errorf("counted %d anchors, want 1", store.TrustAnchorCount)
	}
}

// DISTRUST IS A VERDICT, NOT A FAILURE. It is the answer the whole matrix exists
// to produce, and it must never be confused with "could not be read".
func TestAStoreWithoutTheAnchorDistrustsRatherThanFails(t *testing.T) {
	_, leafDER := anchorAndLeaf(t)
	otherAnchor, _ := anchorAndLeaf(t)

	var store report.TrustStore
	Verify(&store, otherAnchor, [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain == nil {
		t.Fatalf("distrust came back as unassessed: %s", store.NotAssessed)
	}
	if *store.TrustsPresentedChain {
		t.Error("a store holding an unrelated anchor trusted the chain")
	}
	if store.NotAssessed != "" {
		t.Errorf("a verdict was reached and a reason was given too: %q", store.NotAssessed)
	}
}

// A STORE WITH NOTHING READABLE IN IT IS UNKNOWN, NEVER DISTRUST. "There are no
// anchors here" is a fact about the store, not about the chain.
func TestAStoreWithNoReadableAnchorIsUnassessed(t *testing.T) {
	var store report.TrustStore
	Verify(&store, []byte("not a certificate at all"), [][]byte{{0x30}}, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Error("an unreadable store produced a verdict about trust")
	}
	if !strings.Contains(store.NotAssessed, "no certificate") {
		t.Errorf("the reason does not say what was missing: %q", store.NotAssessed)
	}
}

// ONE BROKEN ENTRY IN SOMEBODY'S STORE IS NOT A REASON TO DISCARD THE REST.
func TestAStoreSurvivesOneUnparsableEntry(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	var junk bytes.Buffer
	_ = pem.Encode(&junk, &pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	_ = pem.Encode(&junk, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte{4, 5, 6}})

	var store report.TrustStore
	Verify(&store, append(junk.Bytes(), anchorPEM...), [][]byte{leafDER}, atNoon())

	if store.TrustAnchorCount != 1 {
		t.Errorf("counted %d anchors beside the junk, want 1", store.TrustAnchorCount)
	}
	if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
		t.Errorf("the good anchor was lost with the bad one: %+v", store)
	}
}

// NO CHAIN MEANS NOTHING TO JUDGE, and the anchor count goes back to zero
// because counting anchors in a store nobody asked about reads as a measurement.
func TestNoChainMeansNothingToJudge(t *testing.T) {
	anchorPEM, _ := anchorAndLeaf(t)
	var store report.TrustStore
	Verify(&store, anchorPEM, nil, atNoon())

	if store.TrustsPresentedChain != nil {
		t.Error("a verdict was produced with no chain to judge")
	}
	if store.TrustAnchorCount != 0 {
		t.Errorf("anchors were counted for a question nobody asked: %d", store.TrustAnchorCount)
	}
}

func TestAnUnparsableLeafIsUnassessed(t *testing.T) {
	anchorPEM, _ := anchorAndLeaf(t)
	var store report.TrustStore
	Verify(&store, anchorPEM, [][]byte{{0x00, 0x01}}, atNoon())

	if store.TrustsPresentedChain != nil || store.NotAssessed == "" {
		t.Errorf("an unparsable leaf did not come back unassessed: %+v", store)
	}
}

// atNoon is the clock these tests hand to the verifier - a fixed instant, so
// that "is this certificate out of date" cannot answer differently tomorrow.
func atNoon() time.Time { return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) }

// TestARefusalSaysWhichWay is what stops this program offering a certificate to
// import for a problem importing does not touch.
//
// THE THREE CLASSES ARE NOT COSMETIC. Only an unknown authority is repaired by
// adding a certificate to a store. An expired chain needs whoever runs the
// server; a chain that has not started yet is usually THIS machine's clock, and
// it is one of the commonest causes of the failure this product exists to
// diagnose. A single "does not trust" would send all three to the same wrong
// place.
func TestARefusalSaysWhichWay(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)

	cases := []struct {
		name    string
		anchors []byte
		chain   [][]byte
		wants   report.TrustFailure
	}{
		{
			name: "the store holds nobody who signed this",
			// A different chain entirely: the anchor is real and signed nothing
			// that arrived.
			anchors: func() []byte { other, _ := anchorAndLeaf(t); return other }(),
			chain:   [][]byte{leafDER},
			wants:   report.UnknownAuthority,
		},
		{
			name:    "the chain is past its end",
			anchors: anchorPEM,
			chain:   [][]byte{leafDER},
			wants:   report.Expired,
		},
		{
			name:    "the chain has not started yet",
			anchors: anchorPEM,
			chain:   [][]byte{leafDER},
			wants:   report.NotYetValid,
		},
	}

	// The two dated cases move the CLOCK rather than the certificate, which is
	// the honest way round: the certificate is the same one in every case and
	// only the moment of asking differs.
	clocks := map[string]time.Time{
		"the store holds nobody who signed this": atNoon(),
		"the chain is past its end":              atNoon().Add(48 * time.Hour),
		"the chain has not started yet":          atNoon().Add(-48 * time.Hour),
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var store report.TrustStore
			Verify(&store, c.anchors, c.chain, clocks[c.name])

			if store.TrustsPresentedChain == nil {
				t.Fatalf("no verdict at all: %s", store.NotAssessed)
			}
			if *store.TrustsPresentedChain {
				t.Fatal("the chain was trusted, and this case is a refusal")
			}
			if store.TrustFailure != c.wants {
				t.Errorf("refused with %q, want %q", store.TrustFailure, c.wants)
			}
		})
	}
}

// The positive twin - OBS56. Every case above asserts a particular refusal, and
// a verifier that refused everything with the right word would pass all three.
func TestAnAcceptedChainNamesNoFailure(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	var store report.TrustStore
	Verify(&store, anchorPEM, [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
		t.Fatalf("the chain was not trusted: %s", store.NotAssessed)
	}
	if store.TrustFailure != "" {
		t.Errorf("a trusted chain carries the failure %q", store.TrustFailure)
	}
}

// TestAnIntermediateFromTheChainCompletesThePath is the shape the bench serves
// on port 8443, and the shape a remediation command is written for.
//
// THE INTERMEDIATE COMES FROM THE WIRE AND THE ROOT FROM THE STORE, which is how
// nearly every real chain is built - and until 2026-08-19 no test here passed
// more than one certificate, so the loop that reads the rest of the chain had
// never been executed. The coverage gate is what said so.
func TestAnIntermediateFromTheChainCompletesThePath(t *testing.T) {
	rootDER, rootKey := mint(t, "certdoctor test root", 1, nil, nil, true, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	interDER, interKey := mint(t, "certdoctor test intermediate", 2, rootDER, rootKey, true, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	leafDER, _ := mint(t, "partner.test", 3, interDER, interKey, false, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))

	var store report.TrustStore
	// The store holds the ROOT ONLY. The intermediate has to be taken from what
	// the server sent, which is the whole point.
	Verify(&store, bundleOf(t, rootDER), [][]byte{leafDER, interDER}, atNoon())

	if store.TrustsPresentedChain == nil {
		t.Fatalf("no verdict: %s", store.NotAssessed)
	}
	if !*store.TrustsPresentedChain {
		t.Errorf("a chain carrying its own intermediate was refused, failure %q", store.TrustFailure)
	}

	// THE NEGATIVE TWIN, ON THE SAME CERTIFICATES - OBS56. Without it this test
	// would pass on a verifier that trusted everything. Withhold the
	// intermediate and the same store must refuse, which is scenario S-5.
	var withheld report.TrustStore
	Verify(&withheld, bundleOf(t, rootDER), [][]byte{leafDER}, atNoon())
	if withheld.TrustsPresentedChain == nil || *withheld.TrustsPresentedChain {
		t.Error("the same store accepted the leaf with its intermediate withheld, so the intermediate was not what completed the path")
	}
}

// TestAFailureThisProgramDoesNotClassifyGetsNoGuess.
//
// x509 refuses a path for reasons beyond the three named here - a signer that is
// not a certificate authority is one - and the honest answer is "other". It
// produces NO command, which is the point: choosing the commonest reason instead
// would hand somebody a certificate to import for a problem importing does not
// touch, and they would wait for it to work.
func TestAFailureThisProgramDoesNotClassifyGetsNoGuess(t *testing.T) {
	// A root that is only permitted to sign names under example.com, signing a
	// leaf for partner.test. The signature is sound, the dates are fine and the
	// authority IS in the store - what fails is the constraint, which is neither
	// of the three reasons this program names.
	rootDER, rootKey := mint(t, "certdoctor constrained root", 1, nil, nil, true,
		atNoon().Add(-time.Hour), atNoon().Add(time.Hour),
		func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"example.com"} })
	leafDER, _ := mint(t, "partner.test", 2, rootDER, rootKey, false, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))

	var store report.TrustStore
	Verify(&store, bundleOf(t, rootDER), [][]byte{leafDER}, atNoon())

	if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain {
		t.Fatalf("a leaf outside its issuer's permitted names was trusted: %s", store.NotAssessed)
	}
	if store.TrustFailure != report.OtherFailure {
		t.Errorf("classified as %q, and guessing a familiar reason here is how somebody runs a command that cannot help",
			store.TrustFailure)
	}
}

// TestAnIntermediateInTheStoreEndsNoChainForNode is the case probe S27 measured
// in all eight environments on 2026-10-20 - ADR111 part 3. The server sends its
// leaf alone, the store holds the intermediate that signed it beside an
// unrelated root, and Node refuses. Verify, with every entry a root, says the
// opposite, which is the false PASS this rule exists to prevent.
func TestAnIntermediateInTheStoreEndsNoChainForNode(t *testing.T) {
	rootDER, rootKey := mint(t, "certdoctor test root", 1, nil, nil, true, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	interDER, interKey := mint(t, "certdoctor test intermediate", 2, rootDER, rootKey, true, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	leafDER, _ := mint(t, "partner.test", 3, interDER, interKey, false, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	otherDER, _ := mint(t, "certdoctor unrelated root", 4, nil, nil, true, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	held := bundleOf(t, otherDER, interDER)

	var node report.TrustStore
	VerifySelfSignedAnchors(&node, held, [][]byte{leafDER}, atNoon())
	if node.TrustsPresentedChain == nil || *node.TrustsPresentedChain {
		t.Fatalf("an intermediate alone ended the chain: %s", node.NotAssessed)
	}
	if node.TrustFailure != report.UnknownAuthority {
		t.Errorf("classified as %q, want %q", node.TrustFailure, report.UnknownAuthority)
	}
	if node.TrustAnchorCount != 1 {
		t.Errorf("counted %d anchors, and only the unrelated root can end a chain", node.TrustAnchorCount)
	}

	// THE TWIN ON THE SAME BYTES: the rule every other runtime keeps.
	var other report.TrustStore
	Verify(&other, held, [][]byte{leafDER}, atNoon())
	if other.TrustsPresentedChain == nil || !*other.TrustsPresentedChain {
		t.Error("Verify refused a chain its store holds the issuer of, so the two rules no longer differ where S27 says they do")
	}
}

// TestAnIntermediateInTheStoreStillBuildsThePath is the other half of the same
// measurement: with the root beside it, the intermediate the server did not send
// is taken from the store and Node trusts the leaf.
func TestAnIntermediateInTheStoreStillBuildsThePath(t *testing.T) {
	rootDER, rootKey := mint(t, "certdoctor test root", 1, nil, nil, true, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	interDER, interKey := mint(t, "certdoctor test intermediate", 2, rootDER, rootKey, true, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	leafDER, _ := mint(t, "partner.test", 3, interDER, interKey, false, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))

	var store report.TrustStore
	VerifySelfSignedAnchors(&store, bundleOf(t, interDER, rootDER), [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
		t.Fatalf("a store holding the root and the intermediate refused the leaf: %s %s", store.NotAssessed, store.TrustFailure)
	}
	if store.TrustAnchorCount != 1 {
		t.Errorf("counted %d anchors, want the root alone", store.TrustAnchorCount)
	}
}

// TestAStoreWithNothingSelfSignedIsNotJudged keeps the third state for a store
// in which nothing can end a chain - and says why in this rule's own words.
func TestAStoreWithNothingSelfSignedIsNotJudged(t *testing.T) {
	rootDER, rootKey := mint(t, "certdoctor test root", 1, nil, nil, true, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	interDER, interKey := mint(t, "certdoctor test intermediate", 2, rootDER, rootKey, true, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))
	leafDER, _ := mint(t, "partner.test", 3, interDER, interKey, false, atNoon().Add(-time.Hour), atNoon().Add(time.Hour))

	var store report.TrustStore
	VerifySelfSignedAnchors(&store, bundleOf(t, interDER), [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "self-signed") {
		t.Errorf("a store with no self-signed certificate was judged or said the wrong thing: %v %q",
			store.TrustsPresentedChain, store.NotAssessed)
	}
}

// TestSelfSignedAsksBothHalves: the name and the signature are two questions,
// and a certificate failing either one does not end a chain.
func TestSelfSignedAsksBothHalves(t *testing.T) {
	at := atNoon()
	rootDER, rootKey := mint(t, "certdoctor test root", 1, nil, nil, true, at.Add(-time.Hour), at.Add(time.Hour))
	interDER, _ := mint(t, "certdoctor test intermediate", 2, rootDER, rootKey, true, at.Add(-time.Hour), at.Add(time.Hour))
	// The root's own name over another key, signed by the root: the name says
	// self-signed and the signature does not.
	sameNameDER, _ := mint(t, "certdoctor test root", 3, rootDER, rootKey, true, at.Add(-time.Hour), at.Add(time.Hour))
	// Its own key, and an issuer name that is not its own.
	otherNameDER := signedByItselfUnderAnotherName(t)
	// A self-signed leaf - CheckSignatureFrom would refuse it for not being an
	// authority, and the rule S27 counted with does not ask.
	leafDER, _ := mint(t, "self.test", 5, nil, nil, false, at.Add(-time.Hour), at.Add(time.Hour))

	cases := []struct {
		name string
		der  []byte
		want bool
	}{
		{"a root", rootDER, true},
		{"an intermediate", interDER, false},
		{"its own name over another key", sameNameDER, false},
		{"its own key under another name", otherNameDER, false},
		{"a self-signed leaf", leafDER, true},
	}
	for _, c := range cases {
		certificate, err := x509.ParseCertificate(c.der)
		if err != nil {
			t.Fatalf("%s will not parse: %v", c.name, err)
		}
		if got := selfSigned(certificate); got != c.want {
			t.Errorf("%s: selfSigned says %v, want %v", c.name, got, c.want)
		}
	}
}

// signedByItselfUnderAnotherName mints a certificate signed with its own key
// whose issuer names somebody else.
func signedByItselfUnderAnotherName(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("no key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "certdoctor itself"},
		NotBefore: atNoon().Add(-time.Hour), NotAfter: atNoon().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	parent := &x509.Certificate{Subject: pkix.Name{CommonName: "certdoctor somebody else"}}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("no certificate: %v", err)
	}
	return der
}
