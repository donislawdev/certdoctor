package probe

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// negativeSerial is a copy of a certificate with its serial number made -1 and
// signed again by key - the shape of EC-ACC in /private/etc/ssl/cert.pem of
// macOS 27.2, which the Go library refuses and OpenSSL reads (ADR128).
//
// crypto/x509 will not write such a certificate, so the DER is rebuilt by hand:
// the serial number is the second element of the TBSCertificate, after the
// version - RFC 5280 section 4.1.
func negativeSerial(t *testing.T, der []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	var certificate struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &certificate); err != nil || len(rest) != 0 {
		t.Fatalf("the certificate to rebuild is not one: %v", err)
	}
	fields, err := elements(certificate.TBS.FullBytes)
	if err != nil || len(fields) < 2 || fields[1].Tag != asn1.TagInteger {
		t.Fatalf("the TBSCertificate holds no serial number where RFC 5280 puts it: %v", err)
	}
	fields[1] = asn1.RawValue{FullBytes: []byte{asn1.TagInteger, 0x01, 0xff}}
	var body []byte
	for _, field := range fields {
		body = append(body, field.FullBytes...)
	}
	tbs, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatalf("the TBSCertificate will not encode: %v", err)
	}
	digest := sha256.Sum256(tbs)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("no signature: %v", err)
	}
	certificate.TBS = asn1.RawValue{FullBytes: tbs}
	certificate.Signature = asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}
	rebuilt, err := asn1.Marshal(certificate)
	if err != nil {
		t.Fatalf("the certificate will not encode: %v", err)
	}
	return rebuilt
}

// rootGoCannotRead is a root with a negative serial number, a leaf it signed,
// and a readable root that signed nothing here.
func rootGoCannotRead(t *testing.T) (unreadable, leaf, unrelated []byte) {
	t.Helper()
	from, to := atNoon().Add(-time.Hour), atNoon().Add(time.Hour)
	rootDER, rootKey := mint(t, "certdoctor negative serial root", 1, nil, nil, true, from, to)
	leaf, _ = mint(t, "partner.test", 2, rootDER, rootKey, false, from, to)
	unrelated, _ = mint(t, "certdoctor unrelated root", 3, nil, nil, true, from, to)
	return negativeSerial(t, rootDER, rootKey), leaf, unrelated
}

// junk is a CERTIFICATE block nothing can read.
var junk = []byte{1, 2, 3}

// TestTheFixtureIsRefusedForItsSerialAlone holds the fixture to the shape it
// stands for: Go refuses it, and with x509negativeserial it reads it and the
// leaf's signature checks against it - so every test below is about a serial
// number and nothing else that went wrong in the rebuilding.
func TestTheFixtureIsRefusedForItsSerialAlone(t *testing.T) {
	unreadable, leafDER, _ := rootGoCannotRead(t)
	if _, err := x509.ParseCertificate(unreadable); err == nil {
		t.Fatal("the Go library read a certificate with a negative serial number")
	}
	t.Setenv("GODEBUG", "x509negativeserial=1")
	root, err := x509.ParseCertificate(unreadable)
	if err != nil {
		t.Fatalf("with x509negativeserial the rebuilt root still will not parse: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("the leaf will not parse: %v", err)
	}
	if err := leaf.CheckSignatureFrom(root); err != nil || root.SerialNumber.Sign() >= 0 {
		t.Errorf("the rebuilt root is not the leaf's signer with a negative serial: %v, serial %v", err, root.SerialNumber)
	}
}

// TestARefusalBesideACertificateGoCannotReadIsNotPinnedOnTheStore - ADR128. The
// one path runs through a root the Go library cannot read, so the refusal may
// be Go's alone, and the row says how many it could not read and why the first
// of them failed, under either anchor rule.
func TestARefusalBesideACertificateGoCannotReadIsNotPinnedOnTheStore(t *testing.T) {
	unreadable, leaf, unrelated := rootGoCannotRead(t)
	_, why := x509.ParseCertificate(unreadable)
	for name, judge := range map[string]func(*report.TrustStore, []byte, [][]byte, time.Time){
		"every entry an anchor": Verify, "self-signed anchors": VerifySelfSignedAnchors,
	} {
		t.Run(name, func(t *testing.T) {
			var store report.TrustStore
			judge(&store, bundleOf(t, unrelated, unreadable, junk), [][]byte{leaf}, atNoon())
			if store.TrustsPresentedChain != nil || store.TrustFailure != "" {
				t.Fatalf("a refusal beside a certificate Go cannot read was pinned on the store: failure %q",
					store.TrustFailure)
			}
			if !strings.Contains(store.NotAssessed, "holds 2 certificate(s) the Go library could not read") ||
				!strings.Contains(store.NotAssessed, "(the first: "+why.Error()+")") {
				t.Errorf("the row does not say how many and why the first failed: %q", store.NotAssessed)
			}
			if store.TrustAnchorCount != 0 || store.UnreadableCount != 0 {
				t.Errorf("a row without a verdict counts %d anchors and %d unread", store.TrustAnchorCount,
					store.UnreadableCount)
			}
		})
	}
}

// TestATrustBesideACertificateGoCannotReadStandsAndCountsIt - ADR128 part 2.
// The path Go built is a path whatever else the store holds, so the verdict
// stays, and the row counts what it could not read beside the anchors.
func TestATrustBesideACertificateGoCannotReadStandsAndCountsIt(t *testing.T) {
	unreadable, _, _ := rootGoCannotRead(t)
	anchorPEM, leafDER := anchorAndLeaf(t)
	var store report.TrustStore
	Verify(&store, append(bundleOf(t, unreadable, junk), anchorPEM...), [][]byte{leafDER}, atNoon())
	if store.TrustsPresentedChain == nil || !*store.TrustsPresentedChain {
		t.Fatalf("a trust beside a certificate Go cannot read was taken away: %q", store.NotAssessed)
	}
	if store.TrustAnchorCount != 1 || store.UnreadableCount != 2 {
		t.Errorf("counted %d anchors and %d unread, want 1 and 2", store.TrustAnchorCount, store.UnreadableCount)
	}
}

// TestARefusalWithNothingUnreadStands is the twin: a store Go read whole keeps
// its refusal and counts nothing unread.
func TestARefusalWithNothingUnreadStands(t *testing.T) {
	_, leaf, unrelated := rootGoCannotRead(t)
	var store report.TrustStore
	Verify(&store, bundleOf(t, unrelated), [][]byte{leaf}, atNoon())
	if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain || store.TrustFailure != report.UnknownAuthority ||
		store.UnreadableCount != 0 {
		t.Errorf("a store read whole is %q, failure %q, %d unread", store.NotAssessed, store.TrustFailure,
			store.UnreadableCount)
	}
}

// TestAStrictRefusalBesideACertificateGoCannotReadIsNotPinnedOnTheStore - with
// its own certificates first OpenSSL may take the one this program could not
// read, and build a chain that keeps to the rules. A chain that keeps to them
// stays trusted.
func TestAStrictRefusalBesideACertificateGoCannotReadIsNotPinnedOnTheStore(t *testing.T) {
	roots, chain := strictChain(t, with(extension(oidAuthorityKeyID, false, 0x30, 0x00)))
	row := strictly(t, [][]byte{roots[0], junk}, chain, python313)
	if got := verdictOf(row); !strings.HasPrefix(got, "undetermined: this store holds 1 certificate(s) the Go library") ||
		row.UnreadableCount != 0 {
		t.Errorf("a strict refusal beside a certificate Go cannot read: %s, %d unread", got, row.UnreadableCount)
	}

	roots, chain = strictChain(t, keep)
	row = strictly(t, [][]byte{roots[0], junk}, chain, python313)
	if got := verdictOf(row); got != "trusted" || row.UnreadableCount != 1 {
		t.Errorf("a chain keeping to every rule beside a certificate Go cannot read: %s, %d unread", got,
			row.UnreadableCount)
	}
}

// TestARowWithoutAVerdictCountsNothingItCouldNotRead - Undetermined takes the
// count with the verdict it described, or the contract refuses the row.
func TestARowWithoutAVerdictCountsNothingItCouldNotRead(t *testing.T) {
	anchorPEM, leafDER := anchorAndLeaf(t)
	var store report.TrustStore
	Verify(&store, append(bundleOf(t, junk), anchorPEM...), [][]byte{leafDER}, atNoon())
	Undetermined(&store, "a later rule could not stand behind the trust")
	if store.UnreadableCount != 0 {
		t.Errorf("a row without a verdict still counts %d certificates it could not read", store.UnreadableCount)
	}
}
