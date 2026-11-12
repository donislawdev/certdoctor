package probe

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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

	// A CERTIFICATE NO PATH CAN REACH leaves the strict refusal standing, and
	// counts nothing beside it - ADR136.
	roots, chain = strictChain(t, with(extension(oidAuthorityKeyID, false, 0x30, 0x00)))
	row = strictly(t, [][]byte{roots[0], unreadableNamed(t, "Root Agency")}, chain, python313)
	if got := verdictOf(row); strings.HasPrefix(got, "undetermined") || row.UnreadableCount != 0 {
		t.Errorf("a strict refusal beside a certificate off the path: %s, %d unread", got, row.UnreadableCount)
	}

	roots, chain = strictChain(t, keep)
	row = strictly(t, [][]byte{roots[0], junk}, chain, python313)
	if got := verdictOf(row); got != "trusted" || row.UnreadableCount != 1 {
		t.Errorf("a chain keeping to every rule beside a certificate Go cannot read: %s, %d unread", got,
			row.UnreadableCount)
	}
}

// unreadableNamed is a root named commonName that the Go library cannot read,
// signing nothing here - the shape of CN=Root Agency in the Windows store, which
// Node carries with NODE_USE_SYSTEM_CA=1 (ADR136).
func unreadableNamed(t *testing.T, commonName string) []byte {
	t.Helper()
	from, to := atNoon().Add(-time.Hour), atNoon().Add(time.Hour)
	der, key := mint(t, commonName, 7, nil, nil, true, from, to)
	return negativeSerial(t, der, key)
}

// TestARefusalBesideACertificateOffThePathStands - ADR136, closing OBS223. A
// certificate the Go library cannot read, whose subject is no issuer name on
// any path from the chain, cannot be where a runtime ends it, so the refusal
// stands with its reason and the count of what was not read.
func TestARefusalBesideACertificateOffThePathStands(t *testing.T) {
	_, leaf, unrelated := rootGoCannotRead(t)
	for name, judge := range map[string]func(*report.TrustStore, []byte, [][]byte, time.Time){
		"every entry an anchor": Verify, "self-signed anchors": VerifySelfSignedAnchors,
	} {
		t.Run(name, func(t *testing.T) {
			var store report.TrustStore
			judge(&store, bundleOf(t, unrelated, unreadableNamed(t, "Root Agency")), [][]byte{leaf}, atNoon())
			if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain ||
				store.TrustFailure != report.UnknownAuthority {
				t.Fatalf("a refusal beside a certificate no path can reach was not kept: %q, failure %q",
					store.NotAssessed, store.TrustFailure)
			}
			// THE REPORT CONTRACT REFUSES A COUNT BESIDE A REFUSAL, and a row that
			// carried one threw the whole of L5 away on the first binary run.
			if store.UnreadableCount != 0 {
				t.Errorf("a refusal counts %d certificates it could not read, which the report contract refuses",
					store.UnreadableCount)
			}
		})
	}
}

// TestANameIsMatchedTheWayOpenSSLMatchesIt - ADR136. OpenSSL compares names
// with case and inner spacing folded, so a certificate Go cannot read whose
// subject differs from the leaf's issuer only in those is on the path there,
// and the refusal may be Go's alone.
func TestANameIsMatchedTheWayOpenSSLMatchesIt(t *testing.T) {
	_, leaf, unrelated := rootGoCannotRead(t)
	var store report.TrustStore
	Verify(&store, bundleOf(t, unrelated, unreadableNamed(t, "  CertDoctor   Negative Serial ROOT ")), [][]byte{leaf},
		atNoon())
	if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "holds 1 certificate(s)") {
		t.Errorf("a subject equal to the leaf's issuer once folded was taken for another name: %q, failure %q",
			store.NotAssessed, store.TrustFailure)
	}
}

// TestAPathThroughTheStoreReachesACertificateGoCannotRead - ADR136. The issuer
// of the leaf is in the store and was not presented, and its own issuer is the
// certificate Go cannot read: the names the path can reach grow through the
// store, or the refusal would be pinned on a store a runtime may accept.
func TestAPathThroughTheStoreReachesACertificateGoCannotRead(t *testing.T) {
	from, to := atNoon().Add(-time.Hour), atNoon().Add(time.Hour)
	rootDER, rootKey := mint(t, "certdoctor far root", 11, nil, nil, true, from, to)
	middleDER, middleKey := mint(t, "certdoctor stored intermediate", 12, rootDER, rootKey, true, from, to)
	leaf, _ := mint(t, "partner.test", 13, middleDER, middleKey, false, from, to)
	// A readable root that signed nothing here, so the store has an anchor to
	// judge with and the walk is what decides.
	unrelated, _ := mint(t, "certdoctor unrelated root", 14, nil, nil, true, from, to)

	var store report.TrustStore
	VerifySelfSignedAnchors(&store, bundleOf(t, unrelated, middleDER, negativeSerial(t, rootDER, rootKey)),
		[][]byte{leaf}, atNoon())
	if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "holds 1 certificate(s)") {
		t.Errorf("a root reached through the store's own intermediate was left off the path: %q, failure %q",
			store.NotAssessed, store.TrustFailure)
	}
}

// numberInName gives a certificate a name attribute whose value is a number:
// crypto/x509 reads it, and OpenSSL's canonical form copies it as it is, so
// this program does not guess at it - ADR136.
func numberInName(certificate *x509.Certificate) {
	certificate.Subject.ExtraNames = append(certificate.Subject.ExtraNames,
		pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: 5})
}

// TestWhatCannotBeReadOnTheWayCountsEverything - ADR136. When the chain or the
// store holds a certificate or a name this program cannot put in OpenSSL's
// form, which names a path can reach is not known, so every certificate Go
// could not read counts and the refusal is not pinned on the store.
func TestWhatCannotBeReadOnTheWayCountsEverything(t *testing.T) {
	from, to := atNoon().Add(-time.Hour), atNoon().Add(time.Hour)
	unrelated, _ := mint(t, "certdoctor unrelated root", 21, nil, nil, true, from, to)
	absentDER, absentKey := mint(t, "certdoctor absent root", 22, nil, nil, true, from, to)
	leaf, _ := mint(t, "partner.test", 23, absentDER, absentKey, false, from, to)
	numbered, _ := mint(t, "certdoctor numbered root", 24, nil, nil, true, from, to, numberInName)
	farDER, farKey := mint(t, "certdoctor numbered far root", 25, nil, nil, true, from, to, numberInName)
	middleDER, middleKey := mint(t, "certdoctor stored intermediate", 26, farDER, farKey, true, from, to)
	underMiddle, _ := mint(t, "partner.test", 27, middleDER, middleKey, false, from, to)
	agency := unreadableNamed(t, "Root Agency")

	for _, tc := range []struct {
		name  string
		store [][]byte
		chain [][]byte
	}{
		{"a presented certificate Go cannot read", [][]byte{unrelated, agency}, [][]byte{leaf, junk}},
		{"a stored subject with a number in it", [][]byte{unrelated, numbered, agency}, [][]byte{leaf}},
		{"an issuer on the way with a number in it", [][]byte{unrelated, middleDER, agency}, [][]byte{underMiddle}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var store report.TrustStore
			VerifySelfSignedAnchors(&store, bundleOf(t, tc.store...), tc.chain, atNoon())
			if store.TrustsPresentedChain != nil || !strings.Contains(store.NotAssessed, "holds 1 certificate(s)") {
				t.Errorf("a path nobody could follow was taken to miss CN=Root Agency: %q, failure %q",
					store.NotAssessed, store.TrustFailure)
			}
		})
	}
}

// TestASubjectThatCannotBeFoldedCountsEverything - ADR136. A name this program
// cannot put in OpenSSL's form could be any name, so it decides nothing and the
// refusal may be Go's alone.
func TestASubjectThatCannotBeFoldedCountsEverything(t *testing.T) {
	if _, ok := subjectOf(junk); ok {
		t.Error("a certificate block with nothing in it gave a subject")
	}
	// A certificate whose TBSCertificate breaks off inside its serial number,
	// and one that ends after it.
	for name, tbs := range map[string][]byte{"broken": {0x02, 0x05, 0x01}, "short": {0x02, 0x01, 0x01}} {
		der, err := asn1.Marshal(struct {
			TBS       asn1.RawValue
			Algorithm asn1.RawValue
			Signature asn1.BitString
		}{asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: tbs},
			asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true}, asn1.BitString{}})
		if err != nil {
			t.Fatalf("the %s certificate will not encode: %v", name, err)
		}
		if _, ok := subjectOf(der); ok {
			t.Errorf("a %s TBSCertificate gave a subject", name)
		}
	}
	if _, ok := foldedName([]byte{0x30, 0x03, 0x31, 0x01}); ok {
		t.Error("a name that is not a sequence of attributes was folded")
	}
	numbered, err := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: 5}}})
	if err != nil {
		t.Fatalf("the numbered name will not encode: %v", err)
	}
	if _, ok := foldedName(numbered); ok {
		t.Error("a name holding a number was folded as though it were text")
	}
	// OpenSSL lowers ASCII letters only, so the U with diaeresis keeps its case.
	for raw, want := range map[string]string{" A  b\tC ": "a b c", "\xc3\x9cBER AG": "\xc3\x9cber ag", "": ""} {
		if got := foldedValue(raw); got != want {
			t.Errorf("%q folded to %q, want %q", raw, got, want)
		}
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
