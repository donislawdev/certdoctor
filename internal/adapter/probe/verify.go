package probe

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Verify fills in what one store makes of a presented chain.
//
// ONE PLACE, TWO RUNTIMES, AND THAT IS THE WHOLE REASON THIS IS NOT A METHOD ON
// EITHER PROBE. git reads a PEM bundle off disk. java gets PEM out of keytool
// -list -rfc - measured 2026-08-18, 113 blocks from one JDK. The bytes arrive
// differently and mean the same thing, so the rule that reads them lives ONCE.
// A copy here is the measured shape of OBS50, where duplicating a boundary
// function disarmed three mutation entries at once and reported them as SKIP.
//
// IT ASKS ONE QUESTION: does this store hold an anchor that closes this chain.
// NOT whether the certificate is valid for the host - that is a different
// question with a different answer, and folding them together would report a
// trust failure for a name mismatch. The verdict is written into the store, so
// the caller cannot forget to record why there is no verdict.
// THE CLOCK ARRIVES AS AN ARGUMENT, and that is not ceremony. Left to itself
// crypto/x509 compares against time.Now, so the same store and the same chain
// would answer differently depending on when the test ran - and the answer this
// function has to distinguish is precisely "the certificate is out of date"
// from "nobody here signed it". A wrong machine clock is one of the commonest
// causes of the failure this product diagnoses, and it is one an imported
// certificate does not repair.
func Verify(store *report.TrustStore, anchorsPEM []byte, chain [][]byte, now time.Time) {
	verify(store, anchorsPEM, chain, now, false)
}

// VerifySelfSignedAnchors is Verify for a runtime that ends a chain only at a
// self-signed certificate - ADR111 part 3, measured rather than chosen.
//
// NODE DOES NOT TREAT EVERY CERTIFICATE IT HOLDS AS AN ANCHOR. Measured with
// probe S27 on 2026-10-20 in all eight environments: an intermediate alone in
// NODE_EXTRA_CA_CERTS did not make a leaf signed by it trusted, because Node
// sets no partial-chain flag for OpenSSL, while Verify above - every entry a
// root - says it would. So the other entries of the store help build the path
// and never end it, and the count of anchors counts only what can end one.
func VerifySelfSignedAnchors(store *report.TrustStore, anchorsPEM []byte, chain [][]byte, now time.Time) {
	verify(store, anchorsPEM, chain, now, true)
}

// verify is the one rule both functions above apply - selfSignedOnly is the
// only thing that differs between them.
func verify(store *report.TrustStore, anchorsPEM []byte, chain [][]byte, now time.Time, selfSignedOnly bool) {
	roots, held, anchors := anchorsIn(anchorsPEM, selfSignedOnly)
	store.TrustAnchorCount = anchors

	if anchors == 0 {
		store.NotAssessed = "the store holds no certificate this program could read"
		if selfSignedOnly {
			store.NotAssessed = "the store holds no self-signed certificate this program could read, and only one of " +
				"those ends a chain for this runtime"
		}
		return
	}
	if len(chain) == 0 {
		store.NotAssessed = "no chain was presented, so this store had nothing to judge"
		store.TrustAnchorCount = 0
		return
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		store.NotAssessed = fmt.Sprintf("the presented leaf could not be parsed: %v", err)
		store.TrustAnchorCount = 0
		return
	}
	intermediates := held
	for _, der := range chain[1:] {
		if certificate, parseErr := x509.ParseCertificate(der); parseErr == nil {
			intermediates.AddCert(certificate)
		}
	}

	_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now})
	trusts := verifyErr == nil
	store.TrustsPresentedChain = &trusts
	if !trusts {
		store.TrustFailure = classify(verifyErr, now)
	}
}

// anchorsIn reads a PEM bundle into the certificates that end a chain and the
// ones that only help build it. With selfSignedOnly false every certificate is
// an anchor and held stays empty.
func anchorsIn(anchorsPEM []byte, selfSignedOnly bool) (roots, held *x509.CertPool, anchors int) {
	roots, held = x509.NewCertPool(), x509.NewCertPool()
	rest := anchorsPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return roots, held, anchors
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// One unreadable entry in somebody's store is not a reason to throw
			// away the rest of it.
			continue
		}
		if selfSignedOnly && !selfSigned(certificate) {
			held.AddCert(certificate)
			continue
		}
		roots.AddCert(certificate)
		anchors++
	}
}

// selfSigned reports whether a certificate names itself as its issuer and its
// own key verifies its signature - the rule probe S27 counted with.
//
// CheckSignature AND NOT CheckSignatureFrom, and the difference is measured.
// CheckSignatureFrom refuses a SHA-1 signature and a certificate that may not
// sign others, while CheckSignature accepts SHA-1 and asks nothing about the
// certificate - crypto/x509 of Go 1.27, x509.go. On 2026-10-20 the 121 roots
// node v26.9.0 is built with were all self-signed by this rule, and three of
// them, SHA-1 roots, would not have been by the other.
//
// AN MD5 SIGNATURE FAILS EITHER WAY. The same day the system list on the
// owner's machine held 133 distinct certificates: 77 self-signed by this rule,
// 52 not, and three naming themselves with a signature Go refuses - two MD5
// roots and one of an algorithm it does not know - which count as not ending a
// chain. That no chain a server sends today ends at one of them is an
// ASSESSMENT, not a measurement.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// classify says WHICH WAY a store refused, because only one of the ways is
// something a person can repair by adding a certificate.
//
// IT BRANCHES ON TYPES AND ON A DECLARED CONSTANT, NEVER ON A MESSAGE. That is
// inviolable rule 19 applied to the standard library rather than to somebody
// else's program: the text of these errors is not a contract and has changed
// between Go releases, while the types and x509.Expired are the API.
//
// WHY THE LAST CASE IS NOT A GUESS. An unclassified failure answers "other",
// which produces no command at all. Choosing the commonest reason instead would
// hand somebody a certificate to import for a problem importing does not touch,
// and they would wait for it to work.
func classify(err error, now time.Time) report.TrustFailure {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return report.UnknownAuthority
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		// crypto/x509 folds "past its end" and "before its start" into one
		// reason, and the two send a person to opposite places: one to whoever
		// runs the server, the other to their own clock. Which it is comes from
		// the certificate the error names, compared against the clock we were
		// handed rather than one this function read.
		if invalid.Cert != nil && now.Before(invalid.Cert.NotBefore) {
			return report.NotYetValid
		}
		return report.Expired
	}
	return report.OtherFailure
}
