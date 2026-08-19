package probe

import (
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
	roots := x509.NewCertPool()
	anchors := 0
	rest := anchorsPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		anchor, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// One unreadable entry in somebody's store is not a reason to throw
			// away the rest of it.
			continue
		}
		roots.AddCert(anchor)
		anchors++
	}
	store.TrustAnchorCount = anchors

	if anchors == 0 {
		store.NotAssessed = "the store holds no certificate this program could read"
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
	intermediates := x509.NewCertPool()
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
