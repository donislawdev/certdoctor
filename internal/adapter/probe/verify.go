package probe

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

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
func Verify(store *report.TrustStore, anchorsPEM []byte, chain [][]byte) {
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

	_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
	trusts := verifyErr == nil
	store.TrustsPresentedChain = &trusts
}
