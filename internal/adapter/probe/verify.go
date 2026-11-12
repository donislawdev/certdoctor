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
// only thing that differs between them. It hands back the chains it built and
// every certificate the store holds, for a runtime that judges those further,
// and what it could not read, for one that refuses after it.
func verify(store *report.TrustStore, anchorsPEM []byte, chain [][]byte, now time.Time,
	selfSignedOnly bool) (built [][]*x509.Certificate, stored []*x509.Certificate, skipped unread) {
	roots, held, stored, anchors, skipped := anchorsIn(anchorsPEM, selfSignedOnly)
	store.TrustAnchorCount = anchors

	if anchors == 0 {
		store.NotAssessed = "the store holds no certificate this program could read"
		if selfSignedOnly {
			store.NotAssessed = "the store holds no self-signed certificate this program could read, and only one of " +
				"those ends a chain for this runtime"
		}
		return nil, nil, skipped
	}
	if len(chain) == 0 {
		store.NotAssessed = "no chain was presented, so this store had nothing to judge"
		store.TrustAnchorCount = 0
		return nil, nil, skipped
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		store.NotAssessed = fmt.Sprintf("the presented leaf could not be parsed: %v", err)
		store.TrustAnchorCount = 0
		return nil, nil, skipped
	}
	intermediates := held
	seen := append([]*x509.Certificate{leaf}, stored...)
	for _, der := range chain[1:] {
		if certificate, parseErr := x509.ParseCertificate(der); parseErr == nil {
			intermediates.AddCert(certificate)
			seen = append(seen, certificate)
		}
	}

	built, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now})
	trusts := verifyErr == nil
	var failure report.TrustFailure
	if !trusts {
		failure = classify(verifyErr, now)
	}
	// A REFUSAL GO'S OWN LIST MAY HAVE MADE IS NOT PINNED ON THE STORE - ADR113.
	// That list ends up as a CertificateInvalidError, so as OtherFailure, and an
	// unknown authority or a date fails before it is applied (verify.go of
	// go1.27.3), so those refusals stand. The price, named: a store holding one
	// of those keys beside a chain refused for another such reason - a key usage,
	// a name constraint - says it could not judge rather than "other", which
	// carries no command either.
	if failure == report.OtherFailure && carriesKeyGoRefuses(seen) {
		store.NotAssessed = refusedByGo
		store.TrustAnchorCount = 0
		return nil, nil, skipped
	}
	store.TrustsPresentedChain = &trusts
	store.TrustFailure = failure
	store.UnreadableCount = skipped.count
	if skipped.overturns(store, chain, stored) {
		return nil, nil, skipped
	}
	return built, stored, skipped
}

// unread is what anchorsIn could not read - how many certificates the Go
// library refused to parse, and each one's subject and reason.
type unread struct {
	count int
	// subjects holds the subject of each certificate counted, folded by
	// foldedName, with the reason Go gave, in the order they were met.
	subjects []unreadSubject
}

// unreadSubject is the subject of one certificate the Go library could not
// read, read on its own - known false when even that could not be read.
type unreadSubject struct {
	name  string
	known bool
	why   error
}

// onPath counts the certificates anchorsIn could not read that a
// chain-building library could still put on the path of this chain, and gives
// the first one's reason - ADR136, closing OBS223.
//
// AN ISSUER IS FOUND BY ITS NAME. OpenSSL takes as the issuer of a certificate
// only one whose subject is that certificate's issuer name (X509_check_issued in
// crypto/x509/v3_purp.c, read 2026-11-12 at
// https://github.com/openssl/openssl/blob/openssl-3.5/crypto/x509/v3_purp.c), and
// a certificate whose subject is no issuer name on any path from this chain
// cannot be on it, whatever its key. Measured 2026-11-12 on this machine: with
// NODE_USE_SYSTEM_CA=1 Node's list carries CN=Root Agency twice from the Windows
// store, Go cannot read it, and every node row that refused a chain - a missing
// company root among them - said it could not judge instead.
//
// THE PATH MAY RUN THROUGH THE STORE ITSELF, so the names grow: the issuer of
// every presented certificate, then the issuer of every stored one whose subject
// is a name already reached, until nothing new is.
//
// A NAME THAT CANNOT BE FOLDED COUNTS EVERYTHING, and so does a subject that
// cannot be read: either could be any name, and the direction of a mistake must
// be "cannot be told", never a refusal pinned on a store - ADR128.
//
// overturns asks it only after making sure something was not read, so the
// first subject is always there.
func (u unread) onPath(chain [][]byte, stored []*x509.Certificate) (int, error) {
	reached, ok := issuerNames(chain, stored)
	if !ok {
		return u.count, u.subjects[0].why
	}
	on, first := 0, error(nil)
	for _, subject := range u.subjects {
		if subject.known && !reached[subject.name] {
			continue
		}
		if on == 0 {
			first = subject.why
		}
		on++
	}
	return on, first
}

// issuerNames is every issuer name, folded, that a path from the presented
// chain can reach: the issuers of the presented certificates, then the issuer
// of every stored certificate whose subject is a name already reached, until
// nothing new is. It answers false when a certificate or a name on the way
// cannot be read.
func issuerNames(chain [][]byte, stored []*x509.Certificate) (map[string]bool, bool) {
	reached := map[string]bool{}
	var frontier []string
	reach := func(raw []byte) bool {
		name, ok := foldedName(raw)
		if ok && !reached[name] {
			reached[name] = true
			frontier = append(frontier, name)
		}
		return ok
	}
	for _, der := range chain {
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !reach(certificate.RawIssuer) {
			return nil, false
		}
	}
	bySubject := map[string][]*x509.Certificate{}
	for _, certificate := range stored {
		name, ok := foldedName(certificate.RawSubject)
		if !ok {
			return nil, false
		}
		bySubject[name] = append(bySubject[name], certificate)
	}
	for len(frontier) > 0 {
		name := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		for _, certificate := range bySubject[name] {
			if !reach(certificate.RawIssuer) {
				return nil, false
			}
		}
	}
	return reached, true
}

// overturns takes away a refusal the store made while it held a certificate
// the Go library could not read and that could be on the chain's path, and says
// why there is no verdict - ADR128, decided by the owner 2026-11-04, narrowed to
// the path by ADR136. It reports whether it did.
//
// THE CHAIN MAY END AT THAT CERTIFICATE FOR THE PROGRAM JUDGED HERE. Measured on
// macOS 27.2: Go refused EC-ACC in /private/etc/ssl/cert.pem for its negative
// serial number and the Python reading the same file loaded it, so a chain whose
// one path runs through it is refused here and accepted there. A trust stands,
// because the path Go built is a path whatever else the store holds - and so
// does a refusal when nothing Go could not read can be on the path.
//
// NOT GODEBUG=x509negativeserial=1. Reading such a certificate as an anchor
// would claim Go builds a path through it, and Go refuses to - and a store holds
// certificates Go cannot read for more reasons than one.
//
// EVERY REFUSAL A STORE WRITES IS ASKED, so this is called where one is written:
// at the end of verify, and after the strict rules. The path is asked only
// then, so a store that trusts, or read everything, pays nothing for it.
func (u unread) overturns(store *report.TrustStore, chain [][]byte, stored []*x509.Certificate) bool {
	if u.count == 0 || store.TrustsPresentedChain == nil || *store.TrustsPresentedChain {
		return false
	}
	onPath, first := u.onPath(chain, stored)
	if onPath == 0 {
		// A REFUSAL THAT STANDS COUNTS NOTHING IT COULD NOT READ. What no path can
		// reach decided nothing about it, and the report contract counts unread
		// certificates only beside a trust - measured 2026-11-12, when a node row
		// kept its refusal and its count and the whole of L5 was thrown away for
		// breaking the contract.
		store.UnreadableCount = 0
		return false
	}
	Undetermined(store, fmt.Sprintf("this store holds %d certificate(s) the Go library could not read (the first: %v), "+
		"which the program judged here may read and end the chain at, so whether it accepts this chain cannot be told",
		onPath, first))
	return true
}

// anchorsIn reads a PEM bundle into the certificates that end a chain and the
// ones that only help build it, and hands back every certificate it read and
// what it could not. With selfSignedOnly false every certificate is an anchor
// and held stays empty.
func anchorsIn(anchorsPEM []byte, selfSignedOnly bool) (roots, held *x509.CertPool, stored []*x509.Certificate,
	anchors int, skipped unread) {
	roots, held = x509.NewCertPool(), x509.NewCertPool()
	rest := anchorsPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return roots, held, stored, anchors, skipped
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// One unreadable entry in somebody's store is not a reason to throw
			// away the rest of it - and it is counted, because the program judged
			// here may read it - ADR128.
			skipped.count++
			name, known := subjectOf(block.Bytes)
			skipped.subjects = append(skipped.subjects, unreadSubject{name: name, known: known, why: err})
			continue
		}
		stored = append(stored, certificate)
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

// SelfSigned is the rule above for a probe that has to know, before judging,
// whether a list can end a chain at all - pip on Windows.
func SelfSigned(c *x509.Certificate) bool { return selfSigned(c) }

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
