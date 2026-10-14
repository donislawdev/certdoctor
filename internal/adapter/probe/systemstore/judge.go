package systemstore

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The error bits of CERT_TRUST_STATUS this package reads.
//
// SOURCE, inviolable rule 18: CERT_TRUST_STATUS structure (wincrypt.h), read
// 2026-10-14 at https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status
//
// THEY ARE READ AS NUMBERS, NEVER AS THE SENTENCE WINDOWS WOULD PRINT FOR THEM -
// inviolable rule 19. The sentence is in the language of the machine being
// diagnosed, and the number is the same on every one of them.
const (
	notTimeValid               uint32 = 0x00000001
	revoked                    uint32 = 0x00000004
	notSignatureValid          uint32 = 0x00000008
	notValidForUsage           uint32 = 0x00000010
	untrustedRoot              uint32 = 0x00000020
	cyclic                     uint32 = 0x00000080
	invalidExtension           uint32 = 0x00000100
	invalidPolicyConstraints   uint32 = 0x00000200
	invalidBasicConstraints    uint32 = 0x00000400
	invalidNameConstraints     uint32 = 0x00000800
	notSupportedNameConstraint uint32 = 0x00001000
	notDefinedNameConstraint   uint32 = 0x00002000
	notPermittedNameConstraint uint32 = 0x00004000
	excludedNameConstraint     uint32 = 0x00008000
	partialChain               uint32 = 0x00010000
	weakSignature              uint32 = 0x00100000
	noIssuanceChainPolicy      uint32 = 0x02000000
	explicitDistrust           uint32 = 0x04000000
	notSupportedCriticalExt    uint32 = 0x08000000
)

// refusals are the bits that settle the answer on their own. Whatever root
// Windows could still fetch, a chain carrying one of these is refused - and
// none of them says anything about WHO signed it, so they answer "other", the
// one refusal that never earns a command.
const refusals = revoked | notSignatureValid | notValidForUsage | cyclic | invalidExtension |
	invalidPolicyConstraints | invalidBasicConstraints | invalidNameConstraints | notSupportedNameConstraint |
	notDefinedNameConstraint | notPermittedNameConstraint | excludedNameConstraint | weakSignature |
	noIssuanceChainPolicy | explicitDistrust | notSupportedCriticalExt

// missingAnchor are the two ways a chain fails for want of a root. They are
// the AMBIGUOUS pair: with the network switched off, a root Windows would have
// fetched looks exactly like one nobody installed - ADR101, measured 2026-09-23.
//
// WHAT IS IN NONE OF THESE LISTS IS UNDETERMINED BY CONSTRUCTION: the two
// revocation bits, which only appear when revocation is asked for and it never
// is here, the three about a trust list, and any bit a later Windows adds.
const missingAnchor = partialChain | untrustedRoot

// listFreshFor is how old this machine's copy of the program list may be before
// a missing issuer stops counting as proof that nothing would fetch it - ADR103.
//
// IT IS A JUDGEMENT, NOT A MEASUREMENT, and the owner's, 2026-10-14. The list
// carries no next update of its own - measured that day - so nothing on the
// machine says when it goes stale. A root added to the program after the last
// synchronisation would look absent, and only that case can turn this into a
// wrong FAIL, so past this age the answer is undetermined instead.
const listFreshFor = 30 * 24 * time.Hour

// built is what one chain build reported, copied out of memory Windows owns
// before that memory is handed back.
type built struct {
	// status is dwErrorStatus of the chain context.
	status uint32
	// elements are the first simple chain, leaf first, as far as Windows could
	// take it - so the last one is the certificate whose issuer is missing.
	elements []element
}

// element is one certificate of the chain and its own error bits.
type element struct {
	der    []byte
	status uint32
}

// judge writes into the row what this store made of the chain.
//
// THE ORDER IS THE DECISION. A certificate out of date is refused whatever root
// could still be fetched, so the clock is asked first. A refusal that settles
// itself comes next. A bit nobody here classified makes the answer
// undetermined before the ambiguous pair is even looked at, because guessing
// past it is how a wrong FAIL is written. Only then is the missing root weighed.
func judge(store *report.TrustStore, b built, list programList, now time.Time) {
	switch {
	case b.status == 0:
		trusts := true
		store.TrustsPresentedChain = &trusts
	case b.status&notTimeValid != 0:
		refuse(store, timeFailure(b, now))
	case b.status&refusals != 0:
		refuse(store, report.OtherFailure)
	case b.status&^missingAnchor != 0:
		store.NotAssessed = fmt.Sprintf("Windows reported a chain status this program does not classify (0x%08X), "+
			"so what this store makes of the chain is undetermined", b.status)
	case b.status&partialChain != 0:
		missingIssuer(store, b, list, now)
	default:
		untrustedSentRoot(store, b, list, now)
	}
}

// refuse records a refusal and which way it went.
func refuse(store *report.TrustStore, failure report.TrustFailure) {
	trusts := false
	store.TrustsPresentedChain = &trusts
	store.TrustFailure = failure
}

// timeFailure says which way the clock refused, read off the certificate that
// carries the bit and compared against the clock this probe was handed - the
// same clock the chain was built for.
//
// A CHAIN THAT SAYS "TIME" AND NAMES NO CERTIFICATE ANSWERS "other", the same
// rule crypto/x509's classification follows in this tree: an unclassified
// refusal produces no command, and a guessed one would.
func timeFailure(b built, now time.Time) report.TrustFailure {
	for _, e := range b.elements {
		if e.status&notTimeValid == 0 {
			continue
		}
		certificate, err := x509.ParseCertificate(e.der)
		if err != nil {
			return report.OtherFailure
		}
		if now.Before(certificate.NotBefore) {
			return report.NotYetValid
		}
		return report.Expired
	}
	return report.OtherFailure
}

// The sentences a row carries when the missing root cannot be settled here.
const (
	issuerOnTheList = "the issuer this chain needs is on this machine's copy of Microsoft's root program list and is not " +
		"installed yet - Windows fetches such a root when it first needs one and this program does not, so whether " +
		"this store would trust the chain is undetermined"
	sentRootOnTheList = "the root the server sent is on this machine's copy of Microsoft's root program list and is not " +
		"installed yet - Windows fetches such a root when it first needs one and this program does not, so whether " +
		"this store would trust the chain is undetermined"
	// issuerFetchable is the inviolable rule 16 case: the address is in a
	// certificate the server under diagnosis wrote, and this program never
	// connects where a server points.
	issuerFetchable = "the server did not send the issuer and the certificate names an address to fetch it from - " +
		"Windows would try that address and this program does not connect where a server points, so whether this " +
		"store would trust the chain is undetermined"
	noChainBuilt = "Windows returned no chain to inspect, so what this store makes of it is undetermined"
)

// missingIssuer weighs a chain Windows could not take to any root.
//
// MEASURED 2026-10-13, THREE SHAPES GIVE THIS ONE ANSWER and they need three
// different ones: a root in the program not fetched yet - www.buypass.no - a
// server that left out its intermediate and names where to find it, and an
// authority with no certificate on this machine and no address anywhere. Only
// the last is something this machine will never trust, and it is the main
// scenario of this product.
func missingIssuer(store *report.TrustStore, b built, list programList, now time.Time) {
	last, why := lastCertificate(b)
	if why != "" {
		store.NotAssessed = why
		return
	}
	switch {
	case list.available() && list.namesIssuerOf(last):
		store.NotAssessed = issuerOnTheList
	case len(last.IssuingCertificateURL) > 0:
		store.NotAssessed = issuerFetchable
	default:
		absentEverywhere(store, list, now)
	}
}

// untrustedSentRoot weighs a chain that reached a root this store does not
// hold, which the server sent itself.
//
// IT IS THE SAME QUESTION ONE STEP LATER - docs/17 calls it E4, and no target
// measured so far produced it: a server sending a root from the program that
// this machine has not fetched. The list answers it by the root's own
// fingerprint, because here the root is in hand.
func untrustedSentRoot(store *report.TrustStore, b built, list programList, now time.Time) {
	if len(b.elements) == 0 {
		store.NotAssessed = noChainBuilt
		return
	}
	if list.available() && list.holdsRoot(b.elements[len(b.elements)-1].der) {
		store.NotAssessed = sentRootOnTheList
		return
	}
	absentEverywhere(store, list, now)
}

// absentEverywhere is the last step: nothing here holds the root, nothing will
// fetch it - unless the list cannot rule that out, in which case it says why.
func absentEverywhere(store *report.TrustStore, list programList, now time.Time) {
	if why := list.cannotRuleOut(now); why != "" {
		store.NotAssessed = "this store holds no root for this chain, but " + why +
			", so whether Windows would fetch one is undetermined"
		return
	}
	refuse(store, report.UnknownAuthority)
}

// cannotRuleOut says why this list cannot prove a root absent from the
// program, or returns the empty string when it can.
func (l programList) cannotRuleOut(now time.Time) string {
	day := l.synced.UTC().Format(time.DateOnly)
	switch {
	case !l.available():
		return "this machine's copy of Microsoft's root program list " + l.unreadable
	case l.synced.IsZero():
		return "this machine records no date for its copy of Microsoft's root program list"
	case now.Before(l.synced):
		// The list is dated after this machine's own clock, so its age is not
		// known - and an unknown age is not a fresh one.
		return "this machine's copy of Microsoft's root program list is dated " + day + ", later than this machine's clock"
	case now.Sub(l.synced) > listFreshFor:
		return "this machine's copy of Microsoft's root program list was last brought up to date on " + day +
			", too long ago to rule out a root added since"
	}
	return ""
}

// lastCertificate is the certificate whose issuer Windows could not find.
func lastCertificate(b built) (*x509.Certificate, string) {
	if len(b.elements) == 0 {
		return nil, noChainBuilt
	}
	certificate, err := x509.ParseCertificate(b.elements[len(b.elements)-1].der)
	if err != nil {
		return nil, fmt.Sprintf("the last certificate Windows could place in the chain could not be parsed (%v), "+
			"so whether its issuer could be fetched is undetermined", err)
	}
	return certificate, ""
}
