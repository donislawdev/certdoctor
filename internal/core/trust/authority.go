package trust

import (
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// This file is the only place in the program that decides who signed a chain and
// how widely this machine holds that signer, and the authority guard is what
// keeps it that way.
//
// WHY ONE PLACE. Saying that a signer is local to this machine is one step away
// from the sentence inviolable rule 21 calls harm - "you are being intercepted" -
// and it is safe only when several facts are weighed together: which stores were
// actually assessed, which of them closed this chain, and which refused it for
// the one reason that says anything about a signer at all. A second place
// weighing three of those four would produce a sentence that reads identically.
//
// WHAT THIS FILE WILL NOT DO, AND THE REASON IS MEASURED RATHER THAN CAUTIOUS.
// It never concludes interception. On the bench, 2026-08-19, with a root
// deployed into one store and withheld from another - the shape a group policy
// push produces:
//
//	middlebox        L4 FAIL chain incomplete   one store trusts, one refuses
//	honest internal  L4 PASS chain complete     one store trusts, one refuses
//
// The trust answer is the same. The structural difference is an accident of that
// particular middlebox signing leaves straight from its root, and it vanished the
// moment the same middlebox was handed an intermediate: it then presented a
// complete chain with the same subjects the honest server serves, differing only
// in a fingerprint nothing here can compare against. A rule accusing on these
// facts would accuse scenario S-3 - four JDKs, curl working, the Java service
// failing - which is an ordinary corporate machine behaving as designed.
//
// SO THE FINDING STATES THE MEASUREMENT AND NAMES BOTH READINGS. Naming one of
// them waits for a match against the inspection-product list, which is P6b-K2.

// authorityOf builds the one row saying who signed this chain and how widely the
// machine holds them, or returns nil when there is nothing honest to say.
//
// NIL IS A REAL ANSWER HERE. A run where no store could be assessed - every curl
// on Schannel, say - has measured nothing about any signer, and a row saying
// "no_stores" would turn our own inability to look into a fact about somebody's
// certificate authority. That is the inversion inviolable rule 15 forbids.
func authorityOf(leaf *report.Certificate, stores []report.TrustStore) *report.Finding {
	if leaf == nil || leaf.Issuer == "" || leaf.FingerprintSHA256 == "" {
		// L4 established no leaf, or established one the contract would refuse.
		// Either way there is no signer to describe.
		return nil
	}

	trusting, refusing := sides(stores)
	if len(trusting) == 0 && len(refusing) == 0 {
		return nil
	}

	held := holdingOf(trusting, refusing)
	authority := report.SigningAuthority{
		Issuer:          leaf.Issuer,
		LeafFingerprint: leaf.FingerprintSHA256,
		HeldBy:          held,
		TrustingStores:  trusting,
		RefusingStores:  refusing,
		Caveat:          caveats[held],
	}
	return &report.Finding{
		Kind:             report.FindingSigningAuthority,
		Summary:          sentenceFor(authority),
		Source:           report.SourceDetected,
		SigningAuthority: &authority,
	}
}

// sides splits the stores into the ones that hold an anchor closing this chain
// and the ones that answered that they hold no such signer.
//
// ONLY AN UNKNOWN AUTHORITY COUNTS AS A REFUSAL HERE, and the omission is the
// interesting part. A store that refused because something had EXPIRED built the
// path first - it holds the signer, and it is saying something about a clock or
// a certificate rather than about who signed. Counting it as "does not hold the
// signer" would produce a disagreement between stores that does not exist, which
// is the one mistake this whole finding is shaped to avoid.
//
// STORES ARE COUNTED BY THE FILE THEY READ, NOT BY THE ROW. Measured on the
// owner's machine: two curl binaries in PATH, and a runtime's store can be the
// same file another runtime already reads. Two rows over one file are one
// opinion, and counting them twice would manufacture agreement or disagreement
// out of an installation detail.
func sides(stores []report.TrustStore) (trusting, refusing []string) {
	trusting, refusing = []string{}, []string{}
	counted := map[string]bool{}
	for _, store := range stores {
		if store.TrustsPresentedChain == nil {
			continue
		}
		if *store.TrustsPresentedChain {
			if seen(counted, store) {
				continue
			}
			trusting = append(trusting, label(store))
			continue
		}
		if store.TrustFailure != report.UnknownAuthority {
			continue
		}
		if seen(counted, store) {
			continue
		}
		refusing = append(refusing, label(store))
	}
	return trusting, refusing
}

// seen reports whether this store has already been counted, and records it.
func seen(counted map[string]bool, store report.TrustStore) bool {
	key := store.StorePath
	if key == "" {
		// A platform store has no path to be counted by, so the instance is the
		// identity - which is what it is for everywhere else in this layer.
		key = store.Runtime + "\x00" + store.Instance
	}
	if counted[key] {
		return true
	}
	counted[key] = true
	return false
}

// label is how one store is named in the two lists. It matches the wording of a
// trust row's own summary, so a reader meets one spelling rather than two.
func label(store report.TrustStore) string {
	return strings.TrimSpace(store.Runtime + " " + store.Instance)
}

// holdingOf turns the two lists into the measured answer.
func holdingOf(trusting, refusing []string) report.AnchorHolding {
	switch {
	case len(refusing) == 0:
		return report.HeldByAllStores
	case len(trusting) == 0:
		return report.HeldByNoStores
	default:
		return report.HeldBySomeStores
	}
}

// caveats is what each holding does NOT settle, in one sentence.
//
// THIS TABLE IS WHERE INVIOLABLE RULE 21 LIVES, and it is a table rather than a
// branch inside the renderer for the reason parity rule 12 gives: a hedge that
// exists only on the terminal is a hedge the --json consumer never receives, and
// they are the reader most likely to turn a value into an alert.
//
// EVERY HOLDING HAS ONE, INCLUDING THE COMFORTABLE ONES. A caveat that appeared
// only on the awkward answer would itself become the signal - a reader would
// learn that prose beside this row means bad news, which is the accusation
// smuggled back in through formatting.
var caveats = map[report.AnchorHolding]string{
	report.HeldByAllStores: "this is what an ordinary publicly trusted authority looks like from here, " +
		"and it is also what a private authority looks like once it has been deployed everywhere on a machine",
	report.HeldBySomeStores: "TLS inspection looks exactly like this and so does an organisation's own certificate " +
		"authority, and this program cannot tell those two apart from one connection - the issuer and the " +
		"fingerprint beside this line are what somebody who can tell them apart would need",
	report.HeldByNoStores: "nothing on this machine accepts this name, a browser included, so this is not a " +
		"question of one runtime being configured differently from another",
}

// sentenceFor is the one line every surface prints.
//
// IT STATES THE MEASUREMENT AND STOPS. What the measurement does not settle is
// in the caveat beside it, which travels on all three surfaces - and keeping the
// two apart is what stops this line growing into a paragraph that the terminal
// then pads every other row of the matrix out to.
func sentenceFor(a report.SigningAuthority) string {
	switch a.HeldBy {
	case report.HeldByAllStores:
		return fmt.Sprintf("%s signed this certificate, and all %d store(s) assessed here hold an anchor for it",
			a.Issuer, len(a.TrustingStores))
	case report.HeldByNoStores:
		return fmt.Sprintf("%s signed this certificate, and no store on this machine holds an anchor for it",
			a.Issuer)
	default:
		return fmt.Sprintf(
			"%s signed this certificate and is an authority local to this machine - %d store(s) here hold it and %d do not",
			a.Issuer, len(a.TrustingStores), len(a.RefusingStores))
	}
}
