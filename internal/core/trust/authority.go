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
// SO THE FINDING STATES THE MEASUREMENT AND NAMES BOTH READINGS - unless the
// issuer's name matches the inspection-product list in inspection.go, which is
// the ONLY thing in this program that may turn a count into a sentence about
// somebody's network. P6b-K2 built that list; it did not move the line above.
//
// WHAT A MATCH CHANGES AND WHAT IT DOES NOT. It adds a clause to the summary, it
// replaces the caveat with one saying the naming rests on a NAME, and it fills
// in one field. It does not change the holding, either store list, the
// fingerprint, the trust rows, the remediation commands or the layer's status -
// all of those are established before the list is consulted, and they are what
// the reader acts on either way. That is what "the list is only for naming"
// means in code rather than in prose.

// authorityOf builds the one row saying who signed this chain and how widely the
// machine holds them, or returns nil when there is nothing honest to say.
//
// NIL IS A REAL ANSWER HERE. A run where no store could be assessed - a machine
// whose only rows are builds with a compiled-in bundle, say - has measured
// nothing about any signer, and a row saying
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

	// THE NAME IS ASKED FOR LAST AND CHANGES NOTHING THAT WAS MEASURED - ADR53.
	// The holding, the two lists and the fingerprint are already settled above,
	// and they would be identical whether this matched or not. What a match adds
	// is permission to say what is happening, and a different caveat: the one
	// beside a holding says this program cannot tell two situations apart, and
	// that stops being true the moment the issuer names a product.
	if named := matchInspection(leaf.Issuer); named != nil {
		authority.Inspection = &report.Inspection{
			Product:          named.Product,
			MatchedAttribute: named.Attribute,
		}
		authority.Caveat = inspectionCaveat
	}

	return &report.Finding{
		Kind:             report.FindingSigningAuthority,
		Summary:          summaryFor(authority, leaf.SelfSigned),
		Source:           report.SourceDetected,
		SigningAuthority: &authority,
	}
}

// inspectionCaveat is what a NAMED finding does not settle, and it is a
// different sentence from the three beside the holdings rather than an extra
// clause on one of them.
//
// THE HEDGE HAD TO CHANGE, NOT JUST GROW. The caveat for some_stores says this
// program cannot tell an inspection appliance from an organisation's own
// authority - which is exactly right while nothing is named, and false the
// moment something is. Leaving it in place beside a name would be a report
// contradicting itself in two adjacent lines.
//
// WHAT REPLACES IT SAYS WHAT THE NAMING RESTS ON. It rests on a string in
// somebody else's certificate matching a list this program carries. That is a
// good reason to say the word and a bad reason to be certain, and inviolable
// rule 21 asks for exactly that distance to be printed rather than assumed.
const inspectionCaveat = "this name comes from a list this program carries, with a source beside every entry - " +
	"it rests on the NAME in the issuer rather than on anything measured about this network, and an " +
	"organisation is free to call its own authority anything at all, so the fingerprint above is what " +
	"somebody checking this would compare"

// summaryFor is the line every surface prints: the measurement, and the name
// when there is one.
//
// THE MEASUREMENT COMES FIRST AND IS UNTOUCHED BY THE NAME. A reader who does
// not believe the second half still has the first, and the first is the half
// that produced the trust rows and the commands underneath.
func summaryFor(a report.SigningAuthority, selfSigned bool) string {
	measured := sentenceFor(a, selfSigned)
	if a.Inspection == nil {
		return measured
	}
	return fmt.Sprintf("%s - and that issuer names %s, a TLS inspection product, so this connection is being "+
		"intercepted and re-signed between here and the server", measured, a.Inspection.Product)
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
	keys := keysOf(stores)
	counted := map[string]bool{}
	for _, store := range stores {
		if store.TrustsPresentedChain == nil {
			continue
		}
		if *store.TrustsPresentedChain {
			if seen(counted, keys, store) {
				continue
			}
			trusting = append(trusting, label(store))
			continue
		}
		if store.TrustFailure != report.UnknownAuthority {
			continue
		}
		if seen(counted, keys, store) {
			continue
		}
		refusing = append(refusing, label(store))
	}
	return trusting, refusing
}

// seen reports whether this store has already been counted, and records it.
//
// A ROW THAT DEFERS IS THE STORE IT DEFERS TO - ADR108 part 4. Measured with
// probe S25: curl on Schannel judged by this account's Root store, the one the
// system-store row for CurrentUser reads, so the two rows are one opinion and are
// counted once.
//
// AND IT IS COUNTED UNDER THAT STORE'S OWN KEY, NOT UNDER THE POINTER - ADR110.
// On Linux the platform store is a file and is counted by its path, so a key
// spelled from the pointer counted one store twice: measured with the binary on
// 2026-10-20, "not held by: system-store debian, system-store debian".
func seen(counted map[string]bool, keys map[report.StoreRef]string, store report.TrustStore) bool {
	key := keyOf(store)
	if store.DefersTo != nil {
		key = refKey(*store.DefersTo)
		if target, found := keys[*store.DefersTo]; found {
			key = target
		}
	}
	if counted[key] {
		return true
	}
	counted[key] = true
	return false
}

// keyOf is what a row that does not defer is counted by: the file it reads, or
// for a platform store with no file, its instance - which is what the instance is
// for everywhere else in this layer.
func keyOf(store report.TrustStore) string {
	if store.StorePath != "" {
		return store.StorePath
	}
	return refKey(report.StoreRef{Runtime: store.Runtime, Instance: store.Instance})
}

func refKey(ref report.StoreRef) string { return ref.Runtime + "\x00" + ref.Instance }

// keysOf maps every row that does not defer to the key it is counted by, so a
// row pointing at it is counted under the same one.
func keysOf(stores []report.TrustStore) map[report.StoreRef]string {
	keys := map[report.StoreRef]string{}
	for _, store := range stores {
		if store.DefersTo == nil {
			keys[report.StoreRef{Runtime: store.Runtime, Instance: store.Instance}] = keyOf(store)
		}
	}
	return keys
}

// label is how one store is named in the two lists. It matches the wording of a
// trust row's own summary, so a reader meets one spelling rather than two.
//
// A ROW THAT DEFERS IS NAMED AS THE STORE IT DEFERS TO, so that the store is
// spelled one way whichever of its rows the walk met first.
func label(store report.TrustStore) string {
	if store.DefersTo != nil {
		return strings.TrimSpace(store.DefersTo.Runtime + " " + store.DefersTo.Instance)
	}
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
//
// A LEAF THAT SIGNED ITSELF SAYS SO - ADR107. The issuer of such a certificate
// is its own subject, and a sentence naming it as though it were somebody else
// hides the one thing a person searching for "self signed certificate" needs
// to recognise. The flag comes from L4, where it was read off the signature, so
// a certificate merely NAMING itself as issuer does not get the word.
func sentenceFor(a report.SigningAuthority, selfSigned bool) string {
	signed := a.Issuer + " signed this certificate"
	if selfSigned {
		signed += " itself"
	}
	switch a.HeldBy {
	case report.HeldByAllStores:
		return fmt.Sprintf("%s, and all %d store(s) assessed here hold an anchor for it",
			signed, len(a.TrustingStores))
	case report.HeldByNoStores:
		return signed + ", and no store on this machine holds an anchor for it"
	default:
		return fmt.Sprintf("%s and is an authority local to this machine - %d store(s) here hold it and %d do not",
			signed, len(a.TrustingStores), len(a.RefusingStores))
	}
}
