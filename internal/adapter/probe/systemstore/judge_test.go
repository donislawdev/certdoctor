package systemstore

import (
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The decision, on recorded bits rather than a live machine - so it is checked
// on every platform the tests run on, and a case Windows has not produced yet
// can still be pinned.

// verdict is what one judged row says, flattened for comparison.
type verdict struct {
	trusts  *bool
	failure report.TrustFailure
	unknown string
}

func judged(b built, list programList, now time.Time) verdict {
	store := report.TrustStore{}
	judge(&store, b, list, now)
	return verdict{store.TrustsPresentedChain, store.TrustFailure, store.NotAssessed}
}

func chainOf(status uint32, certificates ...[]byte) built {
	b := built{status: status}
	for _, der := range certificates {
		b.elements = append(b.elements, element{der: der})
	}
	return b
}

func (v verdict) isTrusted() bool { return v.trusts != nil && *v.trusts && v.unknown == "" }

func (v verdict) isRefused(failure report.TrustFailure) bool {
	return v.trusts != nil && !*v.trusts && v.failure == failure && v.unknown == ""
}

func (v verdict) isUndetermined(says string) bool {
	return v.trusts == nil && v.failure == "" && strings.Contains(v.unknown, says)
}

func TestAChainWindowsAcceptsIsTrusted(t *testing.T) {
	if v := judged(chainOf(0), unavailableList("absent"), testClock); !v.isTrusted() {
		t.Errorf("a chain with no error bit was not trusted: %+v", v)
	}
}

// THE CLOCK IS ASKED FIRST. A certificate out of date is refused whatever root
// could still be fetched - so even with the root missing, the answer is the
// clock's, and it says which way.
func TestACertificateOutOfDateIsRefusedAndSaysWhichWay(t *testing.T) {
	root := anAuthority(t, "root")
	expired := aLeaf(t, root, leafOptions{notBefore: testClock.Add(-48 * time.Hour), notAfter: testClock.Add(-time.Hour)})
	early := aLeaf(t, root, leafOptions{notBefore: testClock.Add(time.Hour), notAfter: testClock.Add(48 * time.Hour)})
	list := aListHolding(t, testClock, anAuthority(t, "unrelated").certificate)

	withBit := func(der []byte, status uint32) built {
		return built{status: status, elements: []element{{der: der, status: notTimeValid}}}
	}
	if v := judged(withBit(expired.Raw, notTimeValid|partialChain), list, testClock); !v.isRefused(report.Expired) {
		t.Errorf("an expired leaf with its root missing was not refused as expired: %+v", v)
	}
	if v := judged(withBit(early.Raw, notTimeValid|untrustedRoot), list, testClock); !v.isRefused(report.NotYetValid) {
		t.Errorf("a leaf not valid yet was not refused as such: %+v", v)
	}
	// The bit on the chain with no certificate carrying it, and a certificate
	// that will not parse: refused, and unclassified, because a guessed reason is
	// the one that would earn a command.
	if v := judged(chainOf(notTimeValid, expired.Raw), list, testClock); !v.isRefused(report.OtherFailure) {
		t.Errorf("a time failure no certificate carries was classified anyway: %+v", v)
	}
	if v := judged(withBit([]byte("garbage"), notTimeValid), list, testClock); !v.isRefused(report.OtherFailure) {
		t.Errorf("a time failure on an unreadable certificate was classified anyway: %+v", v)
	}
}

// A REFUSAL THAT SETTLES ITSELF WINS OVER THE MISSING ROOT - a distrusted
// certificate is refused whatever could still be fetched, and it says nothing
// about a signer, so it earns no command.
func TestARefusalThatSettlesItselfIsOther(t *testing.T) {
	root := anAuthority(t, "root")
	leaf := aLeaf(t, root, leafOptions{})
	for _, bit := range []uint32{revoked, notSignatureValid, notValidForUsage, explicitDistrust, weakSignature,
		invalidBasicConstraints, excludedNameConstraint, notSupportedCriticalExt, noIssuanceChainPolicy} {
		if v := judged(chainOf(bit|partialChain, leaf.Raw), unavailableList("absent"), testClock); !v.isRefused(report.OtherFailure) {
			t.Errorf("bit 0x%08X with the root missing was not refused as other: %+v", bit, v)
		}
	}
}

// A BIT NOBODY HERE CLASSIFIED MAKES THE ANSWER UNDETERMINED - before the
// missing root is even weighed, because guessing past it is how a wrong FAIL is
// written.
func TestABitNobodyClassifiedIsUndetermined(t *testing.T) {
	root := anAuthority(t, "root")
	leaf := aLeaf(t, root, leafOptions{})
	fresh := aListHolding(t, testClock, anAuthority(t, "unrelated").certificate)
	// The positive twin: the same chain without the stray bit is a FAIL.
	if v := judged(chainOf(partialChain, leaf.Raw), fresh, testClock); !v.isRefused(report.UnknownAuthority) {
		t.Fatalf("the positive twin was not refused, so this proves nothing: %+v", v)
	}
	const revocationUnknown = 0x00000040
	for _, bit := range []uint32{revocationUnknown, 0x00020000, 0x80000000} {
		v := judged(chainOf(bit|partialChain, leaf.Raw), fresh, testClock)
		if !v.isUndetermined("does not classify") {
			t.Errorf("bit 0x%08X was not reported as unclassified: %+v", bit, v)
		}
	}
}

// THE THREE SHAPES OF A MISSING ISSUER, measured 2026-10-13, and the one that
// is the product's main scenario.
func TestAMissingIssuerIsWeighedAgainstTheListAndTheCertificate(t *testing.T) {
	program := anAuthority(t, "a root in the program")
	private := anAuthority(t, "an authority nobody installed")
	list := aListHolding(t, testClock.Add(-72*time.Hour), program.certificate)

	cases := []struct {
		name  string
		leaf  []byte
		check func(verdict) bool
	}{
		{"its issuer is on the list - www.buypass.no",
			aLeaf(t, program, leafOptions{}).Raw, func(v verdict) bool { return v.isUndetermined(issuerOnTheList) }},
		{"it names an address to fetch its issuer from - incomplete-chain.badssl.com",
			aLeaf(t, private, leafOptions{issuerAddress: []string{"http://127.0.0.1:9/issuer.crt"}}).Raw,
			func(v verdict) bool { return v.isUndetermined(issuerFetchable) }},
		{"nothing here holds it, the list does not name it and no address does - an inspection authority",
			aLeaf(t, private, leafOptions{}).Raw, func(v verdict) bool { return v.isRefused(report.UnknownAuthority) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if v := judged(chainOf(partialChain, c.leaf), list, testClock); !c.check(v) {
				t.Errorf("got %+v", v)
			}
		})
	}
}

// THE LIST DECIDES ONLY THE LAST STEP, AND ONLY WHILE IT IS FIT TO. Every way
// it can be unfit turns the FAIL into an undetermined with a reason - and the
// line is drawn at exactly thirty days, ADR103.
func TestAListThatCannotRuleOutARootTurnsTheFailIntoUndetermined(t *testing.T) {
	private := anAuthority(t, "an authority nobody installed")
	leaf := aLeaf(t, private, leafOptions{}).Raw
	unrelated := anAuthority(t, "unrelated").certificate

	cases := []struct {
		name  string
		list  programList
		check func(verdict) bool
	}{
		{"synchronised exactly thirty days ago",
			aListHolding(t, testClock.Add(-listFreshFor), unrelated),
			func(v verdict) bool { return v.isRefused(report.UnknownAuthority) }},
		{"synchronised thirty days and a second ago",
			aListHolding(t, testClock.Add(-listFreshFor-time.Second), unrelated),
			func(v verdict) bool { return v.isUndetermined("last brought up to date on 2026-09-14") }},
		{"with no date at all",
			aListHolding(t, time.Time{}, unrelated),
			func(v verdict) bool { return v.isUndetermined("records no date") }},
		{"dated after this machine's clock",
			aListHolding(t, testClock.Add(time.Hour), unrelated),
			func(v verdict) bool { return v.isUndetermined("later than this machine's clock") }},
		{"not readable at all",
			unavailableList("could not be read from the registry (gone)"),
			func(v verdict) bool { return v.isUndetermined("(gone)") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if v := judged(chainOf(partialChain, leaf), c.list, testClock); !c.check(v) {
				t.Errorf("got %+v", v)
			}
		})
	}
}

// THE ADDRESS IS WEIGHED EVEN WITHOUT A LIST. With nothing to consult, a
// certificate naming where its issuer lives is still undetermined for that
// reason, rather than for the list's.
func TestAnAddressIsWeighedWithoutAList(t *testing.T) {
	private := anAuthority(t, "private")
	leaf := aLeaf(t, private, leafOptions{issuerAddress: []string{"http://127.0.0.1:9/issuer.crt"}})
	if v := judged(chainOf(partialChain, leaf.Raw), unavailableList("absent"), testClock); !v.isUndetermined(issuerFetchable) {
		t.Errorf("got %+v", v)
	}
}

// E4 - A ROOT THE SERVER SENT. Answered by the root's own fingerprint.
func TestARootTheServerSentIsWeighedByItsFingerprint(t *testing.T) {
	program := anAuthority(t, "a root in the program")
	private := anAuthority(t, "a root nobody installed")
	list := aListHolding(t, testClock, program.certificate)

	sent := func(root issued) built {
		return chainOf(untrustedRoot, aLeaf(t, root, leafOptions{}).Raw, root.certificate.Raw)
	}
	if v := judged(sent(program), list, testClock); !v.isUndetermined(sentRootOnTheList) {
		t.Errorf("a root on the list the server sent was not undetermined: %+v", v)
	}
	if v := judged(sent(private), list, testClock); !v.isRefused(report.UnknownAuthority) {
		t.Errorf("a root nobody installed the server sent was not refused: %+v", v)
	}
	stale := aListHolding(t, testClock.Add(-listFreshFor-time.Hour), program.certificate)
	if v := judged(sent(private), stale, testClock); !v.isUndetermined("too long ago") {
		t.Errorf("a stale list still refused a root it cannot rule out: %+v", v)
	}
}

// BOTH AMBIGUOUS BITS AT ONCE GO TO THE MISSING ISSUER - the chain stopped
// before any root, so there is no root in hand to look up by fingerprint.
func TestAPartialChainIsWeighedAsAMissingIssuerEvenWithTheOtherBit(t *testing.T) {
	program := anAuthority(t, "a root in the program")
	list := aListHolding(t, testClock, program.certificate)
	leaf := aLeaf(t, program, leafOptions{})
	if v := judged(chainOf(partialChain|untrustedRoot, leaf.Raw), list, testClock); !v.isUndetermined(issuerOnTheList) {
		t.Errorf("got %+v", v)
	}
}

// NOTHING TO LOOK AT IS NOT A REFUSAL.
func TestAChainWithNothingToInspectIsUndetermined(t *testing.T) {
	list := aListHolding(t, testClock, anAuthority(t, "root").certificate)
	for _, status := range []uint32{partialChain, untrustedRoot} {
		if v := judged(chainOf(status), list, testClock); !v.isUndetermined(noChainBuilt) {
			t.Errorf("status 0x%08X with no certificate: %+v", status, v)
		}
	}
	if v := judged(chainOf(partialChain, []byte("garbage")), list, testClock); !v.isUndetermined("could not be parsed") {
		t.Errorf("an unreadable last certificate: %+v", v)
	}
}

// EVERY ROW JUDGE WRITES IS ONE THE CONTRACT ACCEPTS - the generator and the
// validator are in two packages and could drift apart.
func TestEveryJudgedRowSatisfiesTheContract(t *testing.T) {
	program := anAuthority(t, "program")
	private := anAuthority(t, "private")
	list := aListHolding(t, testClock, program.certificate)
	shapes := []built{
		chainOf(0, aLeaf(t, program, leafOptions{}).Raw),
		chainOf(partialChain, aLeaf(t, program, leafOptions{}).Raw),
		chainOf(partialChain, aLeaf(t, private, leafOptions{}).Raw),
		chainOf(revoked, aLeaf(t, private, leafOptions{}).Raw),
		chainOf(0x40|partialChain, aLeaf(t, private, leafOptions{}).Raw),
	}
	for i, b := range shapes {
		store := report.TrustStore{
			Runtime: report.RuntimeSystemStore, Instance: report.InstanceCurrentUser,
			StoreForm: report.StoreSystem, SelectedBy: []string{},
		}
		judge(&store, b, list, testClock)
		finding := report.Finding{Kind: report.FindingTrustStore, Summary: "a row", Source: report.SourceDetected, TrustStore: &store}
		if broken := finding.Breach(); broken != "" {
			t.Errorf("shape %d produced a row the contract refuses: %s", i, broken)
		}
	}
}
