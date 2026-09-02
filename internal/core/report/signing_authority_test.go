package report

import (
	"strings"
	"testing"
)

// The contract for the row saying who signed a chain.
//
// WHY IT IS WORTH A FILE OF ITS OWN. This is the finding whose wrong answer
// inviolable rule 21 calls harm rather than a defect, and the contract is the
// only thing standing between a hand-assembled body and a report. The guard on
// internal/core/trust/authority.go keeps the JUDGEMENT in one place. These rules
// keep the SHAPE honest wherever a body arrives from - including from a test.

func anAuthority() SigningAuthority {
	return SigningAuthority{
		Issuer:          "CN=an authority",
		LeafFingerprint: "aa:bb:cc",
		HeldBy:          HeldBySomeStores,
		TrustingStores:  []string{"curl /usr/bin/curl"},
		RefusingStores:  []string{"java jdk-25"},
		Caveat:          "TLS inspection looks like this and so does an internal authority",
	}
}

// TestAWellFormedAuthorityIsAccepted is the positive twin every case below
// needs - OBS56. Without it, a breach check that refused everything would
// satisfy the whole file.
func TestAWellFormedAuthorityIsAccepted(t *testing.T) {
	body := anAuthority()
	if broken := body.breach(""); broken != "" {
		t.Errorf("a well formed authority was refused: %s", broken)
	}
	finding := Finding{
		Kind:             FindingSigningAuthority,
		Summary:          "an authority signed this",
		Source:           SourceDetected,
		SigningAuthority: &body,
	}
	if broken := finding.Breach(); broken != "" {
		t.Errorf("the finding around it was refused: %s", broken)
	}
}

// TestTheRequiredFieldsAreRefusedWhenMissing walks them one at a time, so a
// check satisfying three of five still fails here.
func TestTheRequiredFieldsAreRefusedWhenMissing(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*SigningAuthority)
		says   string
	}{
		{
			// RFC 5280 section 4.1.2.4 forbids an empty issuer, so an empty one
			// is a broken certificate or a defect of ours - never a fact worth
			// reporting about somebody's authority.
			name:   "no issuer",
			break_: func(a *SigningAuthority) { a.Issuer = "" },
			says:   "issuer",
		},
		{
			// The evidence inviolable rule 21 requires. A claim about who signed
			// this, with nothing to check it against, is the shape that rule
			// exists to prevent.
			name:   "no fingerprint",
			break_: func(a *SigningAuthority) { a.LeafFingerprint = "" },
			says:   "fingerprint",
		},
		{
			name:   "a holding outside the registry",
			break_: func(a *SigningAuthority) { a.HeldBy = "most_stores" },
			says:   "registry",
		},
		{
			// An empty list is an answer and a nil is a statement about us -
			// the same distinction selected_by and dns_names carry.
			name:   "the trusting side unset",
			break_: func(a *SigningAuthority) { a.TrustingStores = nil },
			says:   "trusting stores",
		},
		{
			name:   "the refusing side unset",
			break_: func(a *SigningAuthority) { a.RefusingStores = nil },
			says:   "refusing stores",
		},
		{
			// The caveat is how the heuristic is named as a heuristic, and a row
			// without one states a measurement and hides what it leaves open.
			name:   "no caveat",
			break_: func(a *SigningAuthority) { a.Caveat = "" },
			says:   "caveat",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := anAuthority()
			c.break_(&body)
			broken := body.breach("")
			if broken == "" {
				t.Fatalf("a body with %s was accepted", c.name)
			}
			if !strings.Contains(broken, c.says) {
				t.Errorf("the refusal does not name what is wrong - %q does not mention %q", broken, c.says)
			}
		})
	}
}

// TestAHoldingThatDisagreesWithItsOwnListsIsRefused is the cross-check, and it
// is the half of this contract that catches an accusation assembled by hand.
//
// A holding is a SUMMARY of the two lists. One that disagrees with them is
// either a counting mistake of ours or a row somebody wrote to say something the
// stores did not - and the second is exactly what the guard on the judgement
// file exists to make difficult.
func TestAHoldingThatDisagreesWithItsOwnListsIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		holding AnchorHolding
		trust   []string
		refuse  []string
	}{
		{"all stores, and one refused", HeldByAllStores, []string{"curl a"}, []string{"java b"}},
		{"all stores, and none held it", HeldByAllStores, []string{}, []string{}},
		{"some stores, with nobody refusing", HeldBySomeStores, []string{"curl a"}, []string{}},
		{"some stores, with nobody holding", HeldBySomeStores, []string{}, []string{"java b"}},
		{"no stores, and one held it", HeldByNoStores, []string{"curl a"}, []string{"java b"}},
		{"no stores, and nobody refused either", HeldByNoStores, []string{}, []string{}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := anAuthority()
			body.HeldBy, body.TrustingStores, body.RefusingStores = c.holding, c.trust, c.refuse
			if broken := body.breach(""); broken == "" {
				t.Error("a holding disagreeing with its own lists was accepted")
			}
		})
	}

	// THE POSITIVE TWINS, one per holding. Without them every case above passes
	// on a check that refused every combination.
	agreeing := []struct {
		holding AnchorHolding
		trust   []string
		refuse  []string
	}{
		{HeldByAllStores, []string{"curl a"}, []string{}},
		{HeldBySomeStores, []string{"curl a"}, []string{"java b"}},
		{HeldByNoStores, []string{}, []string{"java b"}},
	}
	for _, c := range agreeing {
		body := anAuthority()
		body.HeldBy, body.TrustingStores, body.RefusingStores = c.holding, c.trust, c.refuse
		if broken := body.breach(""); broken != "" {
			t.Errorf("%q with lists that agree was refused: %s", c.holding, broken)
		}
	}
}

// TestEveryHoldingIsDeclaredCompletely is the registry test this file's closed
// list gets, like every other closed list here.
func TestEveryHoldingIsDeclaredCompletely(t *testing.T) {
	if len(AllAnchorHoldings) != len(anchorHoldingMeanings) {
		t.Fatalf("%d holdings are listed and %d have a meaning - one list was edited alone",
			len(AllAnchorHoldings), len(anchorHoldingMeanings))
	}
	seen := map[AnchorHolding]bool{}
	for _, holding := range AllAnchorHoldings {
		if seen[holding] {
			t.Errorf("the holding %q is listed twice", holding)
		}
		seen[holding] = true
		if !holding.Valid() {
			t.Errorf("the holding %q is listed and not in the registry", holding)
		}
		if holding.Meaning() == "" {
			t.Errorf("the holding %q has no meaning, so the schema cannot publish what it means", holding)
		}
		if holding.String() != string(holding) {
			t.Errorf("the holding %q does not spell itself the same way on the wire", holding)
		}
	}
	if AnchorHolding("nonsense").Valid() {
		t.Error("a value outside the registry was accepted, so the list is not closed")
	}
	if AnchorHolding("nonsense").Meaning() != "" {
		t.Error("a value outside the registry has a meaning")
	}
}

// TestAnAccusationWithoutANameIsRefused is inviolable rule 21 turned into the
// one thing a contract can do about it: refuse.
//
// Measured on the bench 2026-08-19 and recorded in ADR53: an intercepting
// middlebox and an honest internal authority produce IDENTICAL values in every
// field of this body. So the words below cannot be earned by any combination of
// the counts - only by a name from a list this program carries with a source
// beside every entry.
func TestAnAccusationWithoutANameIsRefused(t *testing.T) {
	for _, said := range []string{
		"CN=an authority signed this and your traffic is being intercepted",
		"CN=an authority is intercepting this connection",
		"CN=an authority signed this - somebody is running a mitm proxy",
		"CN=an authority signed this and is eavesdropping on you",
		"CN=an authority signed this, which is a man in the middle",
	} {
		body := anAuthority()
		if broken := body.breach(said); broken == "" {
			t.Errorf("accepted an accusation naming no product: %q", said)
		}
	}
}

// TestAnAccusationWithANameIsAccepted is the other direction, and without it the
// rule above would be satisfied by refusing every sentence there is.
func TestAnAccusationWithANameIsAccepted(t *testing.T) {
	body := anAuthority()
	body.Inspection = &Inspection{Product: "mitmproxy", MatchedAttribute: "CN"}
	said := "CN=an authority signed this, and that issuer names mitmproxy, so this connection is being intercepted"
	if broken := body.breach(said); broken != "" {
		t.Errorf("refused an accusation that names a product, which is the one case it is for: %s", broken)
	}
}

// TestQuotingTheISSUERIsNotMakingTheAccusation is the trap, and it is the reason
// this rule strips the issuer before it reads anything.
//
// The summary quotes the issuer because inviolable rule 21 REQUIRES the evidence
// to travel with the claim. An authority whose own name carries one of these
// words - an ordinary company called Intercept Systems - would otherwise break
// this contract, and a broken contract degrades the WHOLE layer. ADR66 kept that
// rule and wrote its price down as "a second, unknown trigger will take the layer
// again"; this would have been that trigger, installed on purpose. OBS74 is the
// same lesson, learned on the bench when CN=mitmproxy read as an accusation.
func TestQuotingTheIssuerIsNotMakingTheAccusation(t *testing.T) {
	body := anAuthority()
	body.Issuer = "CN=Intercept Systems Internal CA,O=Intercept Systems"
	said := body.Issuer + " signed this certificate, and 1 store(s) here hold it and 1 do not"
	if broken := body.breach(said); broken != "" {
		t.Errorf("an ordinary authority was refused for the letters in its own name: %s", broken)
	}
}

// TestANamedProductMustBeCompleteEnoughToCheck refuses the half-filled name.
//
// A product with no name says nothing, and a name with no attribute does not say
// where to look - and inviolable rule 21 asks for a claim of this sort to travel
// with what it rests on or not travel at all. Both are exactly the shape a
// hand-assembled body would take.
func TestANamedProductMustBeCompleteEnoughToCheck(t *testing.T) {
	cases := map[string]Inspection{
		"no product":   {Product: "", MatchedAttribute: "CN"},
		"no attribute": {Product: "mitmproxy", MatchedAttribute: ""},
	}
	for name, inspection := range cases {
		body := anAuthority()
		body.Inspection = &inspection
		if broken := body.breach("an authority signed this"); broken == "" {
			t.Errorf("accepted an inspection body with %s", name)
		}
	}
}

// TestTheAccusingWordsAreMatchedByStemAndTheProductNamesAreNot pins the one
// place two rules that look identical must differ, because getting it wrong
// fails silently in both directions.
//
// A whole-word rule would let "intercepted" through, which is every accusation
// anybody would actually write - strict looking and catching nothing. A stem
// rule applied to product names would tell a company called Fortinetworks it is
// running an appliance, which is the harm rule 21 names. Both were measured while
// this was written: the first by the guard's canary, the second by the scanner
// reporting the product list for saying "mitmproxy".
func TestTheAccusingWordsAreMatchedByStemAndTheProductNamesAreNot(t *testing.T) {
	if !ContainsWordStem("your traffic is being intercepted", "intercept") {
		t.Error("a stem match missed an inflection, so this rule would refuse nothing anybody writes")
	}
	if ContainsWord("your traffic is being intercepted", "intercept") {
		t.Error("a whole-word match accepted an inflection, so the two rules are not different")
	}
	if ContainsWord("Fortinetworks Sp. z o.o.", "Fortinet") {
		t.Error("a whole-word match named a company that merely begins the same way")
	}
	if !ContainsWord("CN=mitmproxy", "mitmproxy") {
		t.Error("a whole-word match missed the name it exists to find")
	}
	if ContainsWord("mitmproxy", "mitm") {
		t.Error("a whole-word match found a word inside a longer one")
	}
}
