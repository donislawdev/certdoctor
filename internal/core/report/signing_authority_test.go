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
	if broken := body.breach(); broken != "" {
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
			broken := body.breach()
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
			if broken := body.breach(); broken == "" {
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
		if broken := body.breach(); broken != "" {
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
