package trust

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// TestEveryEntryCarriesASourceThatWasReadAtTheSource is inviolable rule 18 made
// into a red test rather than a paragraph.
//
// EVERY LINE OF THIS LIST IS A SENTENCE THIS PROGRAM WILL PRINT ABOUT SOMEBODY'S
// NETWORK, and the rule this project says it will break first and most
// expensively is exactly the one that governs it: a claim about somebody else's
// product carries a source that was read at the source, with a date. Descriptor
// has the same gate one file over, and this is the same gate on a list whose
// mistakes cost more.
func TestEveryEntryCarriesASourceThatWasReadAtTheSource(t *testing.T) {
	if len(inspectionProducts) == 0 {
		t.Fatal("the list is empty, so every test below passes while proving nothing")
	}
	for _, product := range inspectionProducts {
		switch {
		case product.Product == "":
			t.Errorf("an entry has no product name, and the name is the whole of what it contributes")
		case product.Match == "":
			t.Errorf("%s has nothing to match, so it can never fire", product.Product)
		case product.Attribute != "CN" && product.Attribute != "O":
			t.Errorf("%s matches on %q, and an entry names ONE attribute of a distinguished name - "+
				"searching all of them is how a locality or an organisational unit becomes an accusation",
				product.Product, product.Attribute)
		case !product.Source.Valid():
			t.Errorf("%s carries the source %q, which is outside the registry", product.Product, product.Source)
		case product.Source == Judgement:
			t.Errorf("%s rests on a judgement, and docs/20 is blunt that a judgement must never be quoted "+
				"as fact - this list is quoted as fact by definition", product.Product)
		case product.Evidence == "":
			t.Errorf("%s carries no evidence, so nobody can check where the name came from", product.Product)
		case !strings.Contains(product.Evidence, "202"):
			t.Errorf("%s carries evidence with no date in it, and a source without a date is a source "+
				"nobody can tell has gone stale: %q", product.Product, product.Evidence)
		}
	}
}

// TestAnEntryMatchesTheNamedAttributeAndNoOther is the difference between naming
// a product and accusing a company.
func TestAnEntryMatchesTheNamedAttributeAndNoOther(t *testing.T) {
	// The entry for mitmproxy matches on the common name. The same string in the
	// organisation must NOT fire it, or the entry's Attribute field decides
	// nothing and could be deleted without a test going red.
	if named := matchInspection("O=mitmproxy,CN=something else"); named != nil {
		t.Errorf("matched %s on an attribute the entry does not name", named.Product)
	}
	if named := matchInspection("CN=mitmproxy,O=somebody"); named == nil {
		t.Error("did not match on the attribute the entry does name")
	}
}

// TestANameThatMERELYBEGINSTheSameWayIsNotAccused is scenario S-3 defended by a
// test rather than by good intentions.
//
// An organisation called Fortinetworks running its own perfectly ordinary
// certificate authority is who inviolable rule 21 protects, and a substring
// search is how it would be told it is running an appliance.
func TestANameThatMerelyBeginsTheSameWayIsNotAccused(t *testing.T) {
	for _, issuer := range []string{
		"CN=mitmproxyish Root CA,O=Somebody",
		"CN=notmitmproxy,O=Somebody",
		"CN=Cisco Umbrellas Ltd Internal CA,O=Cisco Umbrellas Ltd",
	} {
		if named := matchInspection(issuer); named != nil {
			t.Errorf("issuer %q was named as %s, and it merely contains the letters", issuer, named.Product)
		}
	}
}

// TestTheOrdinaryIssuerIsNotNamed is the case that runs on nearly every machine
// this program will ever be pointed at.
func TestTheOrdinaryIssuerIsNotNamed(t *testing.T) {
	for _, issuer := range []string{
		"CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US",
		"CN=certdoctor testbed intermediate",
		"CN=ACME Corp Internal Issuing CA,O=ACME Corp,C=PL",
	} {
		if named := matchInspection(issuer); named != nil {
			t.Errorf("ordinary issuer %q was named as %s", issuer, named.Product)
		}
	}
}

// TestAnIssuerThisSplitterCannotReadIsNotNamed is the failure direction, and it
// is the one that matters.
//
// A distinguished name in a shape this splitter does not handle produces NO
// match. The two mistakes do not cost the same: an appliance left unnamed costs
// a sentence, and a name printed over an ordinary corporate authority is the
// harm inviolable rule 21 names. Every one of these carries the letters and none
// of them may fire.
func TestAnIssuerThisSplitterCannotReadIsNotNamed(t *testing.T) {
	for _, issuer := range []string{
		// No attribute at all.
		"mitmproxy",
		// Empty everywhere.
		"",
		"=",
		"CN=",
		// The hexadecimal form this splitter deliberately does not decode.
		"CN=#046d69746d70726f7879",
		// An attribute written as a bare object identifier: the value is there,
		// and nothing says it is a common name.
		"2.5.4.3=mitmproxy",
	} {
		if named := matchInspection(issuer); named != nil {
			t.Errorf("issuer %q was named as %s, and this splitter does not understand it", issuer, named.Product)
		}
	}
}

// TestAnEscapedCommaDoesNotSplitAnAttribute is the one piece of RFC 2253 this
// splitter has to get right, because it is the one pkix.Name.String() produces.
func TestAnEscapedCommaDoesNotSplitAnAttribute(t *testing.T) {
	attributes := splitDistinguishedName(`CN=Somebody\, Inc.,O=Elsewhere`)
	if len(attributes) != 2 {
		t.Fatalf("split into %d attribute(s) and the escaped comma is inside a value: %v",
			len(attributes), attributes)
	}
	if attributes[0].value != "Somebody, Inc." {
		t.Errorf("the escaped comma did not survive: %q", attributes[0].value)
	}
}

// TestAFragmentWithNoEqualsSignIsNotAnAttribute asks the splitter directly,
// and the reason it does is worth writing down - OBS81.
//
// The obvious place to check this is "an issuer this splitter cannot read is not
// named", and that test proves nothing about it: a fragment turned into an
// attribute gets a type equal to the fragment itself, and no fragment is ever
// called CN or O, so the check one level up refuses it anyway. A gate above a
// gate means the lower one is never reached, and a mutation aimed through it
// survives correctly while looking like a weak test.
//
// THE PROPERTY IS REAL EVEN WHERE IT IS CURRENTLY MASKED: a splitter that
// invents pairs which were not in the name is one that will start naming
// products the day an entry matches on something else.
func TestAFragmentWithNoEqualsSignIsNotAnAttribute(t *testing.T) {
	attributes := splitDistinguishedName("CN=somebody,garbage")
	if len(attributes) != 1 {
		t.Fatalf("split into %d attribute(s) and only one half of that name is a pair: %v",
			len(attributes), attributes)
	}
	if attributes[0].kind != "CN" || attributes[0].value != "somebody" {
		t.Errorf("the one real pair came back as %+v", attributes[0])
	}
}

// TestTheFirstMatchingEntryWins pins the tie-break, because "two entries cannot
// both match" is a property of today's list rather than of this function - and a
// report that answers differently on different runs is not a report.
func TestTheFirstMatchingEntryWins(t *testing.T) {
	saved := inspectionProducts
	t.Cleanup(func() { inspectionProducts = saved })
	inspectionProducts = []InspectionProduct{
		{Product: "first", Attribute: "CN", Match: "shared", Source: Measured, Evidence: "fixture 2026"},
		{Product: "second", Attribute: "CN", Match: "shared", Source: Measured, Evidence: "fixture 2026"},
	}
	named := matchInspection("CN=shared name")
	if named == nil || named.Product != "first" {
		t.Errorf("tie broken as %v, and declaration order is the only order a report may depend on", named)
	}
}

// FuzzSplittingAnIssuerNeverPanics points the fuzzer at the one function here
// that reads somebody else's bytes.
//
// docs/22 asks for a fuzz target wherever this program summarises input it did
// not produce, and the issuer of a certificate is exactly that. The property is
// the modest one worth having: it returns, and every attribute it hands back has
// both halves - because an attribute with an empty name or an empty value is one
// a match could be made against by accident.
func FuzzSplittingAnIssuerNeverPanics(f *testing.F) {
	f.Add("CN=mitmproxy,O=mitmproxy")
	f.Add(`CN=Somebody\, Inc.,O=Elsewhere,C=PL`)
	f.Add("2.5.4.3=#046d69746d")
	f.Add("=====")
	f.Add(`\`)
	f.Add("CN=a+CN=b,O=c")
	f.Fuzz(func(t *testing.T, issuer string) {
		for _, attribute := range splitDistinguishedName(issuer) {
			if attribute.kind == "" || attribute.value == "" {
				t.Errorf("handed back a half-empty attribute %+v from %q", attribute, issuer)
			}
		}
		// It must also survive being asked the real question, which is what the
		// product does with the answer.
		matchInspection(issuer)
	})
}

// TestTheProgramNamesNobodyItCannotSource is the sentence the whole slice rests
// on, checked rather than asserted in prose.
//
// A product on this list is a product whose name this program will print beside
// somebody's connection. It may only be here because a source was read - so if
// this test ever has to be relaxed, the thing being relaxed is inviolable rule
// 18 on the one list where breaking it is the harm rule 21 names.
func TestTheProgramNamesNobodyItCannotSource(t *testing.T) {
	leaf := &report.Certificate{
		Subject:           "CN=registry.example.net",
		Issuer:            "CN=Zscaler Intermediate Root CA,O=Zscaler Inc.",
		FingerprintSHA256: "aa:bb",
	}
	finding := authorityOf(leaf, []report.TrustStore{
		holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"),
		refuser("git", "/usr/bin/git", "/etc/git.crt"),
	})
	if finding == nil {
		t.Fatal("no row for a set of stores that were assessed")
	}
	if finding.SigningAuthority.Inspection != nil {
		t.Errorf("named %q, and no source for that name was ever read - researched 2026-09-01, the vendor's "+
			"help portal renders with a script and could not be read",
			finding.SigningAuthority.Inspection.Product)
	}
}
