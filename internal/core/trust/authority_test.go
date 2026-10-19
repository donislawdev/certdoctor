package trust

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Who signed the chain, and how widely this machine holds them.
//
// EVERY NEGATIVE TEST HERE HAS A POSITIVE TWIN ON THE SAME FIXTURE - OBS56. A
// function returning nil for everything satisfies every "no row here" assertion
// in this file and looks exactly like a careful one.

// holder is a store that read its anchors and closed the chain.
func holder(runtime, instance, path string) report.TrustStore {
	yes := true
	return report.TrustStore{
		Runtime:              runtime,
		Instance:             instance,
		StorePath:            path,
		StoreForm:            report.StoreFile,
		TrustAnchorCount:     150,
		TrustsPresentedChain: &yes,
		SelectedBy:           []string{},
	}
}

// refuser is a store that holds no signer for what arrived.
func refuser(runtime, instance, path string) report.TrustStore {
	return aRefusedStore(runtime, instance, path)
}

func aSignedLeaf() *report.Certificate {
	return &report.Certificate{
		Subject:           "CN=registry.example.net",
		Issuer:            "CN=an authority",
		FingerprintSHA256: "aa:bb:cc:dd",
	}
}

// TestTheHoldingIsCountedRatherThanConcluded walks the three answers, and the
// three together are the test: a rule that always said some_stores would pass
// any one of them alone.
func TestTheHoldingIsCountedRatherThanConcluded(t *testing.T) {
	cases := []struct {
		name   string
		stores []report.TrustStore
		want   report.AnchorHolding
	}{
		{
			name:   "every assessed store holds the signer",
			stores: []report.TrustStore{holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"), holder("git", "/usr/bin/git", "/etc/git.crt")},
			want:   report.HeldByAllStores,
		},
		{
			// THE INTERESTING ANSWER, AND STILL NOT AN ACCUSATION. Measured on
			// the bench 2026-08-19: a middlebox and an honest internal server
			// under a company's own authority both produce exactly this.
			name:   "one holds it and one does not",
			stores: []report.TrustStore{holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"), refuser("git", "/usr/bin/git", "/etc/git.crt")},
			want:   report.HeldBySomeStores,
		},
		{
			name:   "nothing here holds it",
			stores: []report.TrustStore{refuser("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"), refuser("git", "/usr/bin/git", "/etc/git.crt")},
			want:   report.HeldByNoStores,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			finding := authorityOf(aSignedLeaf(), c.stores)
			if finding == nil {
				t.Fatal("no row at all, and every case here has stores that were assessed")
			}
			if broken := finding.Breach(); broken != "" {
				t.Fatalf("the row does not satisfy its own contract: %s", broken)
			}
			if finding.SigningAuthority.HeldBy != c.want {
				t.Errorf("held by %q, want %q", finding.SigningAuthority.HeldBy, c.want)
			}
			if finding.SigningAuthority.Caveat == "" {
				t.Error("no caveat, and inviolable rule 21 asks for the heuristic to be named as one on EVERY answer")
			}
		})
	}
}

// TestNoAccusationIsMadeOnAnyHolding is the assertion the whole slice exists for,
// and it is written as a word search on purpose.
//
// P6b-K2 will add the inspection-product list, and the day it does, the word
// below becomes reachable - but only through a name from that list, never
// through the count. If this test ever has to be weakened, the thing being
// weakened is the promise in inviolable rule 21.
func TestNoAccusationIsMadeOnAnyHolding(t *testing.T) {
	sets := [][]report.TrustStore{
		{holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt")},
		{holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"), refuser("git", "/usr/bin/git", "/etc/git.crt")},
		{refuser("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt")},
	}
	// The words a reader would take as a finding of fact about their network.
	accusations := []string{"intercept", "mitm", "man in the middle", "eavesdrop", "attack"}

	for _, stores := range sets {
		finding := authorityOf(aSignedLeaf(), stores)
		if finding == nil {
			t.Fatal("no row for a set of stores that were assessed")
		}
		sentence := strings.ToLower(finding.Summary + " " + finding.SigningAuthority.Caveat)
		for _, word := range accusations {
			if !strings.Contains(sentence, word) {
				continue
			}
			// "inspection" inside the caveat's own hedge is the one legitimate
			// use, and it is legitimate BECAUSE it names both readings.
			if word == "intercept" && strings.Contains(sentence, "cannot tell those two apart") {
				continue
			}
			t.Errorf("the sentence accuses with %q on a holding that is a count: %q", word, sentence)
		}
	}
}

// TestAStoreRefusingOnDatesIsNotARefusalOfTheSIGNER is the distinction that
// keeps a disagreement from being manufactured out of a clock.
//
// A store that refused because something EXPIRED built the path first, so it
// holds the signer perfectly well. Counting it as "does not hold" would turn a
// machine where every store agrees into one that appears split - and a split is
// the answer this whole finding is shaped around.
func TestAStoreRefusingOnDatesIsNotARefusalOfTheSigner(t *testing.T) {
	expired := refuser("git", "/usr/bin/git", "/etc/git.crt")
	expired.TrustFailure = report.Expired
	stores := []report.TrustStore{holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"), expired}

	finding := authorityOf(aSignedLeaf(), stores)
	if finding == nil {
		t.Fatal("no row at all")
	}
	if got := finding.SigningAuthority.HeldBy; got != report.HeldByAllStores {
		t.Errorf("held by %q, want %q - a refusal on dates says nothing about who signed", got, report.HeldByAllStores)
	}

	// THE POSITIVE TWIN. Without it this passes on a rule that ignored every
	// refusal, whatever its reason.
	unknown := refuser("git", "/usr/bin/git", "/etc/git.crt")
	stores = []report.TrustStore{holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"), unknown}
	finding = authorityOf(aSignedLeaf(), stores)
	if got := finding.SigningAuthority.HeldBy; got != report.HeldBySomeStores {
		t.Errorf("held by %q, want %q - a refusal for want of a signer is exactly what this counts",
			got, report.HeldBySomeStores)
	}
}

// TestTwoRowsOverOneFileAreOneOpinion is the degenerate case this machine
// actually produces.
//
// Measured on the owner's machine: two curl binaries in PATH, and a runtime's
// store can be the very file another runtime already reads. Counting the same
// file twice manufactures agreement or disagreement out of an installation
// detail.
func TestTwoRowsOverOneFileAreOneOpinion(t *testing.T) {
	shared := "/etc/ssl/certs/ca-certificates.crt"
	stores := []report.TrustStore{
		refuser("curl", "/usr/bin/curl", shared),
		refuser("curl", "/usr/local/bin/curl", shared),
	}
	finding := authorityOf(aSignedLeaf(), stores)
	if finding == nil {
		t.Fatal("no row at all")
	}
	if named := finding.SigningAuthority.RefusingStores; len(named) != 1 {
		t.Errorf("one file produced %d entries: %v", len(named), named)
	}

	// THE POSITIVE TWIN: two DIFFERENT files are two opinions and must both be
	// named, or this would pass on a rule that collapsed everything to one.
	stores[1].StorePath = "/opt/curl/ca.crt"
	finding = authorityOf(aSignedLeaf(), stores)
	if named := finding.SigningAuthority.RefusingStores; len(named) != 2 {
		t.Errorf("two files produced %d entries: %v", len(named), named)
	}
}

// TestAPlatformStoreIsCountedByItsInstance covers the row with no path to be
// counted by, which is every Schannel curl on the owner's machine.
func TestAPlatformStoreIsCountedByItsInstance(t *testing.T) {
	platform := func(instance string) report.TrustStore {
		store := refuser("curl", instance, "")
		store.StoreForm = report.StoreSystem
		return store
	}
	finding := authorityOf(aSignedLeaf(), []report.TrustStore{platform("/usr/bin/curl"), platform("/usr/bin/curl")})
	if named := finding.SigningAuthority.RefusingStores; len(named) != 1 {
		t.Errorf("one platform store named twice produced %d entries: %v", len(named), named)
	}

	// THE POSITIVE TWIN, and it is what says the key is the instance rather than
	// the empty path: two different instances stay two.
	finding = authorityOf(aSignedLeaf(), []report.TrustStore{platform("/usr/bin/curl"), platform("/opt/curl")})
	if named := finding.SigningAuthority.RefusingStores; len(named) != 2 {
		t.Errorf("two platform stores produced %d entries: %v", len(named), named)
	}
}

// TestNothingAssessedProducesNoRowAtAll is inviolable rule 15 in this file.
//
// A machine where every store was unreadable has measured NOTHING about any
// signer. A row saying "no store holds it" would turn our own inability to look
// into a fact about somebody's certificate authority.
func TestNothingAssessedProducesNoRowAtAll(t *testing.T) {
	unreadable := report.TrustStore{
		Runtime:     "curl",
		Instance:    "/usr/bin/curl",
		StoreForm:   report.StoreSystem,
		NotAssessed: "this store is the platform's own and this program cannot enumerate it",
		SelectedBy:  []string{},
	}
	if finding := authorityOf(aSignedLeaf(), []report.TrustStore{unreadable}); finding != nil {
		t.Errorf("a row was produced from stores that were never assessed: %q", finding.Summary)
	}

	// THE POSITIVE TWIN. One assessed store beside the unreadable one is enough
	// to have measured something, and then the row must appear.
	stores := []report.TrustStore{unreadable, refuser("git", "/usr/bin/git", "/etc/git.crt")}
	if finding := authorityOf(aSignedLeaf(), stores); finding == nil {
		t.Error("no row although one store was assessed, and silence about a measurement is forbidden")
	}
}

// TestALeafTheContractWouldRefuseProducesNoRow keeps our own defect from being
// reported as a fact about somebody's certificate.
func TestALeafTheContractWouldRefuseProducesNoRow(t *testing.T) {
	stores := []report.TrustStore{refuser("git", "/usr/bin/git", "/etc/git.crt")}

	cases := []struct {
		name string
		leaf *report.Certificate
	}{
		{"no leaf at all", nil},
		{"no issuer", &report.Certificate{Subject: "CN=x", FingerprintSHA256: "aa"}},
		{"no fingerprint", &report.Certificate{Subject: "CN=x", Issuer: "CN=y"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if finding := authorityOf(c.leaf, stores); finding != nil {
				t.Errorf("a row was produced from a leaf with %s: %q", c.name, finding.Summary)
			}
		})
	}

	// THE POSITIVE TWIN, on the same stores: a leaf carrying both required
	// fields does produce one.
	if finding := authorityOf(aSignedLeaf(), stores); finding == nil {
		t.Error("no row for a leaf carrying an issuer and a fingerprint")
	}
}

// TestTheEvidenceTravelsWithTheClaim is inviolable rule 21 as an assertion.
func TestTheEvidenceTravelsWithTheClaim(t *testing.T) {
	finding := authorityOf(aSignedLeaf(), []report.TrustStore{
		holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"),
		refuser("git", "/usr/bin/git", "/etc/git.crt"),
	})
	if finding == nil {
		t.Fatal("no row at all")
	}
	authority := finding.SigningAuthority
	if authority.LeafFingerprint != "aa:bb:cc:dd" {
		t.Errorf("the fingerprint did not travel: %q", authority.LeafFingerprint)
	}
	if authority.Issuer != "CN=an authority" {
		t.Errorf("the issuer did not travel: %q", authority.Issuer)
	}
	if !strings.Contains(finding.Summary, "CN=an authority") {
		t.Errorf("the summary does not name who signed: %q", finding.Summary)
	}
	// Both sides are named rather than counted, so a reader knows WHICH tool
	// will fail without running each one.
	if len(authority.TrustingStores) != 1 || !strings.Contains(authority.TrustingStores[0], "curl") {
		t.Errorf("the trusting side is not named: %v", authority.TrustingStores)
	}
	if len(authority.RefusingStores) != 1 || !strings.Contains(authority.RefusingStores[0], "git") {
		t.Errorf("the refusing side is not named: %v", authority.RefusingStores)
	}
}

// TestEveryHoldingHasACaveat is the registry test for the table rule 21 lives in.
func TestEveryHoldingHasACaveat(t *testing.T) {
	if len(caveats) != len(report.AllAnchorHoldings) {
		t.Fatalf("%d holdings are declared and %d have a caveat - one list was edited alone",
			len(report.AllAnchorHoldings), len(caveats))
	}
	for _, holding := range report.AllAnchorHoldings {
		if strings.TrimSpace(caveats[holding]) == "" {
			t.Errorf("the holding %q has no caveat, so its row would state a measurement and not what it leaves open", holding)
		}
		if !holding.Valid() {
			t.Errorf("the holding %q is listed and not in the registry", holding)
		}
	}
}

// TestANamedProductPromotesTheSentenceAndReplacesTheHedge is the other half of
// TestNoAccusationIsMadeOnAnyHolding, and neither means anything alone.
//
// That test proves the program stays quiet on a count. This one proves it is not
// quiet BECAUSE IT CANNOT SPEAK - a guard that refused everything would pass the
// first test and be worthless. Both halves come from ADR53: the measurement is
// what the report states, and a name from the list is the only thing that turns
// it into a sentence about somebody's network.
func TestANamedProductPromotesTheSentenceAndReplacesTheHedge(t *testing.T) {
	leaf := &report.Certificate{
		Subject:           "CN=registry.example.net",
		Issuer:            "CN=mitmproxy,O=mitmproxy",
		FingerprintSHA256: "aa:bb:cc:dd",
	}
	stores := []report.TrustStore{
		holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"),
		refuser("git", "/usr/bin/git", "/etc/git.crt"),
	}
	finding := authorityOf(leaf, stores)
	if finding == nil {
		t.Fatal("no row for a set of stores that were assessed")
	}
	authority := finding.SigningAuthority

	if authority.Inspection == nil {
		t.Fatal("the issuer names a product on the list and nothing was named")
	}
	if authority.Inspection.Product != "mitmproxy" {
		t.Errorf("named %q rather than the product on the list", authority.Inspection.Product)
	}
	if authority.Inspection.MatchedAttribute != "CN" {
		t.Errorf("said the name came from %q, and a reader checking this needs the right place to look",
			authority.Inspection.MatchedAttribute)
	}
	// THE WHOLE CLAUSE RATHER THAN THE TWO WORDS IN IT, AND THE MUTATION REGISTER
	// IS WHY. Asked for "intercepted" and "mitmproxy" separately, this passed
	// against a sentence mangled into gibberish: the accusation survived in the
	// literal, and the product name survived because THE ISSUER OF THIS VERY
	// FIXTURE is spelled mitmproxy. Two right answers to a question that was not
	// being asked - OBS56, caught by the register rather than by reading.
	const clause = "and that issuer names mitmproxy, a TLS inspection product"
	if !strings.Contains(finding.Summary, clause) {
		t.Errorf("the promoted sentence does not name the product and say what it is: %q", finding.Summary)
	}
	if !strings.Contains(finding.Summary, "intercepted") {
		t.Errorf("named a product and would not say what it means: %q", finding.Summary)
	}

	// THE HEDGE HAD TO CHANGE RATHER THAN GROW. The caveat beside some_stores
	// says this program cannot tell an appliance from a company's own authority,
	// which stops being true the moment one is named - a report carrying both
	// sentences contradicts itself in two adjacent lines.
	if strings.Contains(authority.Caveat, "cannot tell those two apart") {
		t.Errorf("kept the hedge that says the two cannot be told apart, beside a line telling them apart: %q",
			authority.Caveat)
	}
	if !strings.Contains(authority.Caveat, "NAME") {
		t.Errorf("named a product without saying the naming rests on a name: %q", authority.Caveat)
	}

	// AND THE MEASUREMENT IS UNTOUCHED, which is what "the list is only for
	// naming" means in code. A reader who does not believe the second half still
	// has the first, and the first is what produced the rows and the commands.
	unnamed := authorityOf(aSignedLeaf(), stores)
	if authority.HeldBy != unnamed.SigningAuthority.HeldBy {
		t.Errorf("the holding changed with the name: %q against %q", authority.HeldBy,
			unnamed.SigningAuthority.HeldBy)
	}
	if len(authority.TrustingStores) != len(unnamed.SigningAuthority.TrustingStores) ||
		len(authority.RefusingStores) != len(unnamed.SigningAuthority.RefusingStores) {
		t.Error("the store lists changed with the name, and the list is only for naming")
	}
}

// TestANamedProductIsAcceptedByTheContract closes the loop the two tests above
// leave open: a sentence this layer is happy with, that the report would then
// refuse, would take the whole layer down - ADR66 kept that rule and wrote down
// its price.
func TestANamedProductIsAcceptedByTheContract(t *testing.T) {
	leaf := &report.Certificate{
		Subject:           "CN=registry.example.net",
		Issuer:            "CN=mitmproxy,O=mitmproxy",
		FingerprintSHA256: "aa:bb:cc:dd",
	}
	finding := authorityOf(leaf, []report.TrustStore{
		holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"),
		refuser("git", "/usr/bin/git", "/etc/git.crt"),
	})
	if broken := finding.Breach(); broken != "" {
		t.Errorf("the layer produced a finding its own contract refuses: %s", broken)
	}
}

// TestAnIssuerNAMEDAfterAnAccusationDoesNotBreakTheContract is the trap this
// rule would have been without care, and it is worth its own test because the
// failure would not look like this rule at all.
//
// The summary quotes the issuer, which inviolable rule 21 REQUIRES. An authority
// whose own name contains one of the accusing words would then make every
// unnamed finding break the report contract - and a broken contract degrades the
// WHOLE layer. That is the second, unknown trigger ADR66 wrote down the price of.
// OBS74 is the same lesson learned on the bench: quoting the evidence read as
// making the accusation.
func TestAnIssuerNamedAfterAnAccusationDoesNotBreakTheContract(t *testing.T) {
	leaf := &report.Certificate{
		Subject: "CN=registry.example.net",
		// Not on the list: the letters are there and no entry names it, which
		// is precisely the combination that used to be fatal.
		Issuer:            "CN=Intercept Systems Internal CA,O=Intercept Systems",
		FingerprintSHA256: "aa:bb:cc:dd",
	}
	finding := authorityOf(leaf, []report.TrustStore{
		holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"),
	})
	if finding == nil {
		t.Fatal("no row for a store that was assessed")
	}
	if finding.SigningAuthority.Inspection != nil {
		t.Error("named a product on the strength of the customer's own company name")
	}
	if broken := finding.Breach(); broken != "" {
		t.Errorf("an ordinary authority whose NAME carries the letters broke the contract, "+
			"which would degrade all of L5: %s", broken)
	}
}

// TestALeafThatSignedItselfSaysSo is ADR107, on every holding, because the word
// is added before the holding is chosen and a version that added it on one
// branch only would pass any single case.
//
// THE TWIN IS THE SAME NAMES WITHOUT THE FLAG. A certificate can name itself as
// its own issuer while carrying somebody else's signature, and L4 read the flag
// off the signature for exactly that reason - a sentence built from the names
// matching would say "itself" about a certificate that never signed itself.
func TestALeafThatSignedItselfSaysSo(t *testing.T) {
	sets := map[string][]report.TrustStore{
		"held by every store": {holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt")},
		"held by some stores": {holder("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt"), refuser("git", "/usr/bin/git", "/etc/git.crt")},
		"held by no store":    {refuser("curl", "/usr/bin/curl", "/etc/ssl/certs/ca.crt")},
	}
	for name, stores := range sets {
		t.Run(name, func(t *testing.T) {
			self := &report.Certificate{
				Subject:           "CN=*.badssl.com,O=BadSSL",
				Issuer:            "CN=*.badssl.com,O=BadSSL",
				FingerprintSHA256: "aa:bb:cc:dd",
				SelfSigned:        true,
			}
			finding := authorityOf(self, stores)
			if finding == nil {
				t.Fatal("no row for stores that were assessed")
			}
			if broken := finding.Breach(); broken != "" {
				t.Fatalf("the row does not satisfy its own contract: %s", broken)
			}
			if !strings.HasPrefix(finding.Summary, "CN=*.badssl.com,O=BadSSL signed this certificate itself") {
				t.Errorf("a self-signed leaf is named as though somebody else signed it: %q", finding.Summary)
			}

			namesOnly := *self
			namesOnly.SelfSigned = false
			twin := authorityOf(&namesOnly, stores)
			if twin == nil {
				t.Fatal("no row for the twin, so the assertion below would prove nothing")
			}
			if strings.Contains(twin.Summary, "itself") {
				t.Errorf("a leaf that only NAMES itself as issuer is said to have signed itself: %q", twin.Summary)
			}
		})
	}
}
