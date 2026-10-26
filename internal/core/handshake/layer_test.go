package handshake

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// safeClock is a clock that may be read from several goroutines.
//
// It is safe BEFORE the first concurrent caller rather than after the race
// detector explains it - docs/22 section 2 ends with that warning, and this
// layer fans out from its first day.
func safeClock() func() time.Time {
	base := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	var ticks atomic.Int64
	return func() time.Time {
		return base.Add(time.Duration(ticks.Add(1)) * time.Millisecond)
	}
}

func certAt(subject, issuer, fingerprint string, selfSigned bool) Certificate {
	return Certificate{
		Subject:           subject,
		Issuer:            issuer,
		NotBefore:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		FingerprintSHA256: fingerprint,
		SelfSigned:        selfSigned,
	}
}

// completeChain is leaf plus the issuer that signs it - the ordinary case. The
// adapter says so on the leaf, from the signature.
func completeChain(fingerprint string) []Certificate {
	chain := []Certificate{
		certAt("CN=partner.test", "CN=testbed intermediate", fingerprint, false),
		certAt("CN=testbed intermediate", "CN=testbed root", "int-"+fingerprint, false),
	}
	chain[0].IssuerSent = true
	return chain
}

// leafOnly is scenario S-5: the issuer of the leaf was never sent.
func leafOnly(fingerprint string) []Certificate {
	return []Certificate{certAt("CN=partner.test", "CN=testbed intermediate", fingerprint, false)}
}

func shakeReturning(chain []Certificate) Shake {
	return func(context.Context, string, int, string) (Presented, error) {
		return Presented{
			Completed:       true,
			Version:         "TLS 1.3",
			CipherSuite:     4865,
			CipherSuiteName: "TLS_AES_128_GCM_SHA256",
			Protocol:        "h2",
			ServerName:      "partner.test",
			Chain:           chain,
			Name:            NameCovered,
		}, nil
	}
}

func workingInput(shake Shake) Input {
	return Input{
		Addresses:  func() []string { return []string{"192.0.2.10"} },
		Port:       443,
		ServerName: "partner.test",
		Shake:      shake,
		Now:        safeClock(),
		PerAddress: 2 * time.Second,
	}
}

func rowsOf(r Result) []report.TLSHandshake {
	var out []report.TLSHandshake
	for _, f := range r.Findings {
		out = append(out, *f.TLSHandshake)
	}
	return out
}

// TestAskRefusesWhenItWasGivenNoWayToTry covers every missing port, and each one
// has to name ITSELF.
//
// A missing port is our defect, and reporting it as a server that cannot hand
// shake would accuse somebody else of our own omission - inviolable rule 15.
func TestAskRefusesWhenItWasGivenNoWayToTry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(*Input)
		says   string
	}{
		{"no way to hand shake", func(in *Input) { in.Shake = nil }, "handshake"},
		{"no clock", func(in *Input) { in.Now = nil }, "clock"},
		{"no way to learn the addresses", func(in *Input) { in.Addresses = nil }, "addresses"},
		// A missing port outranks a target without TLS - ADR100 part 3. Our own
		// omission has to be visible whatever the user asked about.
		{"no way to hand shake, on a target without TLS", func(in *Input) {
			in.Shake = nil
			in.Plaintext = true
		}, "handshake"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := workingInput(shakeReturning(completeChain("aa")))
			tc.damage(&in)

			got := Ask(context.Background(), in)
			if got.Status != status.Unknown || got.Reason != status.ReasonProbeError {
				t.Errorf("a missing port came back as %s/%s, want unknown with a probe error", got.Status, got.Reason)
			}
			if !strings.Contains(got.Detail, tc.says) {
				t.Errorf("the sentence does not say which port was missing: %q", got.Detail)
			}
			if got.Findings != nil {
				t.Errorf("a layer that could not look handed back findings: %v", got.Findings)
			}
		})
	}
}

// TestANameWithNoAddressesIsNotThisLayersFailure is the boundary between three
// layers, and getting it wrong counts one fault three times.
func TestANameWithNoAddressesIsNotThisLayersFailure(t *testing.T) {
	in := workingInput(shakeReturning(completeChain("aa")))
	in.Addresses = func() []string { return nil }

	got := Ask(context.Background(), in)
	if got.Status != status.Unknown || got.Reason != status.ReasonNothingToCheck {
		t.Errorf("a name with no addresses came back as %s/%s", got.Status, got.Reason)
	}
}

// TestAMissingIssuerIsAWarningThatSaysWhoCanBuildAPath is scenario S-5 as this
// layer sees it, and B01 as ADR114 settled it.
//
// THE BYTES ARE THE SAME FOR TWO OPPOSITE SERVERS. One forgot its intermediate,
// and nothing that lacks it builds a path. The other is signed straight by a
// private root it may leave out, and every store holding that root builds one.
// So the layer warns and says who can build a path - and the verdict names the
// server only when no store here did, which the report package asks. The check
// is structural and consults no trust store at all - ADR46.
func TestAMissingIssuerIsAWarningThatSaysWhoCanBuildAPath(t *testing.T) {
	got := Ask(context.Background(), workingInput(shakeReturning(leafOnly("aa"))))

	if got.Status != status.Warn {
		t.Errorf("a chain without the leaf's issuer left the layer at %s", got.Status)
	}
	if !strings.Contains(got.Detail, "only a client that already holds it can build a path") {
		t.Errorf("the sentence does not say who can still build a path: %q", got.Detail)
	}
	if strings.Contains(strings.ToLower(got.Detail), "trust") {
		t.Errorf("the sentence talks about trust, which is L5's question: %q", got.Detail)
	}
	rows := rowsOf(got)
	if len(rows) != 1 || rows[0].ChainComplete {
		t.Errorf("a leaf with no issuer sent alongside it was reported as a complete chain")
	}
	if broken := got.Findings[0].Breach(); broken != "" {
		t.Errorf("the row is refused by its own contract: %s", broken)
	}
}

// TestAnIssuerMatchedByNameAloneIsNotSent pins that the layer reads the
// adapter's answer and compares no names - ADR114. The certificate after the
// leaf carries the issuer's name, and the adapter found its key did not sign
// the leaf: an issuer re-issued with a new key, sent in its old form.
func TestAnIssuerMatchedByNameAloneIsNotSent(t *testing.T) {
	chain := completeChain("aa")
	chain[0].IssuerSent = false
	got := Ask(context.Background(), workingInput(shakeReturning(chain)))

	if got.Status != status.Warn || !strings.Contains(got.Detail, "did not send the issuer") {
		t.Errorf("a name without the key was taken for the issuer: %s %q", got.Status, got.Detail)
	}
	if rows := rowsOf(got); len(rows) != 1 || rows[0].ChainComplete {
		t.Errorf("the row calls a chain complete whose issuer did not arrive: %+v", rows)
	}
}

// TestACompleteChainPasses is the other side of the same rule, and without it
// the check above would be satisfied by a layer that calls everything broken.
func TestACompleteChainPasses(t *testing.T) {
	got := Ask(context.Background(), workingInput(shakeReturning(completeChain("aa"))))

	if got.Status != status.Pass {
		t.Errorf("a chain carrying its own issuer left the layer at %s: %s", got.Status, got.Detail)
	}
	rows := rowsOf(got)
	if len(rows) != 1 || !rows[0].ChainComplete {
		t.Fatalf("a complete chain was not reported as complete: %+v", rows)
	}
	if rows[0].CipherSuite != 4865 {
		t.Errorf("the cipher suite number did not survive: %d", rows[0].CipherSuite)
	}
	if rows[0].MatchesFirstAddress != nil {
		t.Errorf("the row carrying the chain also carries a comparison against itself")
	}
}

// TestASelfSignedLeafChainsToItself pins the branch that would otherwise report
// every self-signed certificate as a broken chain.
//
// Whether anybody TRUSTS a self-signed certificate is L5's question. Whether it
// can be chained at all is this one, and it can: it is its own issuer.
func TestASelfSignedLeafChainsToItself(t *testing.T) {
	chain := []Certificate{certAt("CN=self", "CN=self", "aa", true)}
	got := Ask(context.Background(), workingInput(shakeReturning(chain)))

	if got.Status != status.Pass {
		t.Errorf("a self-signed leaf left the layer at %s, and chaining is not trusting", got.Status)
	}
}

// TestTheLeafHandedToL5SaysWhetherItSignedItself is the seam ADR107 reads. L5
// says "signed this certificate itself" off this flag, and it was read from the
// signature on the adapter side - so it has to cross, rather than be rebuilt
// from two names matching on the far side.
//
// BOTH DIRECTIONS ON ONE PATH: a mapping that dropped the flag and one that set
// it everywhere would each pass one half.
func TestTheLeafHandedToL5SaysWhetherItSignedItself(t *testing.T) {
	self := Ask(context.Background(), workingInput(shakeReturning([]Certificate{certAt("CN=self", "CN=self", "aa", true)})))
	if self.Leaf == nil || !self.Leaf.SelfSigned {
		t.Errorf("a self-signed leaf crossed to L5 without saying so: %+v", self.Leaf)
	}

	issued := Ask(context.Background(), workingInput(shakeReturning(completeChain("bb"))))
	if issued.Leaf == nil || issued.Leaf.SelfSigned {
		t.Errorf("a leaf with an issuer of its own crossed to L5 as self-signed: %+v", issued.Leaf)
	}
}

// TestEveryAddressGetsARowAndOnlyOneCarriesTheChain is ADR45.
//
// MEASURED BEFORE IT WAS DECIDED: every address of example.com and of
// cloudflare.com presented a byte-identical leaf, so agreement is the norm and
// four copies of one chain would be four times the page for none of the
// information.
func TestEveryAddressGetsARowAndOnlyOneCarriesTheChain(t *testing.T) {
	in := workingInput(shakeReturning(completeChain("aa")))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11", "2001:db8::10"} }

	got := Ask(context.Background(), in)
	rows := rowsOf(got)

	if len(rows) != 3 {
		t.Fatalf("three addresses produced %d rows", len(rows))
	}
	withChain := 0
	for i, row := range rows {
		if len(row.Chain) > 0 {
			withChain++
		}
		if row.LeafFingerprintSHA256 == "" {
			t.Errorf("row %d carries no leaf fingerprint, and that is what the comparison is made of", i)
		}
		if broken := got.Findings[i].Breach(); broken != "" {
			t.Errorf("row %d is refused by its own contract: %s", i, broken)
		}
	}
	if withChain != 1 {
		t.Errorf("%d rows carry the full chain, and ADR45 says exactly one does", withChain)
	}
	for i, row := range rows[1:] {
		if row.MatchesFirstAddress == nil || !*row.MatchesFirstAddress {
			t.Errorf("row %d presented the same certificate and does not say so", i+1)
		}
	}
}

// TestAnAddressPresentingADifferentCertificateSaysSo is the reason the
// comparison exists at all.
//
// IT IS THE ONLY SIGNAL THIS PROGRAM HAS for a middlebox sitting on one path and
// not another. The measurement behind ADR45 says agreement is the norm on a
// healthy network - and says nothing about the case this tool exists for, which
// is precisely why the disagreement has to be visible rather than folded away.
func TestAnAddressPresentingADifferentCertificateSaysSo(t *testing.T) {
	var seen atomic.Int64
	in := workingInput(func(context.Context, string, int, string) (Presented, error) {
		if seen.Add(1) == 1 {
			return Presented{Completed: true, Version: "TLS 1.3", Chain: completeChain("aa"), Name: NameCovered}, nil
		}
		return Presented{Completed: true, Version: "TLS 1.3", Chain: completeChain("bb"), Name: NameCovered}, nil
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	got := Ask(context.Background(), in)
	rows := rowsOf(got)

	if len(rows) != 2 {
		t.Fatalf("two addresses produced %d rows", len(rows))
	}
	if rows[1].MatchesFirstAddress == nil || *rows[1].MatchesFirstAddress {
		t.Errorf("an address presenting a different certificate was reported as presenting the same one")
	}
	if !strings.Contains(got.Detail, "not all present the same") {
		t.Errorf("the sentence does not mention that the addresses disagreed: %q", got.Detail)
	}
	if !strings.Contains(rows[1].Address, "192.0.2.11") {
		t.Errorf("the disagreeing row does not name its address")
	}
}

// TestTheRowShownAndTheChainJudgedComeFromOneAddress is the invariant
// firstShown's comment has always promised and the grader used to break.
//
// A HANDSHAKE CAN COMPLETE AND PRESENT NOTHING. Session resumption in TLS 1.3
// and the anonymous suites do exactly that, and until 2026-08-26 such an
// outcome was picked as the row the report describes - it completed, which was
// the grader's whole test - while presentedOf and presentedLeafOf walked past
// it to the next address, because THEIR rule also asks whether anything was
// presented. The page would then have shown one address's row beside another
// address's certificate, which is a mismatch nobody could see and everybody
// would believe. Both now consume carrierIndex.
//
// THE FIXTURE KEYS ON THE ADDRESS RATHER THAN ON A COUNTER, deliberately: the
// attempts run side by side, so a counter would decide which address presented
// what by whichever goroutine got there first.
func TestTheRowShownAndTheChainJudgedComeFromOneAddress(t *testing.T) {
	const silent, presenting = "192.0.2.10", "192.0.2.11"
	in := workingInput(func(_ context.Context, address string, _ int, _ string) (Presented, error) {
		if address == silent {
			return Presented{Completed: true, Version: "TLS 1.3"}, nil
		}
		return Presented{Completed: true, Version: "TLS 1.3", Chain: completeChain("bb"), Name: NameCovered}, nil
	})
	in.Addresses = func() []string { return []string{silent, presenting} }

	got := Ask(context.Background(), in)
	rows := rowsOf(got)
	if len(rows) != 2 {
		t.Fatalf("two addresses produced %d rows", len(rows))
	}
	if len(rows[0].Chain) != 0 {
		t.Errorf("the address that presented nothing was made to carry the chain")
	}
	if len(rows[1].Chain) == 0 {
		t.Fatalf("the address that presented a chain does not carry it in the report")
	}
	if got.Leaf == nil {
		t.Fatal("nothing crossed the seam to L5, so no store could judge anything")
	}
	if got.Leaf.FingerprintSHA256 != rows[1].Chain[0].FingerprintSHA256 {
		t.Errorf("L5 is judging %q while the report shows %q - two addresses, one page",
			got.Leaf.FingerprintSHA256, rows[1].Chain[0].FingerprintSHA256)
	}
}

// TestNoHandshakeAtAllIsAFailureAndCarriesNoNegotiatedFields is the half of the
// contract easiest to break while making the other half work.
func TestNoHandshakeAtAllIsAFailureAndCarriesNoNegotiatedFields(t *testing.T) {
	// THE STATUS IS PER CASE AND ADR58 IS WHY. Four of these are a server, or the
	// network in front of it, answering or failing to. The fifth is OUR OWN
	// allowed set refusing, so no handshake was ever attempted - and FAIL there
	// says every server refused, about servers nothing spoke to.
	for _, tc := range []struct {
		err        error
		wantStatus status.Status
	}{
		{ErrRejected, status.Fail},
		{ErrTimeout, status.Fail},
		{ErrNotReached, status.Fail},
		{ErrRefusedByRule, status.Unknown},
		{errors.New("nobody wrote a case for this"), status.Fail},
	} {
		err := tc.err
		in := workingInput(func(context.Context, string, int, string) (Presented, error) {
			return Presented{}, err
		})
		got := Ask(context.Background(), in)

		if got.Status != tc.wantStatus {
			t.Errorf("%v left the layer at %s, want %s", err, got.Status, tc.wantStatus)
		}
		rows := rowsOf(got)
		if len(rows) != 1 {
			t.Fatalf("%v produced %d rows", err, len(rows))
		}
		if rows[0].Completed {
			t.Errorf("%v was reported as a completed handshake", err)
		}
		if rows[0].NotCompleted == "" {
			t.Errorf("%v produced a row that does not say why nothing happened", err)
		}
		if rows[0].Version != "" || rows[0].CipherSuite != 0 || len(rows[0].Chain) != 0 {
			t.Errorf("%v reported what was negotiated on a handshake that did not happen", err)
		}
		if broken := got.Findings[0].Breach(); broken != "" {
			t.Errorf("%v produced a row its own contract refuses: %s", err, broken)
		}
	}
}

// TestNothingEstablishedIsToldApartFromNothingConnected is ADR20 applied to the
// second seam - the same rule, and the same pair, as the connecting layer's.
//
// The sentence this replaced said the NAME had resolved to no address, which
// this layer cannot know and which was measurably untrue: a run where L3 was
// discarded had a name that resolved to four.
func TestNothingEstablishedIsToldApartFromNothingConnected(t *testing.T) {
	in := workingInput(shakeReturning(completeChain("aa")))

	in.Addresses = func() []string { return nil }
	got := Ask(context.Background(), in)
	if got.Status != status.Unknown || got.Reason != status.ReasonNothingToCheck {
		t.Errorf("a layer handed nothing answered %s/%s", got.Status, got.Reason)
	}
	if !strings.Contains(got.Detail, "nothing was established") {
		t.Errorf("a nil list is described as %q, and nothing was established rather than measured", got.Detail)
	}

	in.Addresses = func() []string { return []string{} }
	got = Ask(context.Background(), in)
	if !strings.Contains(got.Detail, "no address accepted a connection") {
		t.Errorf("an empty list is described as %q, and that IS a measurement about the addresses", got.Detail)
	}
}

// TestAVerdictAgainstTheseServersNeedsAWalkThatFinishedTrying is ADR58 and its
// twin, in the layer where the false accusation would be loudest.
//
// "None of the addresses completed a TLS handshake" is a sentence about
// somebody's servers. Said after a layer that never spoke to any of them - its
// own budget spent, or its own allowed set refusing - it is a sentence about our
// arithmetic wearing their name. The twin underneath keeps the real failure
// intact: every address spoken to, every one rejecting, verdict unchanged.
func TestAVerdictAgainstTheseServersNeedsAWalkThatFinishedTrying(t *testing.T) {
	unfinished := workingInput(shakeReturning(completeChain("aa")))
	unfinished.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }
	expired, cancel := context.WithDeadline(context.Background(), unfinished.Now().Add(-time.Second))
	defer cancel()

	got := Ask(expired, unfinished)
	if got.Status != status.Unknown {
		t.Errorf("a layer that spoke to nobody answered %s, and it has measured nothing to answer about", got.Status)
	}
	if got.Reason != status.ReasonSkippedBudget {
		t.Errorf("the reason is %q, want %q", got.Reason, status.ReasonSkippedBudget)
	}
	if !strings.Contains(got.Detail, "did not finish trying") {
		t.Errorf("the sentence does not say the layer gave up early: %q", got.Detail)
	}

	// The twin: every address spoken to, every one rejecting the handshake.
	finished := workingInput(func(context.Context, string, int, string) (Presented, error) {
		return Presented{}, ErrRejected
	})
	finished.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }
	if got := Ask(context.Background(), finished); got.Status != status.Fail {
		t.Errorf("a layer that tried every address and completed none answered %s, want %s", got.Status, status.Fail)
	}
}

// TestTheSentenceForAnUnfinishedWalkNamesEveryCount is inviolable rule 1 on the
// one line anybody reads - the same rule, and the same three shapes, as the
// connecting layer's sentence.
func TestTheSentenceForAnUnfinishedWalkNamesEveryCount(t *testing.T) {
	budgetOnly := notFinishedDetail(3, 0, 3)
	if !strings.Contains(budgetOnly, "3 of 3") || !strings.Contains(budgetOnly, "time budget") {
		t.Errorf("the budget-only sentence does not say how many were dropped or why: %q", budgetOnly)
	}
	if strings.Contains(budgetOnly, "refused") {
		t.Errorf("the budget-only sentence mentions a refusal that did not happen: %q", budgetOnly)
	}

	ruleOnly := notFinishedDetail(0, 2, 3)
	if !strings.Contains(ruleOnly, "2 of 3") || !strings.Contains(ruleOnly, "own rule") {
		t.Errorf("the rule-only sentence does not say how many were refused or by what: %q", ruleOnly)
	}

	both := notFinishedDetail(1, 2, 3)
	for _, want := range []string{"1 of 3", "2 more", "time budget", "own rule"} {
		if !strings.Contains(both, want) {
			t.Errorf("the sentence for a walk stopped both ways does not mention %q: %q", want, both)
		}
	}
}

// TestAnAddressWithNoBudgetLeftIsNotBlamedOnTheServer keeps our own arithmetic
// from reading as somebody else's silence.
func TestAnAddressWithNoBudgetLeftIsNotBlamedOnTheServer(t *testing.T) {
	in := workingInput(shakeReturning(completeChain("aa")))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	expired, cancel := context.WithDeadline(context.Background(), in.Now().Add(-time.Second))
	defer cancel()

	got := Ask(expired, in)
	for i, row := range rowsOf(got) {
		if row.Completed {
			t.Errorf("row %d completed a handshake with no budget left", i)
		}
		if !strings.Contains(row.NotCompleted, "budget") {
			t.Errorf("row %d blames something other than our own budget: %q", i, row.NotCompleted)
		}
	}
}

// TestSwitchingEveryBudgetOffMeansNoLimitRatherThanNoAttempt is OBS62, which was
// measured in L1 and L3 and would arrive here the same way.
func TestSwitchingEveryBudgetOffMeansNoLimitRatherThanNoAttempt(t *testing.T) {
	var asked, deadlines atomic.Int64
	in := workingInput(func(ctx context.Context, _ string, _ int, _ string) (Presented, error) {
		asked.Add(1)
		if _, set := ctx.Deadline(); set {
			deadlines.Add(1)
		}
		return Presented{Completed: true, Version: "TLS 1.3", Chain: completeChain("aa"), Name: NameCovered}, nil
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }
	in.PerAddress = 0

	Ask(context.Background(), in)

	if asked.Load() != 2 {
		t.Errorf("two addresses produced %d attempt(s) when the caller asked for no limits", asked.Load())
	}
	if deadlines.Load() != 0 {
		t.Errorf("%d attempt(s) got a deadline of their own when nothing caps them", deadlines.Load())
	}
}

// TestTheServerNameTravelsSeparatelyFromTheAddress is what makes this layer work
// against a virtual host at all.
//
// SNI decides which certificate the server picks. Sending the address as the
// name asks for a certificate nobody issued, and the failure looks exactly like
// a misconfigured server.
func TestTheServerNameTravelsSeparatelyFromTheAddress(t *testing.T) {
	var mu sync.Mutex
	var names, addresses []string
	in := workingInput(func(_ context.Context, address string, _ int, serverName string) (Presented, error) {
		mu.Lock()
		names = append(names, serverName)
		addresses = append(addresses, address)
		mu.Unlock()
		return Presented{Completed: true, Version: "TLS 1.3", Chain: completeChain("aa"), Name: NameCovered}, nil
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	Ask(context.Background(), in)

	for i, name := range names {
		if name != "partner.test" {
			t.Errorf("attempt %d sent %q as the server name, and the target names partner.test", i, name)
		}
		if name == addresses[i] {
			t.Errorf("attempt %d sent the address as the server name", i)
		}
	}
}

// TestAnEmptyChainIsNotComplete pins the branch a loop finding no
// counter-example would otherwise sail through.
func TestAnEmptyChainIsNotComplete(t *testing.T) {
	if chainComplete(nil) {
		t.Error("a server that presented nothing was reported as having sent a complete chain")
	}
}

// TestTheLeafHandedOnIsTheLeafOfTheChainShown is the fourth seam to L5, and the
// property worth pinning is that it describes the SAME address as the chain.
//
// Two different rules for "which address does the report describe" would let the
// fingerprint of one address travel beside the chain of another - a mismatch
// nobody could see on the page and everybody would believe. So the leaf is taken
// from the same walk, in the same order, as the bytes.
func TestTheLeafHandedOnIsTheLeafOfTheChainShown(t *testing.T) {
	result := Ask(context.Background(), workingInput(shakeReturning(completeChain("aa"))))

	if result.Leaf == nil {
		t.Fatal("a completed handshake handed on no leaf, so L5 could not name who signed anything")
	}
	if result.Leaf.FingerprintSHA256 != "aa" {
		t.Errorf("the leaf handed on is %q and the chain shown starts with \"aa\"", result.Leaf.FingerprintSHA256)
	}
	if result.Leaf.Issuer != "CN=testbed intermediate" {
		t.Errorf("the issuer did not travel: %q", result.Leaf.Issuer)
	}
	// The rows the report prints are built from the same walk, so the leaf here
	// and the first certificate there are one certificate rather than two.
	rows := rowsOf(result)
	if len(rows) == 0 || len(rows[0].Chain) == 0 {
		t.Fatal("no chain reached the report at all")
	}
	if rows[0].Chain[0].FingerprintSHA256 != result.Leaf.FingerprintSHA256 {
		t.Errorf("the leaf handed to L5 (%q) is not the leaf the report shows (%q)",
			result.Leaf.FingerprintSHA256, rows[0].Chain[0].FingerprintSHA256)
	}
}

// TestNoHandshakeHandsOnNoLeaf is the other half, and it is what stops L5
// naming a signer for a connection that never happened.
func TestNoHandshakeHandsOnNoLeaf(t *testing.T) {
	in := workingInput(func(context.Context, string, int, string) (Presented, error) {
		return Presented{}, ErrRejected
	})
	result := Ask(context.Background(), in)
	if result.Leaf != nil {
		t.Errorf("a run where no handshake completed handed on a leaf: %+v", *result.Leaf)
	}
	if len(result.Presented) != 0 {
		t.Error("no handshake completed and a chain was handed on anyway")
	}
}

// TestAnAttemptFallingOverIsThisLayersDefectRatherThanTheProcessDying is R-1 at
// L4, where the code that is not ours is crypto/tls handling a stranger's
// certificate.
func TestAnAttemptFallingOverIsThisLayersDefectRatherThanTheProcessDying(t *testing.T) {
	in := workingInput(func(context.Context, string, int, string) (Presented, error) {
		panic("the handshake fell over")
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	got := Ask(context.Background(), in)
	if got.Status != status.Unknown {
		t.Errorf("an attempt fell over inside this program and the layer said %s", got.Status)
	}
	if got.Reason != status.ReasonProbeError {
		t.Errorf("the reason is %q, and probe_error is what means the probe fell over", got.Reason)
	}
	if len(got.Findings) != 0 {
		t.Errorf("the layer kept %d row(s) from the call that fell over", len(got.Findings))
	}

	// THE TWIN. A server rejecting the handshake is a fact about the server.
	ordinary := Ask(context.Background(), workingInput(func(context.Context, string, int, string) (Presented, error) {
		return Presented{}, ErrRejected
	}))
	if ordinary.Reason == status.ReasonProbeError {
		t.Errorf("an ordinary rejection came out as this program falling over: %q", ordinary.Detail)
	}
}

// TestAHandshakeThatPresentedNothingIsAnOrdinaryRow is OBS78 end to end - ADR66.
//
// TLS 1.3 session resumption and the anonymous suites complete a handshake and
// present no certificate. The report contract used to refuse such a row for
// carrying no leaf fingerprint, and a refused finding discards the WHOLE layer -
// so a legal server produced "the layer broke its own contract", about us.
//
// NOT MEASURED AGAINST A REAL SERVER, and that is said out loud: the fixture
// shows what the contract does with such a row, not that somebody sent one.
func TestAHandshakeThatPresentedNothingIsAnOrdinaryRow(t *testing.T) {
	in := workingInput(func(context.Context, string, int, string) (Presented, error) {
		return Presented{Completed: true, Version: "TLS 1.3", CipherSuite: 4865}, nil
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	got := Ask(context.Background(), in)
	rows := rowsOf(got)
	if len(rows) != 2 {
		t.Fatalf("%d row(s) for two addresses", len(rows))
	}
	for i, row := range rows {
		if !row.Completed {
			t.Errorf("row %d says the handshake did not complete", i)
		}
		if row.LeafFingerprintSHA256 != "" || len(row.Chain) != 0 || row.ChainComplete {
			t.Errorf("row %d describes a certificate nobody presented: %+v", i, row)
		}
		// AND THE LATER ADDRESS DOES NOT COMPARE WHAT WAS NEVER PRESENTED. "The
		// same certificate as the first address" about two rows holding none is a
		// measurement of two things neither of which happened.
		if row.MatchesFirstAddress != nil {
			t.Errorf("row %d compares a certificate against the first address and has none", i)
		}
	}
	// AND THE ROWS SURVIVE THE CONTRACT, which is the whole point: a refused
	// finding takes every other row of this layer with it.
	for _, finding := range got.Findings {
		if breach := finding.Breach(); breach != "" {
			t.Errorf("a legal row was refused by the contract: %s", breach)
		}
	}

	// THE SENTENCE HAS TO SAY THE SAME THING AS THE BODY, and until 2026-09-04 it
	// did not. MatchesFirstAddress was left nil above, correctly; the summary was
	// built from the same comparison anyway, and with no carrier at all
	// leafOf(nil) == leafOf(nil) made it "presented the same certificate as the
	// first address" - about a certificate that does not exist and an address
	// that was never chosen. The body is what a machine reads and the summary is
	// what a person reads, and the person was the one being told the untruth.
	for i, finding := range got.Findings {
		for _, forbidden := range []string{"the same certificate", "a DIFFERENT certificate"} {
			if strings.Contains(finding.Summary, forbidden) {
				t.Errorf("row %d compares a certificate nobody presented: %q", i, finding.Summary)
			}
		}
		if !strings.Contains(finding.Summary, "no certificate") {
			t.Errorf("row %d does not say what actually happened: %q", i, finding.Summary)
		}
	}

	// AND THE LAYER'S OWN SENTENCE, which carried the same untruth one level up:
	// chainComplete of an empty chain is false, so the verdict fell into the
	// branch about a server that "did not send the issuer of the first one" -
	// there being no first one. The STATUS is deliberately left alone: a server
	// that authenticates itself with nothing is a failure for a tool asked why a
	// connection does not work, and changing that is a different decision.
	if got.Status != status.Fail {
		t.Errorf("got %s, want FAIL - nothing here authenticated the server", got.Status)
	}
	if strings.Contains(got.Detail, "issuer of the first one") {
		t.Errorf("the layer sentence describes a certificate nobody presented: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "no certificate") {
		t.Errorf("the layer sentence does not say what actually happened: %q", got.Detail)
	}
}

// TestATargetWithoutTLSIsNeitherHandShakenWithNorFailed is OBS149, closed by
// ADR100.
//
// Measured on the bench 2026-09-22: http://auth.proxy.test/ came back as L4
// FAIL, "none of the 1 address(es) completed a TLS handshake", and ADR99 put
// that sentence at the top of the report as the cause of a failure that did not
// exist. There was nothing to complete.
//
// THE COUNTER IS THE HALF NO STATUS CAN SHOW. A layer answering UNKNOWN after
// sending a ClientHello to a plain HTTP port would satisfy every assertion about
// the result, so the same input is first run WITH TLS - which proves the counter
// can see a handshake at all - and only then without.
func TestATargetWithoutTLSIsNeitherHandShakenWithNorFailed(t *testing.T) {
	var shakes atomic.Int64
	var asked atomic.Bool
	in := workingInput(func(context.Context, string, int, string) (Presented, error) {
		shakes.Add(1)
		return Presented{}, ErrRejected
	})
	in.Addresses = func() []string {
		asked.Store(true)
		return []string{"192.0.2.10"}
	}

	if control := Ask(context.Background(), in); control.Status != status.Fail || shakes.Load() == 0 {
		t.Fatalf("the control run with TLS came back %s after %d handshake(s), so the counter proves nothing",
			control.Status, shakes.Load())
	}
	shakes.Store(0)
	asked.Store(false)

	in.Plaintext = true
	got := Ask(context.Background(), in)
	if got.Status != status.Unknown || got.Reason != status.ReasonNothingToCheck {
		t.Errorf("a target without TLS came back as %s/%s, want UNKNOWN/nothing_to_check", got.Status, got.Reason)
	}
	if got.Detail != plaintextTarget {
		t.Errorf("the sentence is %q, and it has to name the scheme and what to type instead", got.Detail)
	}
	if n := shakes.Load(); n != 0 {
		t.Errorf("%d handshake(s) went to a target the user named as http://", n)
	}
	// ASKED BEFORE THE ADDRESSES, so the answer cannot depend on whether L3
	// reached anything - which is what lets the bench declare it.
	if asked.Load() {
		t.Error("the addresses were asked for, so this answer depends on what L3 reached")
	}
	if got.Findings != nil || len(got.Presented) != 0 || got.Leaf != nil {
		t.Errorf("a layer that did not look handed on findings %v, a chain of %d or a leaf %v",
			got.Findings, len(got.Presented), got.Leaf)
	}
}
