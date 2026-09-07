package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// answeringProxy is a port that hands back one answer for every endpoint and
// records what it was asked. The record is the half most of these tests turn on:
// the costly faults here are asking something that should not have been asked,
// and asking it in the wrong shape.
func answeringProxy(asked *[]ChallengeRequest, answer ChallengeAnswer) ChallengeAsk {
	return func(_ context.Context, request ChallengeRequest) ChallengeAnswer {
		if asked != nil {
			*asked = append(*asked, request)
		}
		return answer
	}
}

// demanding is a proxy that wants credentials and says how to supply them.
func demanding() ChallengeAnswer {
	return ChallengeAnswer{
		Asked:   true,
		Status:  407,
		Schemes: []report.ProxyAuthScheme{{Scheme: "Basic", Realm: "corporate"}},
	}
}

// challengeRowsOf returns every challenge row, in the order the layer produced
// them.
func challengeRowsOf(result Result) []report.ProxyChallenge {
	var rows []report.ProxyChallenge
	for _, finding := range result.Findings {
		if finding.ProxyChallenge != nil {
			rows = append(rows, *finding.ProxyChallenge)
		}
	}
	return rows
}

func oneChallengeRow(t *testing.T, result Result) report.ProxyChallenge {
	t.Helper()
	rows := challengeRowsOf(result)
	if len(rows) != 1 {
		t.Fatalf("wanted exactly one challenge row, got %d among %d finding(s)", len(rows), len(result.Findings))
	}
	return rows[0]
}

// askWithProxy walks all three steps with a challenge port attached.
func askWithProxy(t *testing.T, in Input, ask ChallengeAsk) Result {
	t.Helper()
	in.Challenge = ask
	ctx := context.Background()
	return Challenge(ctx, in, Ask(ctx, in, Read(ctx, in)))
}

// TestOnlyA407SaysAProxyWantsCredentials is the measurement probe S15 came back
// with and the reason this row exists at all. Everything else a proxy can answer
// looks the same from the client's side and means something different: the bench
// answered 403 to a CONNECT on a non-SSL port from a proxy wanting no
// credentials whatever, and 503 to a CONNECT it had ALLOWED but could not
// complete. A layer that read any of those as a demand would accuse a working
// proxy and a working machine.
func TestOnlyA407SaysAProxyWantsCredentials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   status.Reason
	}{
		{"a demand", 407, status.ReasonCredentialsRequired},
		{"a refusal that is not about credentials", 403, ""},
		{"a tunnel allowed and not completed", 503, ""},
		{"a request that went through", 200, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Input{Lenses: lensesOf(namingLens(StackEnvironment, "p.example:8080")), Target: target}
			result := askWithProxy(t, in, answeringProxy(nil, ChallengeAnswer{Asked: true, Status: tc.status}))

			if tc.want == "" {
				if result.Reason == status.ReasonCredentialsRequired {
					t.Errorf("a %d was read as a demand for credentials", tc.status)
				}
				return
			}
			if result.Status != status.Unknown || result.Reason != tc.want {
				t.Errorf("a %d answered %s / %s, want unknown / %s", tc.status, result.Status, result.Reason, tc.want)
			}
		})
	}
}

// TestADemandIsUnknownAndNeverFail is inviolable rule 15 read carefully, and the
// word was fixed by testbed/expected/proxy-auth.txt before this code existed. A
// proxy asking who you are is not a broken proxy and not a broken machine, and
// this program cannot see a keyring or a domain login, so it must not pronounce
// on the outcome.
func TestADemandIsUnknownAndNeverFail(t *testing.T) {
	in := Input{Lenses: lensesOf(namingLens(StackEnvironment, "p.example:8080")), Target: target}
	result := askWithProxy(t, in, answeringProxy(nil, demanding()))

	if result.Status != status.Unknown {
		t.Errorf("a proxy that demanded credentials answered %s, want unknown", result.Status)
	}
	// The words the bench forbids in this scenario, because a run that stops at
	// a 407 looks from further down the pipeline like a trust problem.
	for _, forbidden := range []string{"trust store", "certificate"} {
		if strings.Contains(result.Detail, forbidden) {
			t.Errorf("the verdict says %q about a run that stopped at a proxy: %q", forbidden, result.Detail)
		}
	}
	if strings.Contains(result.Detail, "p.example") {
		t.Errorf("the verdict names the proxy, which no masking rule can see in a summary: %q", result.Detail)
	}
}

// TestADemandAgainstAConfiguredCredentialSaysSo is the field that stops this row
// accusing a machine that is fine. ADR89 cuts a credential out of a proxy
// address where it is READ, so a machine whose password works still meets a 407
// here - and a verdict stopping at the demand would tell somebody their machine
// is missing something it has.
func TestADemandAgainstAConfiguredCredentialSaysSo(t *testing.T) {
	lens := Lens{
		Stack: StackEnvironment, Source: "test", Read: true,
		Servers: []Server{{Address: "p.example:8080", CarriedCredentials: true}},
	}
	result := askWithProxy(t, Input{Lenses: lensesOf(lens), Target: target}, answeringProxy(nil, demanding()))

	if !strings.Contains(result.Detail, "cut off where it read it") {
		t.Errorf("the verdict does not say the credential was ours to send and was not sent: %q", result.Detail)
	}
	row := oneChallengeRow(t, result)
	if !row.CarriedCredentials {
		t.Error("the row does not record that the configuration carried a credential")
	}
	if !hasCaveat(row, "may well accept the one this machine holds") {
		t.Errorf("the row does not caveat a demand met without the machine's own credential: %v", row.Caveats)
	}
}

// TestADemandWithoutASchemeSaysNothingWasOffered. A proxy answering 407 and
// naming no way of supplying anything is a real state, and a row that passed
// over it in silence would read as though certdoctor had simply not looked.
func TestADemandWithoutASchemeSaysNothingWasOffered(t *testing.T) {
	in := Input{Lenses: lensesOf(namingLens(StackEnvironment, "p.example:8080")), Target: target}
	result := askWithProxy(t, in, answeringProxy(nil, ChallengeAnswer{Asked: true, Status: 407}))

	row := oneChallengeRow(t, result)
	if !hasCaveat(row, "without naming a single way") {
		t.Errorf("a demand with no scheme carries no caveat saying so: %v", row.Caveats)
	}
}

// TestACodeThatIsNotADemandCarriesTheCaveatThatSaysWhy. The number is in the
// row, and without the sentence beside it a reader would take a 403 for a
// refusal of them rather than of the question that was asked.
func TestACodeThatIsNotADemandCarriesTheCaveatThatSaysWhy(t *testing.T) {
	in := Input{Lenses: lensesOf(namingLens(StackEnvironment, "p.example:8080")), Target: target}
	result := askWithProxy(t, in, answeringProxy(nil, ChallengeAnswer{Asked: true, Status: 403}))

	row := oneChallengeRow(t, result)
	if row.Status != 403 {
		t.Errorf("the row records status %d, want 403", row.Status)
	}
	if !hasCaveat(row, "only a 407 answers") {
		t.Errorf("a code that is not a demand carries no caveat saying so: %v", row.Caveats)
	}
}

// TestTheShapeOfTheQuestionFollowsTheTargetScheme is the measurement that made
// Query a type. Asking with CONNECT about an http:// target gets a refusal from
// squid's default rules - on a proxy that wants no credentials at all - so a
// challenge blind to the scheme would accuse a working configuration.
func TestTheShapeOfTheQuestionFollowsTheTargetScheme(t *testing.T) {
	for _, tc := range []struct {
		name      string
		target    Target
		want      Query
		authority string
	}{
		{"an https target asks for a tunnel", Target{Scheme: "https", Host: "api.example.com", Port: "443"}, QueryConnect, "api.example.com:443"},
		{"an http target asks in absolute form", Target{Scheme: "http", Host: "api.example.com"}, QueryAbsoluteForm, "api.example.com:80"},
		{"an https target on an odd port keeps that port", Target{Scheme: "https", Host: "api.example.com", Port: "8443"}, QueryConnect, "api.example.com:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked []ChallengeRequest
			in := Input{Lenses: lensesOf(namingLens(StackEnvironment, "p.example:8080")), Target: tc.target}
			askWithProxy(t, in, answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

			if len(asked) != 1 {
				t.Fatalf("wanted one question, got %d", len(asked))
			}
			if asked[0].Query != tc.want {
				t.Errorf("asked %s, want %s", asked[0].Query, tc.want)
			}
			if asked[0].Authority != tc.authority {
				t.Errorf("asked about %q, want %q", asked[0].Authority, tc.authority)
			}
		})
	}
}

// TestOneEndpointNamedTwiceIsAskedOnce is the argument ADR90 and ADR91 both
// make, applied to what they arrive at. Two Windows stacks routinely hold one
// proxy, and asking it twice would open two connections and print two answers a
// proxy under load is entitled to make differ.
func TestOneEndpointNamedTwiceIsAskedOnce(t *testing.T) {
	var asked []ChallengeRequest
	in := Input{
		Lenses: lensesOf(
			namingLens(StackWinINET, "p.example:8080"),
			namingLens(StackWinHTTP, "p.example:8080"),
		),
		Target: target,
	}
	result := askWithProxy(t, in, answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

	if len(asked) != 1 {
		t.Fatalf("one proxy named by two places was asked %d time(s)", len(asked))
	}
	row := oneChallengeRow(t, result)
	if len(row.NamedBy) != 2 || row.NamedBy[0] != "wininet" || row.NamedBy[1] != "winhttp" {
		t.Errorf("the row names %v, want both places in report order", row.NamedBy)
	}
}

// TestAProxyThisTargetSkipsIsNotAsked keeps this list down to the connections
// the run has a reason to make. The fact is not lost by leaving it out: the
// proxy_stack row carries bypass_rules, which says it per reading rather than
// once.
func TestAProxyThisTargetSkipsIsNotAsked(t *testing.T) {
	lens := Lens{
		Stack: StackWinINET, Source: "test", Read: true,
		Servers:   []Server{{Address: "p.example:8080"}},
		Bypass:    "api.example.com",
		BypassSet: true,
		Rule:      RuleWinINET,
	}
	var asked []ChallengeRequest
	result := askWithProxy(t, Input{Lenses: lensesOf(lens), Target: target},
		answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

	if len(asked) != 0 {
		t.Errorf("a proxy every reading sends this target past was asked anyway: %v", asked)
	}
	if rows := challengeRowsOf(result); len(rows) != 0 {
		t.Errorf("a proxy nothing would use produced %d challenge row(s)", len(rows))
	}
}

// TestAProxyOneReadingSkipsAndAnotherDoesNotIsStillAsked is the other half, and
// it is the product rather than an edge: one NO_PROXY is read at least two ways
// by runtimes this program asks about, so a target excused under one of them
// still goes through the proxy for the programs that read it the other way.
func TestAProxyOneReadingSkipsAndAnotherDoesNotIsStillAsked(t *testing.T) {
	// "example.com" without a leading dot: curl's reading excuses a subdomain,
	// .NET's does not - both sourced in bypass.go.
	lens := Lens{
		Stack: StackEnvironment, Source: "test", Read: true,
		Servers:   []Server{{Address: "p.example:8080"}},
		Bypass:    "example.com",
		BypassSet: true,
	}
	var asked []ChallengeRequest
	askWithProxy(t, Input{Lenses: lensesOf(lens), Target: target},
		answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

	if len(asked) != 1 {
		t.Errorf("a proxy only some runtimes skip was asked %d time(s), want 1", len(asked))
	}
}

// TestASocksProxyIsNotAskedOverHTTP. A SOCKS proxy speaks a binary protocol on
// the same kind of socket, so an HTTP request to one gets back something that is
// not HTTP - and a status code read out of that would be a number this program
// invented.
func TestASocksProxyIsNotAskedOverHTTP(t *testing.T) {
	lens := Lens{
		Stack: StackEnvironment, Source: "test", Read: true,
		Servers: []Server{{Scheme: "socks5", Address: "socks.example:1080"}},
	}
	var asked []ChallengeRequest
	result := askWithProxy(t, Input{Lenses: lensesOf(lens), Target: target},
		answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

	if len(asked) != 0 {
		t.Errorf("a SOCKS proxy was asked an HTTP question: %v", asked)
	}
	row := oneChallengeRow(t, result)
	if row.Asked {
		t.Error("the row claims a SOCKS proxy was asked")
	}
	if !strings.Contains(row.Detail, "SOCKS") {
		t.Errorf("the row does not say why nothing was asked: %q", row.Detail)
	}
}

// TestAnEndpointWithNoPortAndNoSchemeIsNotGuessedAt. Vendors do not agree on
// what a bare proxy name means, so inventing a port would make this program open
// a connection nobody named and then report what it found there.
func TestAnEndpointWithNoPortAndNoSchemeIsNotGuessedAt(t *testing.T) {
	var asked []ChallengeRequest
	in := Input{Lenses: lensesOf(namingLens(StackEnvironment, "p.example")), Target: target}
	result := askWithProxy(t, in, answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

	if len(asked) != 0 {
		t.Errorf("an address with no port was dialled anyway: %v", asked)
	}
	row := oneChallengeRow(t, result)
	if row.Endpoint != "p.example" {
		t.Errorf("the row reports %q, want the entry as the machine holds it", row.Endpoint)
	}
	if !strings.Contains(row.Detail, "did not guess") {
		t.Errorf("the row does not say a port was not guessed: %q", row.Detail)
	}
}

// TestAnEndpointWithNoPortTakesTheOneItsSchemeImplies is the other half: an
// entry written as a URL says which port it means, and the two schemes this
// program accepts have registered ones.
func TestAnEndpointWithNoPortTakesTheOneItsSchemeImplies(t *testing.T) {
	for _, tc := range []struct {
		scheme  string
		address string
		want    string
	}{
		{"http", "p.example", "p.example:80"},
		{"https", "p.example", "p.example:443"},
		{"http", "[2001:db8::1]", "[2001:db8::1]:80"},
		{"http", "2001:db8::1", "[2001:db8::1]:80"},
	} {
		t.Run(tc.scheme+" "+tc.address, func(t *testing.T) {
			lens := Lens{
				Stack: StackEnvironment, Source: "test", Read: true,
				Servers: []Server{{Scheme: tc.scheme, Address: tc.address}},
			}
			var asked []ChallengeRequest
			askWithProxy(t, Input{Lenses: lensesOf(lens), Target: target},
				answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

			if len(asked) != 1 {
				t.Fatalf("wanted one question, got %d", len(asked))
			}
			if asked[0].Endpoint != tc.want {
				t.Errorf("dialled %q, want %q", asked[0].Endpoint, tc.want)
			}
		})
	}
}

// TestAnAddressThatAlreadyNamesAPortIsDialledAsWritten, including a bracketed
// IPv6 literal. The string in the allowed set and the string handed to the
// dialler have to be the same one, and a second spelling would mean either a
// refusal on a machine where everything works or a connection nothing checked.
func TestAnAddressThatAlreadyNamesAPortIsDialledAsWritten(t *testing.T) {
	for _, address := range []string{"p.example:8080", "[2001:db8::1]:8080", "192.0.2.1:3128"} {
		t.Run(address, func(t *testing.T) {
			var asked []ChallengeRequest
			in := Input{Lenses: lensesOf(namingLens(StackEnvironment, address)), Target: target}
			result := askWithProxy(t, in, answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

			if len(asked) != 1 || asked[0].Endpoint != address {
				t.Fatalf("dialled %v, want exactly %q", asked, address)
			}
			if got := result.Dialable(); len(got) != 1 || got[0] != address {
				t.Errorf("the allowed set would be widened by %v, want exactly %q", got, address)
			}
		})
	}
}

// TestDialableLeavesOutWhatWillNotBeAsked. It is the list the orchestrator
// widens the allowed set by, so an endpoint on it that nothing was ever going to
// contact is permission this program gained for nothing.
func TestDialableLeavesOutWhatWillNotBeAsked(t *testing.T) {
	lens := Lens{
		Stack: StackEnvironment, Source: "test", Read: true,
		Servers: []Server{{Scheme: "socks5", Address: "socks.example:1080"}},
	}
	ctx := context.Background()
	in := Input{Lenses: lensesOf(lens), Target: target}
	result := Ask(ctx, in, Read(ctx, in))

	if len(result.Endpoints) != 1 {
		t.Fatalf("wanted one endpoint, got %d", len(result.Endpoints))
	}
	if got := result.Dialable(); len(got) != 0 {
		t.Errorf("an endpoint the layer declined would still be authorised: %v", got)
	}
}

// TestAScriptsProxyIsAskedAndNamedByTheScript. A PAC answer outranks a stack's
// list on the machine, so the proxy it chooses is one this URL really goes
// through - and the row has to say where it came from, because "the environment
// says one thing and the script another" is the fault this product exists to
// show.
func TestAScriptsProxyIsAskedAndNamedByTheScript(t *testing.T) {
	var asked []ChallengeRequest
	in := Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		ScriptURL: "http://wpad.example/proxy.pac",
		Evaluate:  answering(nil, answeredWith("PROXY chosen.example:3128; DIRECT")),
	}
	result := askWithProxy(t, in, answeringProxy(&asked, demanding()))

	if len(asked) != 1 || asked[0].Endpoint != "chosen.example:3128" {
		t.Fatalf("asked %v, want the address the script chose", asked)
	}
	row := oneChallengeRow(t, result)
	if len(row.NamedBy) != 1 || row.NamedBy[0] != NamedByScript {
		t.Errorf("the row names %v, want the token for a script", row.NamedBy)
	}
	if result.Reason != status.ReasonCredentialsRequired {
		t.Errorf("a script's proxy demanding credentials answered %s, want credentials_required", result.Reason)
	}
}

// TestASocksDirectiveIsNotAskedEither, for the reason a SOCKS entry in a stack
// is not: the keyword is the only thing a script says about how to reach the
// address it names.
func TestASocksDirectiveIsNotAskedEither(t *testing.T) {
	var asked []ChallengeRequest
	in := Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		ScriptURL: "http://wpad.example/proxy.pac",
		Evaluate:  answering(nil, answeredWith("SOCKS5 socks.example:1080")),
	}
	result := askWithProxy(t, in, answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

	if len(asked) != 0 {
		t.Errorf("a SOCKS directive was asked an HTTP question: %v", asked)
	}
	row := oneChallengeRow(t, result)
	if !strings.Contains(row.Detail, "SOCKS") {
		t.Errorf("the row does not say why nothing was asked: %q", row.Detail)
	}
}

// TestAScriptAnsweringDirectNamesNoEndpointToAsk. DIRECT is an answer and not a
// gap, so there is nothing to ask and nothing to say about it here - the script
// row already carries it.
func TestAScriptAnsweringDirectNamesNoEndpointToAsk(t *testing.T) {
	in := Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		ScriptURL: "http://wpad.example/proxy.pac",
		Evaluate:  answering(nil, answeredWith("DIRECT")),
	}
	result := askWithProxy(t, in, answeringProxy(nil, demanding()))

	if rows := challengeRowsOf(result); len(rows) != 0 {
		t.Errorf("a script sending this URL direct produced %d challenge row(s)", len(rows))
	}
}

// TestAMissingChallengePortIsOurGapAndNotAProxyThatLetUsThrough pins the
// direction a forgotten wire has to fail in, which is the same direction every
// other port in this program chose.
func TestAMissingChallengePortIsOurGapAndNotAProxyThatLetUsThrough(t *testing.T) {
	in := Input{Lenses: lensesOf(namingLens(StackEnvironment, "p.example:8080")), Target: target}
	result := askWithProxy(t, in, nil)

	row := oneChallengeRow(t, result)
	if row.Asked {
		t.Error("a run with no way to ask claims a proxy was asked")
	}
	if !strings.Contains(row.Detail, "gap in certdoctor") {
		t.Errorf("the row blames the machine rather than us: %q", row.Detail)
	}
	if result.Reason == status.ReasonCredentialsRequired {
		t.Error("a run that asked nothing concluded a proxy demanded credentials")
	}
}

// TestAPortThatContradictsItselfBecomesOurGapRatherThanABadRow. The report
// contract refuses a row saying a proxy was asked without saying what it
// answered, and a refused row degrades the WHOLE layer - ADR66 - so a port
// returning nonsense would cost a reader every proxy row rather than one.
func TestAPortThatContradictsItselfBecomesOurGapRatherThanABadRow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer ChallengeAnswer
	}{
		{"asked with no code", ChallengeAnswer{Asked: true}},
		{"not asked and no reason", ChallengeAnswer{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Input{Lenses: lensesOf(namingLens(StackEnvironment, "p.example:8080")), Target: target}
			result := askWithProxy(t, in, answeringProxy(nil, tc.answer))

			row := oneChallengeRow(t, result)
			finding := report.Finding{
				Kind: report.FindingProxyChallenge, Summary: "x",
				Source: report.SourceDetected, ProxyChallenge: &row,
			}
			if broken := finding.Breach(); broken != "" {
				t.Errorf("the row is one the contract refuses: %s", broken)
			}
			if row.Asked {
				t.Error("a contradictory answer was reported as an answer")
			}
		})
	}
}

// TestEveryChallengeRowSurvivesItsOwnContract. One refused row degrades the
// whole layer, so a row this package can build and the contract rejects would
// cost a reader every proxy fact in the report.
func TestEveryChallengeRowSurvivesItsOwnContract(t *testing.T) {
	lens := Lens{
		Stack: StackWinINET, Source: "test", Read: true,
		Servers: []Server{{Address: "p.example:8080", CarriedCredentials: true}},
	}
	for _, answer := range []ChallengeAnswer{
		demanding(),
		{Asked: true, Status: 200},
		{Asked: true, Status: 407},
		{Detail: "nothing was asked"},
	} {
		result := askWithProxy(t, Input{Lenses: lensesOf(lens), Target: target}, answeringProxy(nil, answer))
		for _, finding := range result.Findings {
			if broken := finding.Breach(); broken != "" {
				t.Errorf("a row this layer produced is one the contract refuses: %s", broken)
			}
		}
	}
}

// TestTwoProxiesDemandingAreCountedRatherThanNamed. The verdict crosses the
// assembly path through a masking rule that cannot see a bare "host:port", so
// the sentence counts and the rows name.
func TestTwoProxiesDemandingAreCountedRatherThanNamed(t *testing.T) {
	in := Input{
		Lenses: lensesOf(
			namingLens(StackWinINET, "first.example:8080"),
			namingLens(StackWinHTTP, "second.example:8080"),
		),
		Target: target,
	}
	result := askWithProxy(t, in, answeringProxy(nil, demanding()))

	if !strings.Contains(result.Detail, "2 of the proxies") {
		t.Errorf("the verdict does not count the proxies that demanded: %q", result.Detail)
	}
	for _, named := range []string{"first.example", "second.example"} {
		if strings.Contains(result.Detail, named) {
			t.Errorf("the verdict names %q, which no masking rule can see in a summary", named)
		}
	}
}

// TestAskingNothingLeavesTheAnswerExactlyAsItWas. This half of the layer adds
// facts; it must not be able to change one on a machine where there was nothing
// to ask.
func TestAskingNothingLeavesTheAnswerExactlyAsItWas(t *testing.T) {
	ctx := context.Background()
	in := Input{Lenses: lensesOf(silentLens(StackEnvironment)), Target: target}
	before := Ask(ctx, in, Read(ctx, in))
	after := Challenge(ctx, in, before)

	if after.Status != before.Status || after.Reason != before.Reason || after.Detail != before.Detail {
		t.Errorf("a run with nothing to ask changed its answer: %v -> %v", before, after)
	}
	if len(after.Findings) != len(before.Findings) {
		t.Errorf("a run with nothing to ask gained %d row(s)", len(after.Findings)-len(before.Findings))
	}
}

// TestAskingBeforeReadingIsOurGapAndSaysSo. The zero Reading can only arrive by
// way of a caller that skipped Read, and reporting that as a machine whose
// configuration could not be read would put our own wiring fault into the report
// as a fact about somebody's computer.
func TestAskingBeforeReadingIsOurGapAndSaysSo(t *testing.T) {
	result := Ask(context.Background(), Input{Target: target}, Reading{})

	if result.Status != status.Unknown || result.Reason != status.ReasonProbeError {
		t.Errorf("asking before reading answered %s / %s, want unknown / probe_error", result.Status, result.Reason)
	}
	if !strings.Contains(result.Detail, "before this machine's proxy configuration had been") {
		t.Errorf("the detail does not say what was skipped: %q", result.Detail)
	}
}

// TestReadNamesTheScriptsWithoutAskingAnything is what the seam is for: the
// orchestrator has to be able to authorise a script address BEFORE anything
// fetches it, and until this slice a script read off this machine was fetched
// with nothing having authorised it at all.
func TestReadNamesTheScriptsWithoutAskingAnything(t *testing.T) {
	var evaluated []string
	lens := Lens{Stack: StackWinINET, Source: "test", Read: true, Servers: []Server{}, PACURL: "http://wpad.example/proxy.pac"}
	in := Input{
		Lenses:    lensesOf(lens),
		Target:    target,
		ScriptURL: "http://typed.example/other.pac",
		Evaluate:  answering(&evaluated, answeredWith("DIRECT")),
	}

	reading := Read(context.Background(), in)
	if len(evaluated) != 0 {
		t.Errorf("reading the configuration fetched %d script(s) before anything authorised them", len(evaluated))
	}
	want := []string{"http://typed.example/other.pac", "http://wpad.example/proxy.pac"}
	if len(reading.Scripts) != len(want) {
		t.Fatalf("reading named %v, want %v", reading.Scripts, want)
	}
	for at := range want {
		if reading.Scripts[at] != want[at] {
			t.Errorf("script %d is %q, want %q - the command line comes first", at, reading.Scripts[at], want[at])
		}
	}
}

// TestARowNobodyAskedSaysWhyOnEVERYSurface. The terminal renders a summary and a
// value and never a Detail, so a row whose reason lived only in Detail printed
// "was not asked" beside an address and said nothing about why - inviolable rule
// 1 broken on the surface most people read. Measured on the binary, not reasoned.
func TestARowNobodyAskedSaysWhyOnEVERYSurface(t *testing.T) {
	for _, tc := range []struct {
		name string
		lens Lens
		ask  ChallengeAsk
		says string
	}{
		{
			"a proxy this run declined to ask",
			Lens{Stack: StackEnvironment, Source: "test", Read: true,
				Servers: []Server{{Scheme: "socks5", Address: "socks.example:1080"}}},
			answeringProxy(nil, ChallengeAnswer{Asked: true, Status: 200}),
			"SOCKS",
		},
		{
			"a proxy that could not be reached",
			namingLens(StackEnvironment, "p.example:8080"),
			answeringProxy(nil, ChallengeAnswer{Detail: "this proxy could not be reached: the dial failed"}),
			"could not be reached",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := askWithProxy(t, Input{Lenses: lensesOf(tc.lens), Target: target}, tc.ask)

			var summary string
			for _, finding := range result.Findings {
				if finding.ProxyChallenge != nil {
					summary = finding.Summary
				}
			}
			if !strings.Contains(summary, tc.says) {
				t.Errorf("the summary does not say why nothing was asked: %q", summary)
			}
			// AND IT STILL NAMES NO ENDPOINT. A summary crosses the assembly
			// path through a rule that cannot see a bare "host:port", so
			// carrying the reason must not have carried the address with it.
			for _, named := range []string{"p.example", "socks.example"} {
				if strings.Contains(summary, named) {
					t.Errorf("the summary names the proxy: %q", summary)
				}
			}
		})
	}
}

// TestATargetThisRunCannotNameAnOriginForIsNotAsked. proxy.Target says outright
// that a Scheme may be empty when a caller genuinely does not know it, so this
// is a documented state of the type rather than an impossible one - and with no
// scheme and no port there is no origin to put to a proxy. Widening the allowed
// set for an endpoint nothing can ask would be permission gained for nothing.
func TestATargetThisRunCannotNameAnOriginForIsNotAsked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target Target
	}{
		{"no scheme and no port", Target{Host: "api.example.com"}},
		{"no host at all", Target{Scheme: "https"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked []ChallengeRequest
			in := Input{Lenses: lensesOf(namingLens(StackEnvironment, "p.example:8080")), Target: tc.target}
			result := askWithProxy(t, in, answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

			if len(asked) != 0 {
				t.Errorf("a proxy was asked about an origin this run could not name: %v", asked)
			}
			if got := result.Dialable(); len(got) != 0 {
				t.Errorf("the allowed set would be widened for an endpoint nothing can ask: %v", got)
			}
			row := oneChallengeRow(t, result)
			if !strings.Contains(row.Detail, "gap here") {
				t.Errorf("the row blames the machine rather than us: %q", row.Detail)
			}
		})
	}
}

// TestEveryKeywordAScriptMayNameArrivesAtTheRightPort. The keyword is the only
// thing a PAC answer says about how the address it names is reached - Mozilla's
// own list, quoted in internal/core/pac - so it is the only thing a port can be
// derived from when the file names none.
func TestEveryKeywordAScriptMayNameArrivesAtTheRightPort(t *testing.T) {
	for _, tc := range []struct {
		answer string
		want   string
		asked  bool
	}{
		{"PROXY p.example", "p.example:80", true},
		{"HTTP p.example", "p.example:80", true},
		{"HTTPS p.example", "p.example:443", true},
		{"SOCKS p.example", "p.example", false},
	} {
		t.Run(tc.answer, func(t *testing.T) {
			var asked []ChallengeRequest
			in := Input{
				Lenses:    lensesOf(silentLens(StackEnvironment)),
				Target:    target,
				ScriptURL: "http://wpad.example/proxy.pac",
				Evaluate:  answering(nil, answeredWith(tc.answer)),
			}
			result := askWithProxy(t, in, answeringProxy(&asked, ChallengeAnswer{Asked: true, Status: 200}))

			row := oneChallengeRow(t, result)
			if row.Endpoint != tc.want {
				t.Errorf("the row reports %q, want %q", row.Endpoint, tc.want)
			}
			if row.Asked != tc.asked {
				t.Errorf("asked is %v, want %v", row.Asked, tc.asked)
			}
			if tc.asked && (len(asked) != 1 || asked[0].Endpoint != tc.want) {
				t.Errorf("dialled %v, want %q", asked, tc.want)
			}
		})
	}
}

// TestAQueryIsPrintableWithoutAConversion, because the row carries it as a
// string and a second spelling of these two words would be a second vocabulary.
func TestAQueryIsPrintableWithoutAConversion(t *testing.T) {
	if len(AllQueries) != 2 {
		t.Fatalf("%d shapes of question are declared, want 2", len(AllQueries))
	}
	for _, query := range AllQueries {
		if query.String() != string(query) {
			t.Errorf("%q does not print as itself", query)
		}
	}
}

func hasCaveat(row report.ProxyChallenge, want string) bool {
	for _, caveat := range row.Caveats {
		if strings.Contains(caveat, want) {
			return true
		}
	}
	return false
}
