package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/pac"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// answering is a port that hands back one answer for every address, and records
// what it was asked about.
func answering(asked *[]string, answer ScriptAnswer) Evaluate {
	return func(_ context.Context, url string) ScriptAnswer {
		if asked != nil {
			*asked = append(*asked, url)
		}
		return answer
	}
}

// answeredWith is the ordinary case: a script that ran and returned something.
func answeredWith(raw string) ScriptAnswer {
	return ScriptAnswer{
		Fetched: true,
		Result: pac.Result{
			Outcome:    pac.OutcomeAnswered,
			Raw:        raw,
			Directives: pac.ParseDirectives(raw),
		},
	}
}

// scriptRowOf returns the one script row, and fails when there is none.
func scriptRowOf(t *testing.T, result Result) report.PACScript {
	t.Helper()
	var found *report.PACScript
	for _, finding := range result.Findings {
		if finding.PACScript == nil {
			continue
		}
		if found != nil {
			t.Fatalf("more than one script row among %d finding(s)", len(result.Findings))
		}
		found = finding.PACScript
	}
	if found == nil {
		t.Fatalf("no script row among %d finding(s)", len(result.Findings))
	}
	return *found
}

func scriptSummary(result Result) string {
	for _, finding := range result.Findings {
		if finding.PACScript != nil {
			return finding.Summary
		}
	}
	return ""
}

// TestAScriptTheUserNamedIsAsked is the flag's whole reason for existing: only
// the Windows stacks carry an AutoConfigURL, so on every other machine - and on
// the bench, which is Linux - nothing would ever reach this half of the layer.
func TestAScriptTheUserNamedIsAsked(t *testing.T) {
	var asked []string
	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(&asked, answeredWith("DIRECT")),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	if len(asked) != 1 || asked[0] != "http://pac.example/proxy.pac" {
		t.Fatalf("the port was asked about %v, want the address the user named", asked)
	}
	row := scriptRowOf(t, result)
	if len(row.NamedBy) != 1 || row.NamedBy[0] != NamedOnCommandLine {
		t.Errorf("the row says it was named by %v, want the command line", row.NamedBy)
	}
}

// TestTwoPlacesNamingOneScriptProduceOneRow is the deduplication, and it is not
// tidiness: two Windows stacks routinely hold one AutoConfigURL, so a pass per
// place would fetch one file twice, run it twice, and print two answers that a
// file using Math.random is entitled to make differ.
func TestTwoPlacesNamingOneScriptProduceOneRow(t *testing.T) {
	first := silentLens(StackWinINET)
	first.PACURL = "http://wpad.example/proxy.pac"
	second := silentLens(StackWinHTTP)
	second.PACURL = "http://wpad.example/proxy.pac"

	var asked []string
	result := askLayer(t, Input{
		Lenses:   lensesOf(first, second),
		Target:   target,
		Evaluate: answering(&asked, answeredWith("DIRECT")),
	})

	if len(asked) != 1 {
		t.Fatalf("one address named twice was fetched %d time(s)", len(asked))
	}
	row := scriptRowOf(t, result)
	if strings.Join(row.NamedBy, ",") != "wininet,winhttp" {
		t.Errorf("the row names %v, want both places in report order", row.NamedBy)
	}
}

// TestTheCommandLineComesFirst pins report order, which is the order a reader
// meets things in and the order openReason picks a word from.
func TestTheCommandLineComesFirst(t *testing.T) {
	lens := silentLens(StackWinINET)
	lens.PACURL = "http://wpad.example/machine.pac"

	var asked []string
	askLayer(t, Input{
		Lenses:    lensesOf(lens),
		Target:    target,
		Evaluate:  answering(&asked, answeredWith("DIRECT")),
		ScriptURL: "http://pac.example/asked-about.pac",
	})

	if len(asked) != 2 || asked[0] != "http://pac.example/asked-about.pac" {
		t.Errorf("the scripts were asked about in the order %v, want the command line first", asked)
	}
}

// TestAnUnreadablePlaceNamesNoScript is the rule findingFor already applies to a
// place's servers, applied one field along: reporting what a place we could not
// read held is inventing it.
func TestAnUnreadablePlaceNamesNoScript(t *testing.T) {
	unreadable := UnreadableLens(StackWinINET, "test", "no such key")
	unreadable.PACURL = "http://wpad.example/proxy.pac"

	var asked []string
	askLayer(t, Input{
		Lenses:   lensesOf(silentLens(StackEnvironment), unreadable),
		Target:   target,
		Evaluate: answering(&asked, answeredWith("DIRECT")),
	})

	if len(asked) != 0 {
		t.Errorf("a script named by a place nobody could read was fetched anyway: %v", asked)
	}
}

// TestAScriptSendingTheTargetPastTheProxyIsTheHeadline is the fault ADR8 calls
// this product's reason to exist, and testbed/expected/proxy-pac-direct.txt
// spells out what must and must not be said about it: a proxy is configured, the
// environment says so, and the script sends this one name straight out.
func TestAScriptSendingTheTargetPastTheProxyIsTheHeadline(t *testing.T) {
	result := askLayer(t, Input{
		Lenses:    lensesOf(namingLens(StackEnvironment, "proxy.example:8080")),
		Target:    target,
		Evaluate:  answering(nil, answeredWith("DIRECT")),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	if result.Status != status.Pass {
		t.Fatalf("a settled script answered %s / %s: %s", result.Status, result.Reason, result.Detail)
	}
	if !strings.Contains(result.Detail, "past every proxy") {
		t.Errorf("the verdict does not say the script bypasses the proxy: %q", result.Detail)
	}
	// The two sentences that file forbids, because either of them tells somebody
	// the opposite of what happens on their machine.
	for _, forbidden := range []string{"goes through the proxy", "uses HTTPS_PROXY"} {
		if strings.Contains(result.Detail, forbidden) {
			t.Errorf("the verdict says %q about a URL the script sends direct: %q", forbidden, result.Detail)
		}
	}
}

// TestAScriptNamingAProxyPutsTheAddressInTheBodyAndNotTheSummary is ADR90 part 5
// one row along. A summary crosses the assembly path through Redaction.Text,
// which pseudonymises names it was told about and hosts INSIDE a URL - and a PAC
// directive's endpoint is a bare host:port arriving during the walk, so it is
// neither.
func TestAScriptNamingAProxyPutsTheAddressInTheBodyAndNotTheSummary(t *testing.T) {
	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, answeredWith("PROXY proxy.example:8080; DIRECT")),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	row := scriptRowOf(t, result)
	if row.Selected == nil || row.Selected.Endpoint != "proxy.example:8080" {
		t.Fatalf("the row does not carry the endpoint: %+v", row.Selected)
	}
	if len(row.Directives) != 2 {
		t.Errorf("the row carries %d directive(s), want both the file listed", len(row.Directives))
	}
	if strings.Contains(scriptSummary(result), "proxy.example:8080") {
		t.Errorf("the summary carries an address no masking rule can see: %q", scriptSummary(result))
	}
	if strings.Contains(result.Detail, "proxy.example:8080") {
		t.Errorf("the verdict carries an address no masking rule can see: %q", result.Detail)
	}
}

// TestTheFirstRecognisedEntryIsTheOneAClientWouldFollow is Mozilla's own rule -
// entries are tried left to right - and inviolable rule 15 beside it: an entry
// this program does not know is SKIPPED for selection and still CARRIED in the
// list, because one quietly dropped would let a report say a client goes direct.
func TestTheFirstRecognisedEntryIsTheOneAClientWouldFollow(t *testing.T) {
	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, answeredWith("QUIC quic.example:443; PROXY proxy.example:8080")),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	row := scriptRowOf(t, result)
	if len(row.Directives) != 2 {
		t.Fatalf("an unrecognised keyword was dropped: %+v", row.Directives)
	}
	if row.Directives[0].Recognised {
		t.Errorf("QUIC came back as a keyword this program knows")
	}
	if row.Selected == nil || row.Selected.Kind != "PROXY" {
		t.Errorf("the selected entry is %+v, want the first one this program knows", row.Selected)
	}
}

// TestAnAnswerOfNothingRecognisedIsSaidRatherThanTreatedAsDirect is the case an
// empty Selected could be mistaken for. A file naming only keywords we cannot
// read has not said "go direct".
func TestAnAnswerOfNothingRecognisedIsSaidRatherThanTreatedAsDirect(t *testing.T) {
	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, answeredWith("QUIC quic.example:443")),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	row := scriptRowOf(t, result)
	if row.Selected != nil {
		t.Fatalf("an answer of nothing recognised selected %+v", row.Selected)
	}
	if !hasScriptCaveat(row, "keyword certdoctor knows") {
		t.Errorf("the row does not say its answer names nothing to act on: %v", row.Caveats)
	}
	if strings.Contains(result.Detail, "past every proxy") {
		t.Errorf("an unreadable answer was reported as going direct: %q", result.Detail)
	}
	// AND IT SETTLES NOTHING - ADR114. It used to settle the layer and leave it
	// a PASS on an answer this program says it cannot read.
	if result.Status != status.Unknown || result.Reason != status.ReasonUndetermined {
		t.Errorf("an answer of nothing recognised came back as %s / %s", result.Status, result.Reason)
	}
}

// A KNOWN WORD WITHOUT ITS ADDRESS IS NO ENTRY - ADR114. "PROXY" alone was
// selected with an empty address, which is how DIRECT looks, and the report said
// the URL went past every proxy. A client skips it, so a DIRECT after it is the
// entry that decides.
func TestAKnownWordWithoutItsAddressIsNoEntry(t *testing.T) {
	ask := func(raw string) Result {
		return askLayer(t, Input{
			Lenses:    lensesOf(silentLens(StackEnvironment)),
			Target:    target,
			Evaluate:  answering(nil, answeredWith(raw)),
			ScriptURL: "http://pac.example/proxy.pac",
		})
	}

	alone := ask("PROXY")
	if row := scriptRowOf(t, alone); row.Selected != nil || strings.Contains(scriptSummary(alone), "past every proxy") {
		t.Errorf("PROXY alone was followed: %+v, %q", row.Selected, scriptSummary(alone))
	}
	if alone.Status != status.Unknown {
		t.Errorf("PROXY alone settled the layer as %s", alone.Status)
	}
	for _, raw := range []string{"DIRECT elsewhere.example:1", "PROXY two words:1"} {
		if row := scriptRowOf(t, ask(raw)); row.Selected != nil {
			t.Errorf("%q was followed as %+v", raw, row.Selected)
		}
	}

	skipped := ask("PROXY; DIRECT")
	if row := scriptRowOf(t, skipped); row.Selected == nil || row.Selected.Kind != "DIRECT" {
		t.Errorf("the entry after PROXY alone is not the one followed: %+v", row.Selected)
	}
	if skipped.Status != status.Pass || !strings.Contains(skipped.Detail, "past every proxy") {
		t.Errorf("a script ending in DIRECT came back as %s: %q", skipped.Status, skipped.Detail)
	}
}

// A RESOLVER THAT DID NOT ANSWER SETTLES NOTHING - ADR114. The file got the null
// a name that does not exist gets, and may have chosen DIRECT on it.
func TestAnAnswerRestingOnAResolverThatFailedIsNotSettled(t *testing.T) {
	answer := answeredWith("DIRECT")
	answer.Result.LookupsFailed = true

	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, answer),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	if result.Status != status.Unknown || result.Reason != status.ReasonUndetermined {
		t.Errorf("an answer resting on a failed resolver came back as %s / %s", result.Status, result.Reason)
	}
	if !hasScriptCaveat(scriptRowOf(t, result), "no resolver on this machine gave a usable answer") {
		t.Errorf("the row does not say a resolver failed: %v", scriptRowOf(t, result).Caveats)
	}
}

// TestEveryWayAScriptCanFailGetsItsOwnWord is the table ADR80 part 3 fixed and
// this slice declared. The boundary is binding: TIME stays with timeout, every
// other ceiling of ours goes to limit_exceeded, and a file that will not parse
// is the word testbed/expected/pac-broken.txt fixed before this code existed.
func TestEveryWayAScriptCanFailGetsItsOwnWord(t *testing.T) {
	for _, tc := range []struct {
		outcome pac.Outcome
		want    status.Reason
	}{
		{pac.OutcomeMalformed, status.ReasonUnparseable},
		{pac.OutcomeTimeLimit, status.ReasonTimeout},
		{pac.OutcomeMemoryCeiling, status.ReasonLimitExceeded},
		{pac.OutcomeStackLimit, status.ReasonLimitExceeded},
		{pac.OutcomeTooLarge, status.ReasonLimitExceeded},
		{pac.OutcomeNoAnswer, status.ReasonUndetermined},
	} {
		result := askLayer(t, Input{
			Lenses: lensesOf(silentLens(StackEnvironment)),
			Target: target,
			Evaluate: answering(nil, ScriptAnswer{
				Fetched: true,
				Result:  pac.Result{Outcome: tc.outcome, Detail: "what went wrong"},
			}),
			ScriptURL: "http://pac.example/proxy.pac",
		})

		if result.Status != status.Unknown {
			t.Errorf("%s answered %s, want unknown", tc.outcome, result.Status)
		}
		if result.Reason != tc.want {
			t.Errorf("%s came back as %s, want %s", tc.outcome, result.Reason, tc.want)
		}
		row := scriptRowOf(t, result)
		if row.Detail != "what went wrong" {
			t.Errorf("%s lost the evaluator's own sentence: %q", tc.outcome, row.Detail)
		}
		// NIL AND NOT AN EMPTY LIST - ADR20, and the assertion is here rather
		// than on the unfetched row because that one never reaches the
		// conversion at all. A file that did not answer named no entries, and an
		// empty array would say it was asked and listed none.
		if row.Directives != nil {
			t.Errorf("%s came back with an entry list rather than none: %+v", tc.outcome, row.Directives)
		}
	}
}

// TestAScriptThatReturnedNullIsNeverReportedAsDirect is ADR79's open
// disagreement, settled. Mozilla says null means "no proxies" and a browser goes
// direct; testbed/pac/files/null.pac, written before this code existed, expects
// an UNKNOWN with a reason. This program REPORTS rather than routes, and a
// silent fall back to DIRECT is the behaviour it exists to interrupt.
func TestAScriptThatReturnedNullIsNeverReportedAsDirect(t *testing.T) {
	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, ScriptAnswer{Fetched: true, Result: pac.Result{Outcome: pac.OutcomeNoAnswer}}),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	if result.Status != status.Unknown || result.Reason != status.ReasonUndetermined {
		t.Errorf("a null answer came back as %s / %s", result.Status, result.Reason)
	}
	for _, said := range []string{result.Detail, scriptSummary(result)} {
		if strings.Contains(said, "DIRECT") || strings.Contains(said, "past every proxy") {
			t.Errorf("a null answer was reported as going direct: %q", said)
		}
	}
	if row := scriptRowOf(t, result); row.Selected != nil {
		t.Errorf("a null answer selected %+v", row.Selected)
	}
}

// TestAnAnswerRestingOnAQuestionNobodyCouldAnswerIsNotSettled is decision B of
// this slice and the reason pac.Result.Unanswered exists. The file answered, so
// nothing in the outcome shows a problem - and its branch was decided by a
// helper that was told "no" because there was nobody to ask.
func TestAnAnswerRestingOnAQuestionNobodyCouldAnswerIsNotSettled(t *testing.T) {
	answer := answeredWith("DIRECT")
	answer.Result.Unanswered = []string{"isInNet"}

	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, answer),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	if result.Status != status.Unknown || result.Reason != status.ReasonUndetermined {
		t.Errorf("an answer resting on an unanswerable helper came back as %s / %s", result.Status, result.Reason)
	}
	row := scriptRowOf(t, result)
	if !hasScriptCaveat(row, "isInNet") {
		t.Errorf("the row does not name the helper nobody could answer: %v", row.Caveats)
	}
}

// TestAnAnswerThatSpentTheResolverAllowanceIsNotSettled is the same untruth as
// the test above reached from the other side, and it is the reason the two
// fields are separate rather than one boolean.
//
// A run with a resolver still stops answering once the file has asked about more
// distinct names than one evaluation may - the bound probe S16 showed the
// stopwatch does not provide, because it holds time and not count. From the PAC
// file's point of view those names simply did not resolve, so it takes a branch a
// browser would not, and an answer reached that way settles nothing.
//
// THE SENTENCE HAS TO BE THE OTHER ONE. Folding this into Unanswered would tell
// somebody their machine has no resolver when it has one and their script spent
// its allowance - a false statement about their machine rather than about their
// file, which is the direction this program is built not to go.
func TestAnAnswerThatSpentTheResolverAllowanceIsNotSettled(t *testing.T) {
	answer := answeredWith("PROXY proxy.example:8080")
	answer.Result.LookupsExhausted = true

	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, answer),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	if result.Status != status.Unknown || result.Reason != status.ReasonUndetermined {
		t.Errorf("an answer reached past the resolver allowance came back as %s / %s", result.Status, result.Reason)
	}
	row := scriptRowOf(t, result)
	if !hasScriptCaveat(row, "more distinct names than one evaluation may resolve") {
		t.Errorf("the row does not say the allowance was spent: %v", row.Caveats)
	}
	for _, caveat := range row.Caveats {
		if strings.Contains(caveat, "this run had nothing behind those") {
			t.Errorf("a machine WITH a resolver was told it has none: %q", caveat)
		}
	}
}

// TestARandomisedAnswerIsOneOfTheAnswersRatherThanTheAnswer keeps the report
// from overstating itself. The sandbox pins the random source so two runs of one
// binary agree, which is what the determinism guard needs - and it makes this
// answer one branch of several a browser would spread across.
func TestARandomisedAnswerIsOneOfTheAnswersRatherThanTheAnswer(t *testing.T) {
	answer := answeredWith("PROXY proxy.example:8080")
	answer.Result.UsedRandomness = true

	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, answer),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	if !hasScriptCaveat(scriptRowOf(t, result), "Math.random") {
		t.Errorf("a randomised answer carries no caveat: %v", scriptRowOf(t, result).Caveats)
	}
}

// TestAClockedAnswerCarriesItsDateAndStillSettlesTheLayer holds both halves of
// what UsedClock is for, and the second half is the one easy to get wrong.
//
// A file routing office hours through a proxy gives one answer at nine in the
// morning and another at nine at night, and both are correct - so the report
// says which moment it took. But it is NOT a refusal: a clock this run really
// has is not a question nobody could be asked, which is the line between this
// and Unanswered. Grading it UNKNOWN would tell somebody their machine could
// not work something out, when it worked it out exactly.
func TestAClockedAnswerCarriesItsDateAndStillSettlesTheLayer(t *testing.T) {
	answer := answeredWith("PROXY proxy.example:8080")
	answer.Result.UsedClock = true

	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, answer),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	if !hasScriptCaveat(scriptRowOf(t, result), "what day or time it is") {
		t.Errorf("a clocked answer carries no caveat: %v", scriptRowOf(t, result).Caveats)
	}
	if result.Status == status.Unknown {
		t.Errorf("a clocked answer was refused as %s / %s - the clock was read, not missing",
			result.Status, result.Reason)
	}
}

// TestAScriptNobodyCouldFetchSaysSoAndSaysWhy keeps two facts apart that send a
// reader to different places: a web server nobody can reach, and a file that
// answers badly.
func TestAScriptNobodyCouldFetchSaysSoAndSaysWhy(t *testing.T) {
	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(nil, ScriptAnswer{Detail: "the dial failed"}),
		ScriptURL: "http://pac.example/proxy.pac",
	})

	row := scriptRowOf(t, result)
	if row.Fetched {
		t.Error("a script nobody fetched came back as fetched")
	}
	if row.Detail != "the dial failed" {
		t.Errorf("the row does not say why: %q", row.Detail)
	}
	if row.Outcome != "" || row.Directives != nil || row.Selected != nil {
		t.Errorf("a script nobody fetched reports what it said: %+v", row)
	}
	if result.Reason != status.ReasonUndetermined {
		t.Errorf("an unfetched script came back as %s", result.Reason)
	}
}

// TestARunWithNoWayToFetchSaysTheGapIsOurs is the safe direction for a forgotten
// wire: it must not make a machine look like it has no script.
func TestARunWithNoWayToFetchSaysTheGapIsOurs(t *testing.T) {
	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		ScriptURL: "http://pac.example/proxy.pac",
	})

	row := scriptRowOf(t, result)
	if row.Fetched {
		t.Fatal("a run with no port fetched a script")
	}
	if !strings.Contains(row.Detail, "certdoctor") {
		t.Errorf("the row blames the machine rather than this program: %q", row.Detail)
	}
}

// TestACredentialInAScriptAddressIsCutBeforeAnythingIsFetched is inviolable rule
// 17 and ADR89's mechanism, applied to the second field that becomes both a
// connection target and a report field.
func TestACredentialInAScriptAddressIsCutBeforeAnythingIsFetched(t *testing.T) {
	var asked []string
	result := askLayer(t, Input{
		Lenses:    lensesOf(silentLens(StackEnvironment)),
		Target:    target,
		Evaluate:  answering(&asked, answeredWith("DIRECT")),
		ScriptURL: "http://bob:hunter2@pac.example/proxy.pac",
	})

	if len(asked) != 1 || asked[0] != "http://pac.example/proxy.pac" {
		t.Fatalf("the port was asked about %v, and a credential must not reach it", asked)
	}
	row := scriptRowOf(t, result)
	if strings.Contains(row.URL, "hunter2") || strings.Contains(row.URL, "bob") {
		t.Errorf("the row carries the credential: %q", row.URL)
	}
	if !hasScriptCaveat(row, "dropped them and did not send them") {
		t.Errorf("the row drops a credential without saying so: %v", row.Caveats)
	}
	if strings.Contains(scriptSummary(result), "hunter2") {
		t.Errorf("the summary carries the credential: %q", scriptSummary(result))
	}
}

// TestWithoutCredentialsReadsAURLAndNotAProxyListEntry is the rule this package
// deliberately did NOT borrow, and the test says why: parseServer cuts the path
// off first, because a proxy list entry has no path. A script address is a URL
// where the path is the point.
func TestWithoutCredentialsReadsAURLAndNotAProxyListEntry(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		carried bool
	}{
		{"http://pac.example/proxy.pac", "http://pac.example/proxy.pac", false},
		{"http://bob:hunter2@pac.example/proxy.pac", "http://pac.example/proxy.pac", true},
		{"http://bob@pac.example/proxy.pac", "http://pac.example/proxy.pac", true},
		// An empty userinfo is a badly written address rather than a secret -
		// the same reading parseServer makes of the same character.
		{"http://@pac.example/proxy.pac", "http://pac.example/proxy.pac", false},
		// THE PATH SURVIVES, which is the whole difference from a list entry.
		{"http://pac.example/a/b/proxy.pac?v=2", "http://pac.example/a/b/proxy.pac?v=2", false},
		// AN "@" AFTER THE AUTHORITY IS PATH AND NOT A CREDENTIAL.
		{"http://pac.example/mail@host/proxy.pac", "http://pac.example/mail@host/proxy.pac", false},
		{"http://bob:hunter2@pac.example:8080/x@y.pac", "http://pac.example:8080/x@y.pac", true},
		// AN ADDRESS WITH NO SCHEME AT ALL IS LEFT ALONE. Nothing here decides
		// whether it can be fetched - Target does, and refuses it - so guessing
		// where an authority starts in a string with no "://" would be this
		// function inventing a grammar the caller never promised.
		{"pac.example/proxy.pac", "pac.example/proxy.pac", false},
		{"bob:hunter2@pac.example/proxy.pac", "bob:hunter2@pac.example/proxy.pac", false},
	} {
		got, carried := withoutCredentials(tc.in)
		if got != tc.want {
			t.Errorf("%q came back as %q, want %q", tc.in, got, tc.want)
		}
		if carried != tc.carried {
			t.Errorf("%q reported carried=%v, want %v", tc.in, carried, tc.carried)
		}
	}
}

// TestEveryScriptRowSurvivesTheContract is the cheapest guard here: a row the
// contract refuses takes the whole layer down with it - ADR66.
func TestEveryScriptRowSurvivesTheContract(t *testing.T) {
	for _, answer := range []ScriptAnswer{
		answeredWith("PROXY proxy.example:8080; DIRECT"),
		answeredWith("QUIC quic.example:443"),
		{Fetched: true, Result: pac.Result{Outcome: pac.OutcomeMalformed, Detail: "will not parse"}},
		{Fetched: true, Result: pac.Result{Outcome: pac.OutcomeNoAnswer}},
		{Detail: "the dial failed"},
	} {
		result := askLayer(t, Input{
			Lenses:    lensesOf(silentLens(StackEnvironment)),
			Target:    target,
			Evaluate:  answering(nil, answer),
			ScriptURL: "http://pac.example/proxy.pac",
		})
		for _, finding := range result.Findings {
			if broken := finding.Breach(); broken != "" {
				t.Errorf("a row this layer produced %s", broken)
			}
		}
	}
}

// TestAScriptDoesNotStopTheLayerOnceItIsSettled is the behaviour this slice
// changes. Until a script could be fetched, an address pointing at one left the
// question permanently open, so a machine naming a script could never be told
// anything better than "and this run did not look".
func TestAScriptDoesNotStopTheLayerOnceItIsSettled(t *testing.T) {
	lens := silentLens(StackEnvironment)
	lens.PACURL = "http://wpad.example/proxy.pac"

	result := askLayer(t, Input{
		Lenses:   lensesOf(lens),
		Target:   target,
		Evaluate: answering(nil, answeredWith("DIRECT")),
	})

	if result.Status != status.Pass {
		t.Errorf("a settled script still left the layer at %s / %s: %s", result.Status, result.Reason, result.Detail)
	}
}

// TestDiscoveryStillStopsTheLayerAfterAScriptIsSettled is the half this slice
// does NOT lift, said out loud because ADR90 named both halves together. WPAD is
// on by default on an ordinary Windows machine - measured, OBS108 - and nothing
// here performs it, so PASS there stays out of reach.
func TestDiscoveryStillStopsTheLayerAfterAScriptIsSettled(t *testing.T) {
	lens := namingLens(StackWinINET, "proxy.example:8080")
	lens.PACURL = "http://wpad.example/proxy.pac"
	lens.AutoDetect = On

	result := askLayer(t, Input{
		Lenses:   lensesOf(lens),
		Target:   target,
		Evaluate: answering(nil, answeredWith("DIRECT")),
	})

	if result.Status != status.Warn {
		t.Fatalf("a machine with discovery on answered %s, want warn", result.Status)
	}
	if !strings.Contains(result.Detail, "did not perform") {
		t.Errorf("the verdict does not name the discovery this run did not do: %q", result.Detail)
	}
	// AND IT LEADS WITH WHAT THE SCRIPT DECIDED. A sentence leading with the
	// machine's list while a script overrides it tells somebody the opposite of
	// what happens on their computer.
	if !strings.Contains(result.Detail, "automatic configuration script decides this URL") {
		t.Errorf("the verdict does not lead with the script's answer: %q", result.Detail)
	}
}

// answeringEach is the port for a run with more than one script, keyed by
// address so the two do not have to answer the same way.
func answeringEach(answers map[string]ScriptAnswer) Evaluate {
	return func(_ context.Context, url string) ScriptAnswer {
		return answers[url]
	}
}

// TestOneScriptSettledBesideOneThatIsNotSaysBothThings is the case a single
// script cannot produce: the verdict has to lead with what WAS settled while
// still naming what was not, and the sentence that names the answer has to walk
// past the row that has none rather than stopping at it.
func TestOneScriptSettledBesideOneThatIsNotSaysBothThings(t *testing.T) {
	lens := silentLens(StackWinINET)
	lens.PACURL = "http://wpad.example/answers.pac"

	result := askLayer(t, Input{
		Lenses: lensesOf(lens),
		Target: target,
		Evaluate: answeringEach(map[string]ScriptAnswer{
			// THE OPEN ONE COMES FIRST, and the order is what this test is for:
			// the command line is asked about before the machine, so the sentence
			// naming what was settled has to walk PAST a row with no answer
			// rather than stopping at it.
			"http://pac.example/unreachable.pac": {Detail: "the dial failed"},
			"http://wpad.example/answers.pac":    answeredWith("PROXY proxy.example:8080"),
		}),
		ScriptURL: "http://pac.example/unreachable.pac",
	})

	if result.Status != status.Warn {
		t.Fatalf("one settled script and one open one answered %s / %s: %s",
			result.Status, result.Reason, result.Detail)
	}
	if !strings.Contains(result.Detail, "through a proxy of its own choosing") {
		t.Errorf("the verdict does not lead with what the settled script decided: %q", result.Detail)
	}
	if !strings.Contains(result.Detail, "did not settle") {
		t.Errorf("the verdict does not name the script that stayed open: %q", result.Detail)
	}
}

func hasScriptCaveat(row report.PACScript, phrase string) bool {
	for _, caveat := range row.Caveats {
		if strings.Contains(caveat, phrase) {
			return true
		}
	}
	return false
}
