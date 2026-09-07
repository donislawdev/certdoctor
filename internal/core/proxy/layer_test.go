package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// target is the one this file asks about unless a test says otherwise. It is a
// name rather than an address, because an address never matches a suffix rule
// and half the readings below are about suffixes.
var target = Target{Scheme: "https", Host: "api.example.com", Port: "443"}

// lensesOf builds the port from a fixed list, which is what every test here
// hands the layer instead of a machine.
func lensesOf(lenses ...Lens) func(context.Context) []Lens {
	return func(context.Context) []Lens { return lenses }
}

// namingLens is a readable place that names one proxy for everything.
func namingLens(stack Stack, address string) Lens {
	return Lens{
		Stack:   stack,
		Source:  "test",
		Read:    true,
		Servers: []Server{{Address: address}},
	}
}

// silentLens is a readable place that names nothing. It is NOT the zero value,
// which is the distinction the whole type exists for.
func silentLens(stack Stack) Lens {
	return Lens{Stack: stack, Source: "test", Read: true, Servers: []Server{}}
}

// askLayer is named for the layer because bypass_test.go already has an ask()
// for one exception list rule. Two helpers with one name in one package is the
// shape OBS50 measures, and it fails here as a compile error rather than as a
// disarmed mutation entry.
// IT WALKS THE WHOLE LAYER, all three steps, because that is what a caller of
// this package does and a test that stopped at Ask would leave the second seam
// unexercised. What it deliberately does NOT do is widen anything between the
// steps: the allowed set belongs to the entry point, so the tests that care
// about the order of the seams live beside the orchestrator, and these care
// about what the layer says.
func askLayer(t *testing.T, in Input) Result {
	t.Helper()
	ctx := context.Background()
	return Challenge(ctx, in, Ask(ctx, in, Read(ctx, in)))
}

// findingOf returns the row for one place, and fails when there is none - a test
// asserting against a zero body would pass for a layer that emitted no row at
// all.
func findingOf(t *testing.T, result Result, stack Stack) report.ProxyStack {
	t.Helper()
	for _, finding := range result.Findings {
		if finding.ProxyStack != nil && finding.ProxyStack.Stack == stack.String() {
			return *finding.ProxyStack
		}
	}
	t.Fatalf("no row for %s among %d finding(s)", stack, len(result.Findings))
	return report.ProxyStack{}
}

func divergenceOf(result Result) *report.StackDivergence {
	for _, finding := range result.Findings {
		if finding.StackDivergence != nil {
			return finding.StackDivergence
		}
	}
	return nil
}

// TestAMissingPortIsOurDefectAndNotAnAnswerAboutTheMachine pins the direction a
// forgotten wire has to fail in. Reporting "no proxy configured" for a port
// nobody supplied would be this program's own gap printed as a fact about
// somebody's network.
func TestAMissingPortIsOurDefectAndNotAnAnswerAboutTheMachine(t *testing.T) {
	result := askLayer(t, Input{Target: target})

	if result.Status != status.Unknown || result.Reason != status.ReasonProbeError {
		t.Errorf("a missing port answered %s / %s, want unknown / probe_error", result.Status, result.Reason)
	}
	if result.Findings != nil {
		t.Error("a layer that could not look reported a list of findings, which renders as a claim that it did")
	}
	if !strings.Contains(result.Detail, "no way to read") {
		t.Errorf("the detail does not say what was missing: %q", result.Detail)
	}
}

// TestAPortThatNamesNoPlaceAtAllIsAlsoOurDefect is the second half, and it is a
// different failure from the first: the port was supplied and answered with
// nothing. This program always asks at least about its own environment, so an
// empty answer is a miswiring rather than a machine.
func TestAPortThatNamesNoPlaceAtAllIsAlsoOurDefect(t *testing.T) {
	result := askLayer(t, Input{Lenses: lensesOf(), Target: target})

	if result.Status != status.Unknown || result.Reason != status.ReasonProbeError {
		t.Errorf("an empty reading answered %s / %s, want unknown / probe_error", result.Status, result.Reason)
	}
	if !strings.Contains(result.Detail, "naming no place at all") {
		t.Errorf("the detail does not say what came back: %q", result.Detail)
	}
}

// TestAMachineWithNoProxyAnywhereHasNothingToCheck is the ordinary Linux answer
// and it must not be a PASS: this layer establishes that there is no proxying to
// examine, which is not the same as examining proxying and finding it well.
func TestAMachineWithNoProxyAnywhereHasNothingToCheck(t *testing.T) {
	result := askLayer(t, Input{Lenses: lensesOf(silentLens(StackEnvironment)), Target: target})

	if result.Status != status.Unknown || result.Reason != status.ReasonNothingToCheck {
		t.Errorf("a machine with no proxy answered %s / %s, want unknown / nothing_to_check", result.Status, result.Reason)
	}
	if divergenceOf(result) != nil {
		t.Error("one place was read and a class of divergence was still produced - ADR65 says a class needs two")
	}
	row := findingOf(t, result, StackEnvironment)
	if row.Servers == nil {
		t.Error("a place that was read came back with a nil server list, which says it was not read")
	}
	if len(row.Servers) != 0 {
		t.Errorf("a place naming nothing came back with %d server(s)", len(row.Servers))
	}
}

// TestOnePlaceNamingAProxyPassesAndSaysNothingWasCompared is ADR65 in the
// wording rather than only in the class. One place is a complete answer about
// that place and no answer at all about whether this machine is consistent.
func TestOnePlaceNamingAProxyPassesAndSaysNothingWasCompared(t *testing.T) {
	result := askLayer(t, Input{
		Lenses: lensesOf(namingLens(StackEnvironment, "proxy.example:8080")),
		Target: target,
	})

	if result.Status != status.Pass {
		t.Errorf("one place naming a proxy answered %s, want PASS", result.Status)
	}
	if result.Reason != "" {
		t.Errorf("a passing layer carried the reason %q, and only UNKNOWN requires one", result.Reason)
	}
	if !strings.Contains(result.Detail, "nothing to compare") {
		t.Errorf("the detail does not say that nothing was compared: %q", result.Detail)
	}
	if divergenceOf(result) != nil {
		t.Error("a run with one place produced a class of divergence")
	}
	row := findingOf(t, result, StackEnvironment)
	if row.Selected == nil || row.Selected.Address != "proxy.example:8080" {
		t.Errorf("the row does not say which entry applies to this target: %+v", row.Selected)
	}
}

// TestTwoPlacesDisagreeingAboutAProxyWarns is the measured case this layer
// exists for - S14, 2026-09-05: Internet Settings returned a proxy in full while
// WinHTTP said no proxy at all, on one machine, with nothing misconfigured.
func TestTwoPlacesDisagreeingAboutAProxyWarns(t *testing.T) {
	result := askLayer(t, Input{
		Lenses: lensesOf(namingLens(StackWinINET, "proxy.example:8080"), silentLens(StackWinHTTP)),
		Target: target,
	})

	if result.Status != status.Warn {
		t.Errorf("two places disagreeing answered %s, want WARN", result.Status)
	}
	if !strings.Contains(result.Detail, "do not agree") {
		t.Errorf("the detail does not say the places disagree: %q", result.Detail)
	}
	compared := divergenceOf(result)
	if compared == nil {
		t.Fatal("two readable places produced no comparison at all")
	}
	if compared.Class != string(DivergeOneSided) {
		t.Errorf("the class is %q, want one_sided", compared.Class)
	}
	if len(compared.Stacks) != 2 {
		t.Errorf("the comparison names %d place(s): %v", len(compared.Stacks), compared.Stacks)
	}
}

// TestTwoPlacesNamingDifferentProxiesWarns is the other disagreement, and it
// needs its own case because it reaches the grade by a different class.
func TestTwoPlacesNamingDifferentProxiesWarns(t *testing.T) {
	result := askLayer(t, Input{
		Lenses: lensesOf(namingLens(StackWinINET, "a.example:8080"), namingLens(StackWinHTTP, "b.example:8080")),
		Target: target,
	})

	if result.Status != status.Warn {
		t.Errorf("two places naming different proxies answered %s, want WARN", result.Status)
	}
	if compared := divergenceOf(result); compared == nil || compared.Class != string(DivergeConflicting) {
		t.Errorf("the class is %v, want conflicting", compared)
	}
}

// TestTwoPlacesNamingTheSameProxyPasses is the case that must NOT warn, and it
// is here because a layer that warns about everything is a layer people turn
// off.
func TestTwoPlacesNamingTheSameProxyPasses(t *testing.T) {
	result := askLayer(t, Input{
		Lenses: lensesOf(namingLens(StackWinINET, "proxy.example:8080"), namingLens(StackWinHTTP, "proxy.example:8080")),
		Target: target,
	})

	if result.Status != status.Pass {
		t.Errorf("two places agreeing answered %s, want PASS", result.Status)
	}
	if !strings.Contains(result.Detail, "say the same thing") {
		t.Errorf("the detail does not say the places agree: %q", result.Detail)
	}
}

// TestEveryPlaceRefusingToBeReadIsUndeterminedAndNotEmpty pins the direction of
// the worst answer this layer can give. Places that refused have said nothing,
// so reporting no proxy would be our failure to look printed as their
// configuration - inviolable rule 15 read from the other end.
func TestEveryPlaceRefusingToBeReadIsUndeterminedAndNotEmpty(t *testing.T) {
	result := askLayer(t, Input{
		Lenses: lensesOf(
			UnreadableLens(StackWinINET, "test", "the call failed"),
			UnreadableLens(StackWinHTTP, "test", "the call failed"),
		),
		Target: target,
	})

	if result.Status != status.Unknown || result.Reason != status.ReasonUndetermined {
		t.Errorf("two unreadable places answered %s / %s, want unknown / undetermined", result.Status, result.Reason)
	}
	if divergenceOf(result) != nil {
		t.Error("places that could not be read were still compared with each other")
	}
	row := findingOf(t, result, StackWinINET)
	if row.Read {
		t.Error("a place that refused is reported as read")
	}
	if row.Servers != nil {
		t.Error("a place that refused came back with a server list, and nil is what says it was not read")
	}
}

// TestAnAutomaticConfigurationScriptStopsTheLayerShortOfAnAnswer is OBS111 and
// OBS108 in the grade. A place pointing at a script has not named a proxy, and
// saying "no proxy" there would be an answer this run did not establish.
func TestAnAutomaticConfigurationScriptStopsTheLayerShortOfAnAnswer(t *testing.T) {
	lens := silentLens(StackWinINET)
	lens.PACURL = "http://wpad.example/proxy.pac"

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})

	if result.Status != status.Unknown || result.Reason != status.ReasonUndetermined {
		t.Errorf("a place naming only a script answered %s / %s, want unknown / undetermined", result.Status, result.Reason)
	}
	// "DID NOT SETTLE" RATHER THAN "DID NOT FETCH", and the widening is the
	// point rather than a loosening. Until this run could fetch a script there
	// was one way to leave it open; there are now several - unreachable,
	// unparseable, stopped by a ceiling, or answered by asking something this
	// run had nobody to ask - and a sentence naming only the first would be
	// wrong about the other four.
	if !strings.Contains(result.Detail, "did not settle") {
		t.Errorf("the detail does not say the script was left unsettled: %q", result.Detail)
	}
	row := findingOf(t, result, StackWinINET)
	if row.PACURL != "http://wpad.example/proxy.pac" {
		t.Errorf("the row does not carry the script address: %q", row.PACURL)
	}
	if !hasCaveatAbout(row, "not proof") {
		t.Errorf("the row names a script without the caveat that naming one proves nothing: %v", row.Caveats)
	}
}

// TestDiscoveryBeingOnStopsTheLayerShortOfAnAnswer is the stock Windows machine
// - measured, fAutoDetect comes back set where the registry value does not exist
// at all - and it is the reason this layer answers UNKNOWN there rather than
// "no proxy".
func TestDiscoveryBeingOnStopsTheLayerShortOfAnAnswer(t *testing.T) {
	lens := silentLens(StackWinINET)
	lens.AutoDetect = On

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})

	if result.Status != status.Unknown || result.Reason != status.ReasonUndetermined {
		t.Errorf("a place with discovery on answered %s / %s, want unknown / undetermined", result.Status, result.Reason)
	}
	if !strings.Contains(result.Detail, "did not perform") {
		t.Errorf("the detail does not say the discovery was not performed: %q", result.Detail)
	}
	row := findingOf(t, result, StackWinINET)
	if row.AutoDetect != report.DeterminedTrue {
		t.Errorf("the row reports discovery as %v, want determined true", row.AutoDetect)
	}
}

// TestBothOfThemUnresolvedIsSaidInOneSentence exists because the three arms of
// that sentence are three different answers and the middle one is the easiest to
// leave unwritten.
func TestBothOfThemUnresolvedIsSaidInOneSentence(t *testing.T) {
	lens := silentLens(StackWinINET)
	lens.PACURL = "http://wpad.example/proxy.pac"
	lens.AutoDetect = On

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})

	if !strings.Contains(result.Detail, "both") {
		t.Errorf("a run with a script AND discovery does not say both: %q", result.Detail)
	}
	row := findingOf(t, result, StackWinINET)
	if len(row.Caveats) != 2 {
		t.Errorf("a row with two things left open carries %d caveat(s): %v", len(row.Caveats), row.Caveats)
	}
}

// TestANamedProxyBesideDiscoveryWarnsRatherThanPasses is the judgement this
// layer would most easily get wrong in the flattering direction. The proxy is a
// fact; whether it is the WHOLE answer is not, and a PASS would claim it is.
func TestANamedProxyBesideDiscoveryWarnsRatherThanPasses(t *testing.T) {
	lens := namingLens(StackWinINET, "proxy.example:8080")
	lens.AutoDetect = On

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})

	if result.Status != status.Warn {
		t.Errorf("a named proxy beside discovery answered %s, want WARN", result.Status)
	}
	if !strings.Contains(result.Detail, "may not be the whole answer") {
		t.Errorf("the detail does not say the answer may be incomplete: %q", result.Detail)
	}
}

// TestOneExceptionListIsReadTwiceForTheEnvironment is the product: one NO_PROXY,
// two runtimes, two answers. A single boolean here would be true of curl and
// false of .NET on one machine.
func TestOneExceptionListIsReadTwiceForTheEnvironment(t *testing.T) {
	lens := namingLens(StackEnvironment, "proxy.example:8080")
	// A bare suffix: curl excuses api.example.com under it, .NET documents that
	// it does not - "NO_PROXY=example.com will NOT match www.example.com".
	lens.Bypass, lens.BypassSet = "example.com", true

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})
	row := findingOf(t, result, StackEnvironment)

	if len(row.BypassRules) != len(EnvironmentRules) {
		t.Fatalf("the environment list was read under %d rule(s), want %d", len(row.BypassRules), len(EnvironmentRules))
	}
	answers := map[string]bool{}
	for _, rule := range row.BypassRules {
		answers[rule.Rule] = rule.Bypasses
	}
	if !answers[string(RuleNoProxyCurl)] {
		t.Error("curl's reading does not excuse a host under its own suffix, and the source at RuleNoProxyCurl says it does")
	}
	if answers[string(RuleNoProxyDotNet)] {
		t.Error("the .NET reading excuses a subdomain under a bare suffix, and Microsoft documents that it does not")
	}
}

// TestASystemPlaceIsReadUnderItsOwnRuleOnly is the other side of the rule above:
// a place that holds its list under one documented reading gets one answer, not
// two borrowed from somewhere else.
func TestASystemPlaceIsReadUnderItsOwnRuleOnly(t *testing.T) {
	lens := namingLens(StackWinINET, "proxy.example:8080")
	lens.Rule = RuleWinINET
	lens.Bypass, lens.BypassSet = "*.example.com", true

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})
	row := findingOf(t, result, StackWinINET)

	if len(row.BypassRules) != 1 {
		t.Fatalf("a system place was read under %d rule(s), want 1: %v", len(row.BypassRules), row.BypassRules)
	}
	if row.BypassRules[0].Rule != string(RuleWinINET) || !row.BypassRules[0].Bypasses {
		t.Errorf("the reading came out %+v, want wininet excusing this host", row.BypassRules[0])
	}
}

// TestAListHeldUnderNoKnownRuleIsLeftUnreadRatherThanCalledNotExcused pins the
// direction an unknown reading fails in. ErrUnknownRule means a defect here, and
// answering "not excused" would put it in the report as somebody's setting.
func TestAListHeldUnderNoKnownRuleIsLeftUnreadRatherThanCalledNotExcused(t *testing.T) {
	lens := namingLens(StackWinINET, "proxy.example:8080")
	lens.Bypass, lens.BypassSet = "*.example.com", true

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})
	row := findingOf(t, result, StackWinINET)

	if row.BypassRules != nil {
		t.Errorf("a list nobody knows how to read produced %v", row.BypassRules)
	}
	if !row.BypassSet || row.Bypass != "*.example.com" {
		t.Error("the list itself was dropped, and it is what the machine holds whether or not we can read it")
	}
}

// TestAPlaceWithNoListAtAllReadsNothing keeps "no list" apart from "a list
// excusing nothing", which is what BypassSet is for.
func TestAPlaceWithNoListAtAllReadsNothing(t *testing.T) {
	result := askLayer(t, Input{
		Lenses: lensesOf(namingLens(StackEnvironment, "proxy.example:8080")),
		Target: target,
	})
	row := findingOf(t, result, StackEnvironment)

	if row.BypassSet || row.BypassRules != nil {
		t.Errorf("a place holding no list reported one: set=%v rules=%v", row.BypassSet, row.BypassRules)
	}
}

// TestAWindowsListCarryingAPathIsFlaggedAndStillRead is OBS109. Microsoft says
// such an entry invalidates the whole list; we have never measured it, so the
// row says so and the list is still read - claiming an exception does not exist
// where it may is rule 18 broken from the easiest side.
func TestAWindowsListCarryingAPathIsFlaggedAndStillRead(t *testing.T) {
	lens := namingLens(StackWinINET, "proxy.example:8080")
	lens.Rule = RuleWinINET
	lens.Bypass, lens.BypassSet = "https://www.example.com/;*.example.com", true

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})
	row := findingOf(t, result, StackWinINET)

	if !hasCaveatAbout(row, "invalidating the whole list") {
		t.Errorf("a list carrying a path was not flagged: %v", row.Caveats)
	}
	if len(row.BypassRules) != 1 || !row.BypassRules[0].Bypasses {
		t.Errorf("the list stopped being read because of the caveat: %v", row.BypassRules)
	}
}

// TestAPathInAListThisRuleIsNotAboutIsNotFlagged is the other half, and without
// it the flag would be our reading carried somewhere no vendor documented it.
func TestAPathInAListThisRuleIsNotAboutIsNotFlagged(t *testing.T) {
	lens := namingLens(StackEnvironment, "proxy.example:8080")
	lens.Bypass, lens.BypassSet = "https://www.example.com/", true

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})
	row := findingOf(t, result, StackEnvironment)

	if hasCaveatAbout(row, "invalidating the whole list") {
		t.Errorf("a NO_PROXY carrying a path was flagged with a sentence Microsoft wrote about Internet Settings: %v", row.Caveats)
	}
}

// TestTheEntryForThisProtocolWinsOverTheDefault is ServerFor reaching the report,
// and it matters because a row naming the wrong entry is worse than naming none.
func TestTheEntryForThisProtocolWinsOverTheDefault(t *testing.T) {
	lens := Lens{
		Stack: StackWinINET, Source: "test", Read: true,
		Servers: []Server{
			{Address: "default.example:8080"},
			{Protocol: "https", Address: "https.example:8080"},
		},
	}

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})
	row := findingOf(t, result, StackWinINET)

	if row.Selected == nil || row.Selected.Address != "https.example:8080" {
		t.Errorf("the row names %+v for an https target, want the https entry", row.Selected)
	}
	if len(row.Servers) != 2 {
		t.Errorf("the row lists %d server(s), and the whole list is what the machine holds", len(row.Servers))
	}
}

// TestAProxyForAnotherProtocolOnlyLeavesThisTargetWithout is the case a summary
// gets wrong by saying "names a proxy" when none of them applies here.
func TestAProxyForAnotherProtocolOnlyLeavesThisTargetWithout(t *testing.T) {
	lens := Lens{
		Stack: StackWinINET, Source: "test", Read: true,
		Servers: []Server{{Protocol: "ftp", Address: "ftp.example:8080"}},
	}

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})
	row := findingOf(t, result, StackWinINET)

	if row.Selected != nil {
		t.Errorf("an ftp-only list was said to apply to an https target: %+v", row.Selected)
	}
	summary := summaryFor(result, StackWinINET)
	if !strings.Contains(summary, "none applying") {
		t.Errorf("the summary does not say none of them applies: %q", summary)
	}
}

// TestNoSummaryNamesTheProxy is the masking rule from summaryOf turned into a
// guard, and it is here because the leak it prevents was measured on the binary:
// a summary carrying the address printed it in a document stamped redacted,
// beside a body where the same value had become a pseudonym.
func TestNoSummaryNamesTheProxy(t *testing.T) {
	const address = "proxy.corp.internal:8080"
	lens := namingLens(StackEnvironment, address)
	lens.PACURL = "http://wpad.corp.internal/proxy.pac"
	lens.Bypass, lens.BypassSet = "secret.corp.internal", true

	result := askLayer(t, Input{Lenses: lensesOf(lens), Target: target})

	for _, finding := range result.Findings {
		if strings.Contains(finding.Summary, address) {
			t.Errorf("a summary names the proxy, and the rule that masks summaries cannot see a bare host:port: %q", finding.Summary)
		}
		if strings.Contains(finding.Summary, "secret.corp.internal") {
			t.Errorf("a summary carries an entry of the exception list: %q", finding.Summary)
		}
	}
	if strings.Contains(result.Detail, address) {
		t.Errorf("the layer's own sentence names the proxy: %q", result.Detail)
	}
}

// TestATargetWithNoSchemeIsDescribedByItsNameAlone keeps a row from reading
// "://api.example.com", which looks like a defect in the tool.
func TestATargetWithNoSchemeIsDescribedByItsNameAlone(t *testing.T) {
	result := askLayer(t, Input{
		Lenses: lensesOf(namingLens(StackEnvironment, "proxy.example:8080")),
		Target: Target{Host: "api.example.com"},
	})

	summary := summaryFor(result, StackEnvironment)
	if strings.Contains(summary, "://") {
		t.Errorf("a target with no scheme was described with an empty one: %q", summary)
	}
	if !strings.Contains(summary, "api.example.com") {
		t.Errorf("the summary does not name the target at all: %q", summary)
	}
}

// TestTheHostIsComparedInOneSpelling is normalise reaching the layer. A machine
// holding an exception in lower case excuses a target somebody typed in capitals
// - and the comparison has to happen on one spelling or it happens twice.
func TestTheHostIsComparedInOneSpelling(t *testing.T) {
	lens := namingLens(StackEnvironment, "proxy.example:8080")
	lens.Bypass, lens.BypassSet = ".example.com", true

	result := askLayer(t, Input{
		Lenses: lensesOf(lens),
		Target: Target{Scheme: "HTTPS", Host: "API.Example.COM."},
	})
	row := findingOf(t, result, StackEnvironment)

	for _, rule := range row.BypassRules {
		if !rule.Bypasses {
			t.Errorf("%s did not excuse a host that differs from the entry only in case and a trailing dot", rule.Rule)
		}
	}
}

// TestEveryRowThisLayerProducesSurvivesTheContract is the cheapest guard here
// and the one that would catch a body filled in half way. The contract refuses
// several states this layer could reach by a plausible mistake, and a row it
// refuses takes the whole layer down with it - ADR66.
func TestEveryRowThisLayerProducesSurvivesTheContract(t *testing.T) {
	full := namingLens(StackWinINET, "proxy.example:8080")
	full.Rule = RuleWinINET
	full.Bypass, full.BypassSet = "*.example.com;<local>", true
	full.PACURL = "http://wpad.example/proxy.pac"
	full.AutoDetect = On
	full.Detail = "read from the current user's Internet Settings"

	result := askLayer(t, Input{
		Lenses: lensesOf(full, silentLens(StackWinHTTP), UnreadableLens(StackMacSystem, "test", "no such command")),
		Target: target,
	})

	// Three places, one comparison, and the script the first place names. The
	// script row is here BECAUSE the contract refuses more states on it than on
	// any other body in this layer - a script nobody pointed at, one reported
	// unreachable without a reason, one that was fetched and never says what
	// running it came to - and this run reaches it with a nil Evaluate, which is
	// the state that produces the second of those.
	if len(result.Findings) != 5 {
		t.Fatalf("three places, one comparison and one script produced %d finding(s)", len(result.Findings))
	}
	for _, finding := range result.Findings {
		if broken := finding.Breach(); broken != "" {
			t.Errorf("a row this layer produced %s", broken)
		}
	}
}

// TestAnUnreadablePlaceIsLeftOutOfTheComparison is the same rule Compare states,
// checked at the layer because that is where a reader sees the count.
func TestAnUnreadablePlaceIsLeftOutOfTheComparison(t *testing.T) {
	result := askLayer(t, Input{
		Lenses: lensesOf(
			namingLens(StackWinINET, "proxy.example:8080"),
			silentLens(StackWinHTTP),
			UnreadableLens(StackMacSystem, "test", "no such command"),
		),
		Target: target,
	})

	compared := divergenceOf(result)
	if compared == nil {
		t.Fatal("two readable places produced no comparison")
	}
	for _, stack := range compared.Stacks {
		if stack == string(StackMacSystem) {
			t.Error("a place that could not be read was counted among those compared")
		}
	}
}

// TestDiscoveryExplicitlyOffIsNotTheSameAsUnasked is the middle value of the
// three, and it is the one a boolean would have swallowed. A place that HAS the
// setting and has it off has answered; a place that has no such setting has not.
func TestDiscoveryExplicitlyOffIsNotTheSameAsUnasked(t *testing.T) {
	off := namingLens(StackWinINET, "proxy.example:8080")
	off.AutoDetect = Off

	result := askLayer(t, Input{
		Lenses: lensesOf(off, namingLens(StackWinHTTP, "proxy.example:8080")),
		Target: target,
	})

	if result.Status != status.Pass {
		t.Errorf("discovery reported as off answered %s, want PASS - off is an answer", result.Status)
	}
	if got := findingOf(t, result, StackWinINET).AutoDetect; got != report.DeterminedFalse {
		t.Errorf("a place with discovery off reports %v, want determined false", got)
	}
	if got := findingOf(t, result, StackWinHTTP).AutoDetect; got != report.NotDetermined {
		t.Errorf("a place without that setting reports %v, want not determined", got)
	}
}

// TestAPlaceReportedAsReadWithNoListAtAllStaysNil is the nil-versus-empty rule at
// its least comfortable corner.
//
// IT IS A SHAPE NO READER PRODUCES TODAY and the branch is kept anyway, because
// the alternative is a conversion that turns nil into an empty slice - which
// would say "this place was read and names no proxy" about a place that named
// nothing at all. A platform reader added later gets the honest answer for free
// rather than a silent one.
func TestAPlaceReportedAsReadWithNoListAtAllStaysNil(t *testing.T) {
	result := askLayer(t, Input{
		Lenses: lensesOf(Lens{Stack: StackMacSystem, Source: "test", Read: true}),
		Target: target,
	})

	if row := findingOf(t, result, StackMacSystem); row.Servers != nil {
		t.Errorf("a nil list became %v on the way into the report", row.Servers)
	}
}

func hasCaveatAbout(row report.ProxyStack, phrase string) bool {
	for _, caveat := range row.Caveats {
		if strings.Contains(caveat, phrase) {
			return true
		}
	}
	return false
}

func summaryFor(result Result, stack Stack) string {
	for _, finding := range result.Findings {
		if finding.ProxyStack != nil && finding.ProxyStack.Stack == stack.String() {
			return finding.Summary
		}
	}
	return ""
}
