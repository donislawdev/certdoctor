package report

import (
	"strings"
	"testing"
)

// The prohibitions of the two proxy bodies, one case each.
//
// THE ONE THIS FILE EXISTS FOR IS THE PAIR AT THE TOP OF ProxyStack: a place
// that COULD NOT BE READ and a place that WAS READ AND NAMES NOTHING. They send
// a person to two different places - the first to whatever refused, the second
// to whoever was supposed to configure a proxy - and a body that let them
// collapse would make L2 wrong in the direction that looks calmest. Both halves
// are checked, because a rule enforced in one direction can be satisfied by a
// function that refuses everything.

// aReadPlace is the shape measured on the owner's machine 2026-09-06: the
// environment stack of a run started with HTTPS_PROXY and NO_PROXY set.
func aReadPlace() ProxyStack {
	return ProxyStack{
		Stack:   "environment",
		Read:    true,
		Servers: []ProxyServer{{Protocol: "https", Scheme: "http", Address: "proxy.example:8080"}},
		Selected: &ProxyServer{
			Protocol: "https", Scheme: "http", Address: "proxy.example:8080",
		},
		Bypass:      "localhost,.internal.example",
		BypassSet:   true,
		BypassRules: []ProxyBypassRule{{Rule: "no_proxy_curl", Bypasses: false}},
	}
}

func TestAWellFormedProxyStackIsAccepted(t *testing.T) {
	place := aReadPlace()
	if got := place.breach(); got != "" {
		t.Errorf("a well formed place was refused: %q", got)
	}
}

// A place that was read and names nothing is ORDINARY - it is what every stack
// on a machine without a proxy looks like, and refusing it would empty the
// layer on the commonest machine there is.
func TestAPlaceNamingNoProxyIsAccepted(t *testing.T) {
	place := ProxyStack{Stack: "winhttp", Read: true, Servers: []ProxyServer{}}
	if got := place.breach(); got != "" {
		t.Errorf("a place naming no proxy was refused: %q", got)
	}
}

// A place that could not be read is an ANSWER when it says why.
func TestAnUnreadablePlaceWithAReasonIsAccepted(t *testing.T) {
	place := ProxyStack{Stack: "macos_system", Detail: "scutil is not on this machine"}
	if got := place.breach(); got != "" {
		t.Errorf("an unreadable place carrying a reason was refused: %q", got)
	}
}

func TestAPlaceWithNoNameIsRefused(t *testing.T) {
	place := aReadPlace()
	place.Stack = ""
	requireRefusal(t, place.breach(), "which place")
}

// THE ONE THAT MATTERS MOST. proxy.Lens says a failure without a reason is a
// defect on our side, and this is that sentence enforced on the way out: a row
// saying only "could not be read" leaves a reader with nothing to do next.
func TestAnUnreadablePlaceWithoutAReasonIsRefused(t *testing.T) {
	place := ProxyStack{Stack: "wininet"}
	requireRefusal(t, place.breach(), "does not say why")
}

// A place that refused has said NOTHING, so anything it appears to hold came
// from somewhere else - which is the shape that would turn our own failure to
// look into a fact about somebody's configuration.
func TestAnUnreadablePlaceThatStillReportsContentIsRefused(t *testing.T) {
	for name, damage := range map[string]func(*ProxyStack){
		"servers":      func(p *ProxyStack) { p.Servers = []ProxyServer{} },
		"selected":     func(p *ProxyStack) { p.Selected = &ProxyServer{Address: "proxy.example:8080"} },
		"bypass set":   func(p *ProxyStack) { p.BypassSet = true },
		"bypass text":  func(p *ProxyStack) { p.Bypass = "localhost" },
		"bypass rules": func(p *ProxyStack) { p.BypassRules = []ProxyBypassRule{{Rule: "wininet"}} },
		"pac url":      func(p *ProxyStack) { p.PACURL = "http://wpad.example/proxy.pac" },
		"auto detect":  func(p *ProxyStack) { p.AutoDetect = DeterminedFalse },
	} {
		place := ProxyStack{Stack: "wininet", Detail: "the call failed"}
		damage(&place)
		if got := place.breach(); got == "" {
			t.Errorf("a place that could not be read reported its %s and was accepted", name)
		}
	}
}

// A proxy that applies to this target has to be one of the ones this place
// names. Anything else is a row answering a question about a list it does not
// have.
func TestAnAppliedProxyFromAnEmptyListIsRefused(t *testing.T) {
	place := ProxyStack{
		Stack: "wininet", Read: true,
		Servers:  []ProxyServer{},
		Selected: &ProxyServer{Address: "proxy.example:8080"},
	}
	requireRefusal(t, place.breach(), "listing none")
}

// Reading a list this place does not hold is our arithmetic reported as their
// configuration - the same shape ADR70 took out of L5.
func TestReadingAListThatIsNotThereIsRefused(t *testing.T) {
	place := aReadPlace()
	place.BypassSet = false
	requireRefusal(t, place.breach(), "does not hold")
}

func TestAProxyWithNoAddressIsRefused(t *testing.T) {
	place := aReadPlace()
	place.Servers = []ProxyServer{{Protocol: "https"}}
	place.Selected = nil
	requireRefusal(t, place.breach(), "no address")
}

func TestAReadingThatDoesNotNameItsRuleIsRefused(t *testing.T) {
	place := aReadPlace()
	place.BypassRules = []ProxyBypassRule{{Bypasses: true}}
	requireRefusal(t, place.breach(), "naming the reading")
}

func TestAWellFormedDivergenceIsAccepted(t *testing.T) {
	compared := StackDivergence{Class: "one_sided", Stacks: []string{"wininet", "winhttp"}}
	if got := compared.breach(); got != "" {
		t.Errorf("a well formed comparison was refused: %q", got)
	}
}

func TestADivergenceWithNoClassIsRefused(t *testing.T) {
	compared := StackDivergence{Stacks: []string{"wininet", "winhttp"}}
	requireRefusal(t, compared.breach(), "how they came out")
}

// ADR65 MADE STRUCTURAL. A class is a sentence about a comparison, and one place
// is not a comparison - so a body claiming to be one with fewer than two parties
// is refused here rather than being left to whoever reads the document.
func TestADivergenceOverFewerThanTwoPlacesIsRefused(t *testing.T) {
	for _, stacks := range [][]string{nil, {"wininet"}} {
		compared := StackDivergence{Class: "agree", Stacks: stacks}
		requireRefusal(t, compared.breach(), "needs two")
	}
}

func TestADivergenceCountingAnUnnamedPlaceIsRefused(t *testing.T) {
	compared := StackDivergence{Class: "agree", Stacks: []string{"wininet", ""}}
	requireRefusal(t, compared.breach(), "unnamed place")
}

// TestBothProxyBodiesReachTheUnionRule checks the wiring rather than the rules:
// a body whose breach nothing calls is a set of prohibitions that never runs.
func TestBothProxyBodiesReachTheUnionRule(t *testing.T) {
	place := aReadPlace()
	place.Stack = ""
	finding := Finding{Kind: FindingProxyStack, Summary: "x", Source: SourceDetected, ProxyStack: &place}
	if got := finding.Breach(); got == "" {
		t.Error("a broken proxy place passed the whole finding contract")
	}

	compared := StackDivergence{Class: "agree", Stacks: []string{"wininet"}}
	finding = Finding{Kind: FindingStackDivergence, Summary: "x", Source: SourceDerived, StackDivergence: &compared}
	if got := finding.Breach(); got == "" {
		t.Error("a broken comparison passed the whole finding contract")
	}
}

// requireRefusal asks that the refusal NAMES what it refused. A validator that
// answers "no" without saying what is wrong is satisfied by one that refuses
// everything - OBS56, measured twice in this tree.
func requireRefusal(t *testing.T, said, phrase string) {
	t.Helper()
	if said == "" {
		t.Fatalf("the body was accepted, and it should have been refused for %q", phrase)
	}
	if !strings.Contains(said, phrase) {
		t.Errorf("the refusal reads %q and does not name %q", said, phrase)
	}
}
