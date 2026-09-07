package report

import (
	"strings"
	"testing"
)

// The prohibitions of the challenge body, one case each.
//
// THE PAIR THIS FILE EXISTS FOR IS A PROXY NOBODY ASKED AGAINST ONE THAT LET THE
// REQUEST THROUGH. They send a person to two different places - "certdoctor did
// not look here" and "this proxy is not your problem" - and a body that let them
// collapse would make L2 wrong in the direction that looks calmest. Both halves
// are checked, because a rule enforced in one direction can be satisfied by a
// function that refuses everything.

// aDemandingProxy is the shape probe S15 measured on the bench 2026-09-07: a
// CONNECT answered 407 with a Basic challenge and a realm.
func aDemandingProxy() ProxyChallenge {
	return ProxyChallenge{
		Endpoint: "172.28.0.128:3129",
		NamedBy:  []string{"pac"},
		Asked:    true,
		Query:    "connect",
		Status:   407,
		Schemes:  []ProxyAuthScheme{{Scheme: "Basic", Realm: "certdoctor testbed proxy"}},
		Caveats:  []string{},
	}
}

// anUnaskedProxy is the other half: an endpoint that is there and a question
// this run declined to put.
func anUnaskedProxy() ProxyChallenge {
	return ProxyChallenge{
		Endpoint: "socks.example:1080",
		NamedBy:  []string{"environment"},
		Detail:   "this entry names a SOCKS proxy, and certdoctor asks this question over HTTP",
		Caveats:  []string{},
	}
}

func TestBothWellFormedChallengesAreAccepted(t *testing.T) {
	for name, challenge := range map[string]ProxyChallenge{
		"one that demanded credentials": aDemandingProxy(),
		"one nobody asked":              anUnaskedProxy(),
		"one that let the request through": {
			Endpoint: "proxy.example:8080", NamedBy: []string{"wininet", "winhttp"},
			Asked: true, Query: "absolute_form", Status: 200,
		},
		"one that demanded and offered nothing": {
			Endpoint: "proxy.example:8080", NamedBy: []string{"environment"},
			Asked: true, Query: "connect", Status: 407,
		},
	} {
		if got := challenge.breach(); got != "" {
			t.Errorf("%s was refused: %q", name, got)
		}
	}
}

func TestAChallengeWithNoEndpointIsRefused(t *testing.T) {
	challenge := aDemandingProxy()
	challenge.Endpoint = ""

	if got := challenge.breach(); !strings.Contains(got, "which proxy answered") {
		t.Errorf("a row naming no proxy was accepted or refused for the wrong reason: %q", got)
	}
}

// TestAChallengeNothingPointedAtIsRefused. An endpoint arrives from a stack or
// from a script, and a row that names neither is a proxy this report cannot say
// where it got.
func TestAChallengeNothingPointedAtIsRefused(t *testing.T) {
	challenge := aDemandingProxy()
	challenge.NamedBy = nil

	if got := challenge.breach(); !strings.Contains(got, "nothing on this machine and no script") {
		t.Errorf("a row nothing pointed at was accepted or refused for the wrong reason: %q", got)
	}
}

func TestAChallengeWithAnEmptyNamerIsRefused(t *testing.T) {
	challenge := aDemandingProxy()
	challenge.NamedBy = []string{"pac", ""}

	if got := challenge.breach(); !strings.Contains(got, "unnamed source") {
		t.Errorf("an empty namer was accepted or refused for the wrong reason: %q", got)
	}
}

// TestAnUnaskedProxyWithNoReasonIsRefused is the sentence this program owes
// about its own gaps. "certdoctor did not ask" without a why is our defect
// wearing a fact's clothes.
func TestAnUnaskedProxyWithNoReasonIsRefused(t *testing.T) {
	challenge := anUnaskedProxy()
	challenge.Detail = ""

	if got := challenge.breach(); !strings.Contains(got, "does not say why") {
		t.Errorf("a silent refusal to ask was accepted or refused for the wrong reason: %q", got)
	}
}

// TestAnUnaskedProxyThatReportsAnAnswerIsRefused is the prohibition this body
// exists for, in the direction that matters. A row saying nothing was asked and
// carrying a status code has collapsed the two states a reader needs kept apart.
func TestAnUnaskedProxyThatReportsAnAnswerIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*ProxyChallenge){
		"a status code":       func(c *ProxyChallenge) { c.Status = 407 },
		"a shape of question": func(c *ProxyChallenge) { c.Query = "connect" },
		"a way of authenticating": func(c *ProxyChallenge) {
			c.Schemes = []ProxyAuthScheme{{Scheme: "Basic"}}
		},
	} {
		challenge := anUnaskedProxy()
		mutate(&challenge)
		if got := challenge.breach(); !strings.Contains(got, "reports what it answered") {
			t.Errorf("a row carrying %s without asking was accepted or refused for the wrong reason: %q", name, got)
		}
	}
}

// TestAnAskedProxyWithNoQuestionIsRefused. Which question was put decides what
// the answer means - a CONNECT to a non-SSL port is refused by proxies that want
// no credentials at all - so a code without its shape is a number nobody can
// read.
func TestAnAskedProxyWithNoQuestionIsRefused(t *testing.T) {
	challenge := aDemandingProxy()
	challenge.Query = ""

	if got := challenge.breach(); !strings.Contains(got, "which question it was asked") {
		t.Errorf("an answer with no question was accepted or refused for the wrong reason: %q", got)
	}
}

func TestAnAskedProxyWithNoStatusIsRefused(t *testing.T) {
	challenge := aDemandingProxy()
	challenge.Status = 0

	if got := challenge.breach(); !strings.Contains(got, "never says what it answered") {
		t.Errorf("an answer with no code was accepted or refused for the wrong reason: %q", got)
	}
}

func TestAWayOfAuthenticatingWithNoNameIsRefused(t *testing.T) {
	challenge := aDemandingProxy()
	challenge.Schemes = []ProxyAuthScheme{{Realm: "corporate"}}

	if got := challenge.breach(); !strings.Contains(got, "no scheme name") {
		t.Errorf("a nameless scheme was accepted or refused for the wrong reason: %q", got)
	}
}

// TestTheChallengeBodyIsReachedThroughTheEnvelope, because every rule above is
// worth nothing if the dispatch never arrives at it - the failure OBS120 named
// one directory over, where four gates went red and none said why.
func TestTheChallengeBodyIsReachedThroughTheEnvelope(t *testing.T) {
	challenge := aDemandingProxy()
	challenge.Status = 0
	finding := Finding{
		Kind:           FindingProxyChallenge,
		Summary:        "a proxy demands credentials",
		Source:         SourceDetected,
		ProxyChallenge: &challenge,
	}

	if got := finding.Breach(); !strings.Contains(got, "never says what it answered") {
		t.Errorf("the envelope did not reach the body's own rules: %q", got)
	}
}
