package report

import (
	"strings"
	"testing"
)

// The prohibitions of the script body, one case each.
//
// THE PAIR THIS FILE EXISTS FOR IS A SCRIPT NOBODY FETCHED AGAINST ONE THAT WAS
// FETCHED AND ANSWERED BADLY. They send a person to two different places - a web
// server nobody can reach, and a file whose contents are wrong - and a body that
// let them collapse would make L2 wrong in the direction that looks calmest.
// Both halves are checked, because a rule enforced in one direction can be
// satisfied by a function that refuses everything.

// anAnsweringScript is the shape measured on the owner's machine 2026-09-06,
// running testbed/pac/files/proxy.pac against a name the file proxies.
func anAnsweringScript() PACScript {
	return PACScript{
		URL:        "http://wpad.example/proxy.pac",
		NamedBy:    []string{"wininet"},
		Fetched:    true,
		Outcome:    "answered",
		Answer:     "PROXY proxy.example:8080; DIRECT",
		Directives: []PACDirective{{Kind: "PROXY", Endpoint: "proxy.example:8080", Recognised: true}, {Kind: "DIRECT", Recognised: true}},
		Selected:   &PACDirective{Kind: "PROXY", Endpoint: "proxy.example:8080", Recognised: true},
		Caveats:    []string{},
	}
}

// anUnfetchedScript is the other half: an address that is there and a server
// that is not.
func anUnfetchedScript() PACScript {
	return PACScript{
		URL:     "http://wpad.example/proxy.pac",
		NamedBy: []string{"wininet", "winhttp"},
		Detail:  "the automatic configuration script could not be fetched: the dial failed",
		Caveats: []string{},
	}
}

func TestBothWellFormedScriptsAreAccepted(t *testing.T) {
	for name, script := range map[string]PACScript{
		"one that answered":  anAnsweringScript(),
		"one nobody fetched": anUnfetchedScript(),
		"one that would not parse": {
			URL: "http://wpad.example/proxy.pac", NamedBy: []string{"command_line"},
			Fetched: true, Outcome: "malformed", Detail: "the PAC file could not be loaded",
		},
	} {
		if got := script.breach(); got != "" {
			t.Errorf("%s was refused: %q", name, got)
		}
	}
}

func TestAScriptWithNoAddressIsRefused(t *testing.T) {
	script := anAnsweringScript()
	script.URL = ""
	if got := script.breach(); !strings.Contains(got, "where the script was") {
		t.Errorf("a script with no address was answered with %q", got)
	}
}

// TestAScriptNobodyPointedAtIsRefused is the row's own reason to exist. Every
// script in a report got there because something named it - a place on the
// machine, or the user - and a row that cannot say which is a row nobody can act
// on.
func TestAScriptNobodyPointedAtIsRefused(t *testing.T) {
	script := anAnsweringScript()
	script.NamedBy = nil
	if got := script.breach(); !strings.Contains(got, "nothing on this machine and nobody pointed at") {
		t.Errorf("a script nobody named was answered with %q", got)
	}

	script.NamedBy = []string{""}
	if got := script.breach(); !strings.Contains(got, "unnamed source") {
		t.Errorf("a script named by nothing in particular was answered with %q", got)
	}
}

// TestAScriptNobodyFetchedMustSayWhy is the sentence proxy.ScriptAnswer states
// and this contract enforces: a failure with no reason is a defect here rather
// than an answer about somebody's machine.
func TestAScriptNobodyFetchedMustSayWhy(t *testing.T) {
	script := anUnfetchedScript()
	script.Detail = ""
	if got := script.breach(); !strings.Contains(got, "does not say why") {
		t.Errorf("an unfetched script with no reason was answered with %q", got)
	}
}

// TestAScriptNobodyFetchedMayNotReportWhatItSaid is the collapse this body
// exists to prevent, checked field by field because any one of them alone would
// make the row read as a file that answered.
func TestAScriptNobodyFetchedMayNotReportWhatItSaid(t *testing.T) {
	for name, fill := range map[string]func(*PACScript){
		"an outcome":     func(p *PACScript) { p.Outcome = "answered" },
		"an answer":      func(p *PACScript) { p.Answer = "DIRECT" },
		"its entries":    func(p *PACScript) { p.Directives = []PACDirective{{Kind: "DIRECT", Recognised: true}} },
		"a chosen entry": func(p *PACScript) { p.Selected = &PACDirective{Kind: "DIRECT", Recognised: true} },
	} {
		script := anUnfetchedScript()
		fill(&script)
		if got := script.breach(); !strings.Contains(got, "reports what it said") {
			t.Errorf("an unfetched script carrying %s was answered with %q", name, got)
		}
	}
}

// TestAFetchedScriptMustSayWhatRunningItCameTo is the other direction of the
// same pair: bytes that arrived were handed to the evaluator, and the evaluator
// always says something.
func TestAFetchedScriptMustSayWhatRunningItCameTo(t *testing.T) {
	script := anAnsweringScript()
	script.Outcome = ""
	if got := script.breach(); !strings.Contains(got, "never says what running it came to") {
		t.Errorf("a fetched script with no outcome was answered with %q", got)
	}
}

func TestAChosenEntryNeedsEntriesToHaveBeenChosenFrom(t *testing.T) {
	script := anAnsweringScript()
	script.Directives = nil
	if got := script.breach(); !strings.Contains(got, "listing no entries at all") {
		t.Errorf("a chosen entry with no list was answered with %q", got)
	}
}

// TestAnEntryWithNoKeywordIsRefused keeps inviolable rule 15's other half
// honest. An unrecognised keyword is CARRIED rather than dropped - but an entry
// with no keyword at all is not something a file said, it is something this
// program failed to read and then reported as a fact.
func TestAnEntryWithNoKeywordIsRefused(t *testing.T) {
	script := anAnsweringScript()
	script.Directives = append(script.Directives, PACDirective{Endpoint: "proxy.example:1"})
	if got := script.breach(); !strings.Contains(got, "no keyword") {
		t.Errorf("an entry with no keyword was answered with %q", got)
	}
}

// TestAnUnrecognisedKeywordIsStillAcceptedIsTheOtherSide. A rule refusing
// everything would pass every test above while making the contract useless, and
// this is the case most likely to be refused by accident.
func TestAnUnrecognisedKeywordIsStillAccepted(t *testing.T) {
	script := anAnsweringScript()
	script.Directives = []PACDirective{{Kind: "QUIC", Endpoint: "quic.example:443"}}
	script.Selected = nil
	if got := script.breach(); got != "" {
		t.Errorf("a script naming a keyword certdoctor does not know was refused: %q", got)
	}
}

// TestAScriptBodyReachesTheUnionRule checks the wiring rather than the rules: a
// body whose kind and field disagree is refused by the envelope, and a kind
// added without a place in that map would be a body nothing validates.
func TestAScriptBodyReachesTheUnionRule(t *testing.T) {
	script := anAnsweringScript()
	finding := Finding{Kind: FindingPACScript, Summary: "a script answered", Source: SourceDetected, PACScript: &script}
	if got := finding.Breach(); got != "" {
		t.Errorf("a well formed script finding was refused: %q", got)
	}

	finding.PACScript = nil
	if got := finding.Breach(); got == "" {
		t.Error("a finding calling itself a script and carrying no script body was accepted")
	}

	broken := anAnsweringScript()
	broken.URL = ""
	finding.PACScript = &broken
	if got := finding.Breach(); !strings.Contains(got, "where the script was") {
		t.Errorf("the envelope did not reach the body's own rule: %q", got)
	}
}
