package main

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/tool/noproxy"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// TestEveryToolIsInTheFacts holds the website's list of tools to the tools'
// contract, so a page cannot name a tool the program does not have, or miss
// one it has.
func TestEveryToolIsInTheFacts(t *testing.T) {
	got := collectTools()
	if len(got.List) != len(spec.All) {
		t.Fatalf("the facts list %d tools and the program has %d", len(got.List), len(spec.All))
	}
	for i, tool := range spec.All {
		fact := got.List[i]
		if fact.ID != tool.ID || fact.Title != tool.Title || len(fact.Inputs) != len(tool.Inputs) {
			t.Errorf("tool %d is %s %q in the facts and %s %q in the program", i, fact.ID, fact.Title, tool.ID, tool.Title)
			continue
		}
		for j := range tool.Inputs {
			if fact.Inputs[j].Switch != tool.FileSwitch(j) {
				t.Errorf("%s input %d is read with --%s in the facts and --%s by the program", tool.ID, j,
					fact.Inputs[j].Switch, tool.FileSwitch(j))
			}
		}
		if len(fact.Options) != len(tool.Options()) || fact.Options[0].Spelled != "--"+tool.FileSwitch(0)+" <path>" {
			t.Errorf("%s has switches in the facts that its --help does not list: %+v", tool.ID, fact.Options)
		}
	}
	if len(got.ExitCodes) != len(spec.Endings) {
		t.Error("the facts do not carry every exit code a tool ends with")
	}
}

// TestTheNoProxyTableComesFromTheTester checks one answer of the table against
// the tester asked directly: Go does not take ".example.com" to cover
// example.com itself, and curl does - the case the table is there to show.
// Without this, a table of the right shape with every cell the same would pass.
func TestTheNoProxyTableComesFromTheTester(t *testing.T) {
	examples, err := askNoProxy(noProxyExamples[:1])
	if err != nil {
		t.Fatal(err)
	}
	answers := map[string]string{}
	for _, p := range examples[0].Programs {
		answers[p.Key] = p.Answer
	}
	if answers["go"] != "proxy" || answers["curl"] != "direct" || examples[0].Agreement != "WARN" {
		t.Errorf(".example.com for https://example.com/ reads go=%s curl=%s agreement=%s, and the tester says "+
			"proxy, direct and WARN", answers["go"], answers["curl"], examples[0].Agreement)
	}
}

// TestAReleaseThatAnswersDifferentlyIsSaid covers the third answer: a program
// whose releases disagree is not given the answer of its first one.
func TestAReleaseThatAnswersDifferentlyIsSaid(t *testing.T) {
	programs, err := byProgram([]noproxy.Reading{
		{Program: "node_fetch", Name: "Node.js fetch", Versions: "old", Direct: false, Basis: "no_entry"},
		{Program: "node_fetch", Name: "Node.js fetch", Versions: "new", Direct: true, Basis: "entry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := programs[0]
	if len(programs) != 1 || p.Answer != "releases" || strings.Join(p.DirectIn, ",") != "new" ||
		strings.Join(p.ProxyIn, ",") != "old" {
		t.Errorf("two releases answering differently came out as %+v", programs)
	}
}

// TestWhatTheTableCannotSayIsRefused: a program whose releases need different
// things before they read the list, and a list the tester refuses, stop the
// generator rather than leave a cell that says less than the tool.
func TestWhatTheTableCannotSayIsRefused(t *testing.T) {
	on, off := "NODE_USE_ENV_PROXY=1", ""
	_, err := byProgram([]noproxy.Reading{
		{Program: "node_http", Name: "Node.js http", Versions: "a", Condition: &on},
		{Program: "node_http", Name: "Node.js http", Versions: "b", Condition: &off},
	})
	if err == nil || !strings.Contains(err.Error(), "need different things") {
		t.Errorf("releases with different conditions were joined: %v", err)
	}
	if _, err := askNoProxy([]struct{ list, address string }{{"example.com", ""}}); err == nil {
		t.Error("an example without an address was answered")
	}
}
