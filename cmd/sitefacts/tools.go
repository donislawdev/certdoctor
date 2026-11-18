package main

import (
	"fmt"

	"github.com/donislawdev/certdoctor/internal/tool/noproxy"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// toolFacts are the tools as "certdoctor tool" and each tool's --help list
// them, read from the tools' contract.
type toolFacts struct {
	// Categories are the groups the list shows, in its order.
	Categories []string `json:"categories"`
	// ExitCodes are the endings --help names for a tool.
	ExitCodes []toolEnding `json:"exitCodes"`
	List      []toolFact   `json:"list"`
}

// toolOption is a switch as --help prints it.
type toolOption struct {
	// Name is the switch without its dashes.
	Name string `json:"name"`
	// Input is the input a file switch reads, empty for a switch every tool
	// takes. The website translates the two kinds under different keys.
	Input   string `json:"input"`
	Spelled string `json:"spelled"`
	Summary string `json:"summary"`
}

type toolEnding struct {
	Code    int    `json:"code"`
	Meaning string `json:"meaning"`
}

type toolFact struct {
	ID       string      `json:"id"`
	Category string      `json:"category"`
	Title    string      `json:"title"`
	Summary  string      `json:"summary"`
	Inputs   []toolInput `json:"inputs"`
	// Options are its switches, in the order --help lists them.
	Options []toolOption `json:"options"`
}

type toolInput struct {
	Name string `json:"name"`
	// Shape is line, which a terminal takes as a paste and Enter, or bytes,
	// which is piped in or named with a file switch.
	Shape string `json:"shape"`
	// File is the kind of file --help shows the input read from.
	File string `json:"file"`
	// Switch names a file for the input, without its dashes.
	Switch   string `json:"switch"`
	MaxBytes int    `json:"maxBytes"`
}

func collectTools() toolFacts {
	t := toolFacts{Categories: []string{}, ExitCodes: []toolEnding{}, List: []toolFact{}}
	for _, c := range spec.Categories {
		t.Categories = append(t.Categories, string(c))
	}
	for _, e := range spec.Endings {
		t.ExitCodes = append(t.ExitCodes, toolEnding{e.Code, e.Meaning})
	}
	for _, tool := range spec.All {
		fact := toolFact{ID: tool.ID, Category: string(tool.Category), Title: tool.Title, Summary: tool.Summary,
			Inputs: []toolInput{}, Options: []toolOption{}}
		for i, in := range tool.Inputs {
			fact.Inputs = append(fact.Inputs, toolInput{in.Name, string(in.Shape), in.File, tool.FileSwitch(i), in.MaxBytes})
		}
		for _, o := range tool.Options() {
			fact.Options = append(fact.Options, toolOption{o.Name, o.Input, o.Spelled, o.Summary})
		}
		t.List = append(t.List, fact)
	}
	return t
}

// noProxyExamples are the lists and addresses the website asks the NO_PROXY
// tester about: the ways people write an entry, each beside an address it is
// meant to cover, and the two local names. The answers are the tool's, so when
// a program's reading changes in the tool, the website's table changes with it
// - and the test fails until the facts are written again.
var noProxyExamples = []struct{ list, address string }{
	{".example.com", "https://example.com/"},
	{".example.com", "https://api.example.com/"},
	{"example.com", "https://api.example.com/"},
	{"*.example.com", "https://api.example.com/"},
	{"*", "https://api.example.com/"},
	{"example.com:8443", "https://example.com:8443/"},
	{"10.0.0.0/8", "https://10.1.2.3/"},
	{"10.*", "https://10.1.2.3/"},
	{"169.254.169.254", "http://169.254.169.254/"},
	{"localhost", "http://127.0.0.1:8080/"},
	{"127.0.0.1", "http://localhost:8080/"},
	{"example.com", "http://localhost:8080/"},
	{"::1", "http://[::1]:8080/"},
	{"[::1]", "http://[::1]:8080/"},
}

// noProxyExample is the tester's answer about one address under one list.
type noProxyExample struct {
	List    string `json:"list"`
	Address string `json:"address"`
	// Agreement is the status of the tool's one check: PASS when every
	// program answers alike, WARN when they disagree.
	Agreement string           `json:"agreement"`
	Programs  []noProxyProgram `json:"programs"`
}

// noProxyProgram is one program's answer, its ranges of releases together,
// in the order the tool lists them.
type noProxyProgram struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// Answer is direct or proxy when every range of releases answers so, and
	// releases when they answer differently.
	Answer string `json:"answer"`
	// Condition is what the program needs before it reads the list at all,
	// the same for each of its releases, empty when it needs nothing.
	Condition string `json:"condition"`
	// DirectIn and ProxyIn are the releases going each way, as the tool names
	// them, when the answer is releases.
	DirectIn []string `json:"directIn,omitempty"`
	ProxyIn  []string `json:"proxyIn,omitempty"`
}

// askNoProxy asks the tester about every example. A refusal, or a program
// whose releases need different things before they read the list, is an
// error: the website's table has one cell per program and could not say it.
func askNoProxy(examples []struct{ list, address string }) ([]noProxyExample, error) {
	out := []noProxyExample{}
	for _, e := range examples {
		outcome, err := noproxy.Ask([]byte(e.list), []byte(e.address))
		if err != nil {
			return nil, fmt.Errorf("the NO_PROXY tester did not answer %q for %s: %w", e.list, e.address, err)
		}
		data, ok := outcome.Data.(noproxy.Data)
		if !ok || len(outcome.Checks) != 1 {
			return nil, fmt.Errorf("the NO_PROXY tester answered %q for %s in a shape this does not read", e.list, e.address)
		}
		programs, err := byProgram(data.Readings)
		if err != nil {
			return nil, fmt.Errorf("%q for %s: %w", e.list, e.address, err)
		}
		out = append(out, noProxyExample{List: e.list, Address: e.address,
			Agreement: outcome.Checks[0].Status.String(), Programs: programs})
	}
	return out, nil
}

// byProgram joins the readings of one program, keeping the tool's order.
func byProgram(readings []noproxy.Reading) ([]noProxyProgram, error) {
	var out []noProxyProgram
	at := map[string]int{}
	for _, r := range readings {
		condition := ""
		if r.Condition != nil {
			condition = *r.Condition
		}
		i, seen := at[r.Program]
		switch {
		case !seen:
			at[r.Program] = len(out)
			out = append(out, noProxyProgram{Key: r.Program, Name: r.Name, Condition: condition})
			i = len(out) - 1
		case out[i].Condition != condition:
			return nil, fmt.Errorf("the releases of %s need different things before they read the list", r.Name)
		}
		if r.Direct {
			out[i].DirectIn = append(out[i].DirectIn, r.Versions)
		} else {
			out[i].ProxyIn = append(out[i].ProxyIn, r.Versions)
		}
	}
	for i := range out {
		p := &out[i]
		switch {
		case len(p.ProxyIn) == 0:
			p.Answer, p.DirectIn = "direct", nil
		case len(p.DirectIn) == 0:
			p.Answer, p.ProxyIn = "proxy", nil
		default:
			p.Answer = "releases"
		}
	}
	return out, nil
}
