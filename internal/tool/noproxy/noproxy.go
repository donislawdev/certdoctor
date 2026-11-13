// Package noproxy is the NO_PROXY tester (ADR147): it says which programs go to
// an address through the proxy and which go directly, under one list, because
// each program that reads NO_PROXY reads it its own way.
//
// THE READINGS ARE NOT HERE. They are the diagnosis's, in internal/core/proxy,
// each written from the program's own code with its source beside it, and this
// package is the one part of the tools allowed to ask them (ADR147 decision 1)
// - so the tool and L2 cannot answer the same list two ways.
//
// IT READS NO ENVIRONMENT AND CONNECTS TO NOTHING. The list is the one it is
// handed, never this machine's NO_PROXY, and the address is never resolved or
// opened (ADR141, inviolable rule 16).
package noproxy

import (
	"fmt"

	"github.com/donislawdev/certdoctor/internal/core/proxy"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// Data is what the tester found, for a script to read.
type Data struct {
	Address Address `json:"address"`
	// Readings are the programs' answers, one for every range of releases whose
	// code reads the list the same way, in the order of proxy.NoProxyRules.
	Readings []Reading `json:"readings"`
}

// Address is the address as read: the three parts a program hands its reading
// of NO_PROXY.
type Address struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	// Port is the port the address named, null when it named none - a program
	// that compares an entry's port fills in the scheme's default itself, and
	// Python's compares only a port the address wrote.
	Port *int `json:"port"`
}

// Reading is one program's answer.
type Reading struct {
	// Program is the program's key - curl, dotnet, go, python, requests,
	// node_http, node_fetch - the same for each of its ranges of releases.
	Program string `json:"program"`
	// Name is the program as a person calls it.
	Name     string `json:"name"`
	Versions string `json:"versions"`
	// Condition is what the program needs before it reads the list at all,
	// null when it reads it whenever it has a proxy.
	Condition *string `json:"condition"`
	// Direct is true when the program goes to the address without the proxy.
	Direct bool `json:"direct"`
	// Entry is the part of the list that sent it direct, as the program cut it
	// out, null when none did.
	Entry *string `json:"entry"`
	// Basis is what the answer rests on: entry, whole_value, local or no_entry.
	Basis string `json:"basis"`
}

// Ask reads list and address and asks every reading of NO_PROXY about them. A
// refusal is a *spec.Refusal and means one of the two is not something every
// program would read the same way.
func Ask(list, address []byte) (spec.Outcome, error) {
	l, listNotes, err := readList(list)
	if err != nil {
		return spec.Outcome{}, err
	}
	a, addressNotes, err := readAddress(address)
	if err != nil {
		return spec.Outcome{}, err
	}
	answers := make([]answer, 0, len(proxy.NoProxyRules))
	for _, r := range proxy.NoProxyRules {
		d, err := proxy.Decide(r, l, a.target)
		if err != nil {
			// Both inputs were held to what every reading answers for, so an
			// error here is a defect on this side, never a property of the input.
			return spec.Outcome{}, fmt.Errorf("the reading %s did not answer: %w", r, err)
		}
		answers = append(answers, answer{rule: r, decision: d})
	}
	asked := asked{address: a, answers: answers}
	return spec.Outcome{
		Notes:  append(listNotes, addressNotes...),
		Checks: []spec.Check{asked.agreement()},
		Data:   asked.data(),
		View:   asked.view(),
	}, nil
}

// answer is one reading's answer.
type answer struct {
	rule     proxy.Rule
	decision proxy.Decision
}

// asked is the address and every answer about it.
type asked struct {
	address address
	answers []answer
}

// data is what was found, for a script.
func (a asked) data() Data {
	d := Data{
		Address:  Address{Scheme: a.address.target.Scheme, Host: a.address.target.Host},
		Readings: []Reading{},
	}
	if a.address.port != 0 {
		port := a.address.port
		d.Address.Port = &port
	}
	for _, x := range a.answers {
		d.Readings = append(d.Readings, Reading{
			Program:   x.rule.ProgramKey(),
			Name:      x.rule.Program(),
			Versions:  x.rule.Versions(),
			Condition: orNull(x.rule.Condition()),
			Direct:    x.decision.Direct,
			Entry:     orNull(x.decision.Entry),
			Basis:     string(x.decision.Basis),
		})
	}
	return d
}

func orNull(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
