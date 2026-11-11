package main

import (
	"fmt"
	"strings"
)

// A licenceExpr is how a section of the notices names the licences of what it
// quotes: identifiers joined by AND and OR, an exception after WITH, and
// brackets where the grouping needs them - the grammar of SPDX 2.3, annex D,
// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/ read
// 2026-11-11. WITH binds tightest, then AND, then OR.
//
// The notices of the command line only ever join identifiers with AND. The
// window's need the rest: a module that offers a choice of two licences
// (Unlicense OR BSD-3-Clause), and a library under Apache-2.0 with the LLVM
// exception.
type licenceExpr struct {
	op   string        // "AND" or "OR" for a group, "" for one licence
	id   string        // the licence, when op is ""
	with string        // its exception, when it has one
	args []licenceExpr // the group's members, never a group of the same op
}

// parseExpression reads one expression, and refuses rather than guesses: a
// bracket left open, an operator with nothing after it, or a word after a
// complete expression are each a section that says something other than what
// it was meant to.
func parseExpression(text string) (licenceExpr, error) {
	text = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(text)
	p := exprParser{tokens: strings.Fields(text)}
	e, err := p.or()
	if err != nil {
		return licenceExpr{}, err
	}
	if rest := p.next(); rest != "" {
		return licenceExpr{}, fmt.Errorf("%q follows a complete expression", rest)
	}
	return e, nil
}

type exprParser struct {
	tokens []string
	at     int
}

func (p *exprParser) peek() string {
	if p.at < len(p.tokens) {
		return p.tokens[p.at]
	}
	return ""
}

func (p *exprParser) next() string {
	token := p.peek()
	if token != "" {
		p.at++
	}
	return token
}

func (p *exprParser) or() (licenceExpr, error) {
	return p.group("OR", p.and)
}

func (p *exprParser) and() (licenceExpr, error) {
	return p.group("AND", p.term)
}

// group reads members joined by op, each read by member, and flattens a member
// that is itself a group of op - A AND (B AND C) names three licences.
func (p *exprParser) group(op string, member func() (licenceExpr, error)) (licenceExpr, error) {
	first, err := member()
	if err != nil {
		return licenceExpr{}, err
	}
	members := []licenceExpr{first}
	for p.peek() == op {
		p.next()
		m, err := member()
		if err != nil {
			return licenceExpr{}, err
		}
		members = append(members, m)
	}
	if len(members) == 1 {
		return first, nil
	}
	group := licenceExpr{op: op}
	for _, m := range members {
		if m.op == op {
			group.args = append(group.args, m.args...)
			continue
		}
		group.args = append(group.args, m)
	}
	return group, nil
}

func (p *exprParser) term() (licenceExpr, error) {
	token := p.next()
	switch token {
	case "":
		return licenceExpr{}, fmt.Errorf("it ends where a licence should follow")
	case "(":
		inner, err := p.or()
		if err != nil {
			return licenceExpr{}, err
		}
		if p.next() != ")" {
			return licenceExpr{}, fmt.Errorf("a bracket is opened and never closed")
		}
		return inner, nil
	case ")", "AND", "OR", "WITH":
		return licenceExpr{}, fmt.Errorf("%q stands where a licence should", token)
	}
	leaf := licenceExpr{id: token}
	if p.peek() == "WITH" {
		p.next()
		exception := p.next()
		switch exception {
		case "", "(", ")", "AND", "OR", "WITH":
			return licenceExpr{}, fmt.Errorf("WITH after %s is not followed by an exception", token)
		}
		leaf.with = exception
	}
	return leaf, nil
}

// String is the expression as a document carries it. A group inside another
// is always bracketed, even where the order of the operators would not need
// it, because a reader should not have to know that order to read it right.
func (e licenceExpr) String() string {
	if e.op == "" {
		if e.with != "" {
			return e.id + " WITH " + e.with
		}
		return e.id
	}
	parts := make([]string, 0, len(e.args))
	for _, a := range e.args {
		s := a.String()
		if a.op != "" {
			s = "(" + s + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " "+e.op+" ")
}

// terms are what the expression requires all of: the members of a top level
// AND, or the whole expression when it is anything else. Each is written once,
// in the order it first appears - the notices name a licence once for every
// text quoted under it, so a section quoting two texts under one licence names
// it twice, and a document says it once.
func (e licenceExpr) terms() []string {
	members := []licenceExpr{e}
	if e.op == "AND" {
		members = e.args
	}
	var out []string
	for _, m := range members {
		out = appendNew(out, m.String())
	}
	return out
}

// licences and exceptions are every identifier the expression names, each
// once, in the order they appear.
func (e licenceExpr) licences() []string {
	if e.op == "" {
		return []string{e.id}
	}
	var out []string
	for _, a := range e.args {
		for _, id := range a.licences() {
			out = appendNew(out, id)
		}
	}
	return out
}

func (e licenceExpr) exceptions() []string {
	if e.op == "" {
		if e.with == "" {
			return nil
		}
		return []string{e.with}
	}
	var out []string
	for _, a := range e.args {
		for _, id := range a.exceptions() {
			out = appendNew(out, id)
		}
	}
	return out
}

// joinTerms is terms that all apply, as one expression: joined by AND, with a
// term that offers a choice bracketed so the choice stays inside it.
func joinTerms(terms []string) string {
	if len(terms) == 1 {
		return terms[0]
	}
	parts := make([]string, 0, len(terms))
	for _, t := range terms {
		// A term is one licence, perhaps with an exception, or a choice: a
		// group of AND inside an AND is flattened into it. So a term with OR in
		// it is a choice, whether its own members are bracketed or not.
		if strings.Contains(t, " OR ") {
			t = "(" + t + ")"
		}
		parts = append(parts, t)
	}
	return strings.Join(parts, " AND ")
}

func appendNew(list []string, s string) []string {
	if contains(list, s) {
		return list
	}
	return append(list, s)
}
