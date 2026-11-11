package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestAnExpressionIsReadWithTheOrderOfItsOperators(t *testing.T) {
	for _, c := range []struct {
		text, written string
		terms         []string
		licences      []string
		exceptions    []string
	}{
		{"MIT", "MIT", []string{"MIT"}, []string{"MIT"}, nil},
		{"MIT AND BSD-3-Clause AND MIT", "MIT AND BSD-3-Clause AND MIT", []string{"MIT", "BSD-3-Clause"},
			[]string{"MIT", "BSD-3-Clause"}, nil},
		{"Unlicense OR BSD-3-Clause", "Unlicense OR BSD-3-Clause", []string{"Unlicense OR BSD-3-Clause"},
			[]string{"Unlicense", "BSD-3-Clause"}, nil},
		{"(Unlicense OR BSD-3-Clause) AND MIT", "(Unlicense OR BSD-3-Clause) AND MIT",
			[]string{"Unlicense OR BSD-3-Clause", "MIT"}, []string{"Unlicense", "BSD-3-Clause", "MIT"}, nil},
		// AND binds tighter than OR, so this is a choice between two, not three.
		{"MIT AND ISC OR Zlib", "(MIT AND ISC) OR Zlib", []string{"(MIT AND ISC) OR Zlib"}, []string{"MIT", "ISC", "Zlib"}, nil},
		{"MIT AND Apache-2.0 WITH LLVM-exception", "MIT AND Apache-2.0 WITH LLVM-exception",
			[]string{"MIT", "Apache-2.0 WITH LLVM-exception"}, []string{"MIT", "Apache-2.0"}, []string{"LLVM-exception"}},
		// A group of the same operator is one group, and brackets around one
		// licence say nothing.
		{"MIT AND (ISC AND (Zlib))", "MIT AND ISC AND Zlib", []string{"MIT", "ISC", "Zlib"}, []string{"MIT", "ISC", "Zlib"}, nil},
		{"(MIT OR ISC) OR (Zlib OR MIT)", "MIT OR ISC OR Zlib OR MIT", []string{"MIT OR ISC OR Zlib OR MIT"},
			[]string{"MIT", "ISC", "Zlib"}, nil},
	} {
		e, err := parseExpression(c.text)
		if err != nil {
			t.Errorf("%q: %v", c.text, err)
			continue
		}
		if got := e.String(); got != c.written {
			t.Errorf("%q is written %q, want %q", c.text, got, c.written)
		}
		for what, pair := range map[string][2][]string{
			"terms":      {e.terms(), c.terms},
			"licences":   {e.licences(), c.licences},
			"exceptions": {e.exceptions(), c.exceptions},
		} {
			if !reflect.DeepEqual(pair[0], pair[1]) {
				t.Errorf("%q has the %s %q, want %q", c.text, what, pair[0], pair[1])
			}
		}
	}
}

func TestAnExpressionThatSaysNothingWholeIsRefused(t *testing.T) {
	for text, want := range map[string]string{
		"":                  "ends where a licence should follow",
		"MIT AND":           "ends where a licence should follow",
		"(MIT":              "a bracket is opened and never closed",
		"MIT )":             `")" follows a complete expression`,
		"MIT ISC":           `"ISC" follows a complete expression`,
		"AND MIT":           `"AND" stands where a licence should`,
		"MIT WITH":          "WITH after MIT is not followed by an exception",
		"MIT WITH OR":       "WITH after MIT is not followed by an exception",
		"(MIT OR ISC) WITH": `"WITH" follows a complete expression`,
	} {
		if _, err := parseExpression(text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want one saying %q", text, err, want)
		}
	}
}

// Terms that all apply are joined by AND, and a term that offers a choice keeps
// the choice inside brackets - otherwise "A OR B AND C" would read as a choice
// between A and both of the others.
func TestTermsAreJoinedSoThatAChoiceStaysAChoice(t *testing.T) {
	for _, c := range []struct {
		terms []string
		want  string
	}{
		{[]string{"Unlicense OR BSD-3-Clause"}, "Unlicense OR BSD-3-Clause"},
		{[]string{"Unlicense OR BSD-3-Clause", "MIT"}, "(Unlicense OR BSD-3-Clause) AND MIT"},
		{[]string{"(MIT AND ISC) OR Zlib", "MIT"}, "((MIT AND ISC) OR Zlib) AND MIT"},
		{[]string{"Apache-2.0 WITH LLVM-exception", "MIT"}, "Apache-2.0 WITH LLVM-exception AND MIT"},
	} {
		if got := joinTerms(c.terms); got != c.want {
			t.Errorf("%q joined as %q, want %q", c.terms, got, c.want)
		}
	}
}
