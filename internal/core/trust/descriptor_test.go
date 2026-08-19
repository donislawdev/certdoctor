package trust

import (
	"strings"
	"testing"
)

// THE REGISTRY TEST IS INVIOLABLE RULE 18 MADE MACHINE-CHECKABLE. Every claim
// this program makes about somebody else's runtime has to carry its source, and
// docs/20 says plainly that this rule is the one this project would break first
// and most expensively. A descriptor missing its source does not get to exist.
func TestEveryDescriptorCarriesItsSource(t *testing.T) {
	if len(All()) == 0 {
		t.Fatal("the registry is empty, so this test proves nothing about anything")
	}
	seen := map[string]bool{}
	for _, d := range All() {
		if breach := d.Breach(); breach != "" {
			t.Errorf("descriptor %q %s", d.ID, breach)
		}
		if seen[d.ID] {
			t.Errorf("two descriptors answer to %q, and an id is an identity", d.ID)
		}
		seen[d.ID] = true
	}
}

// All hands out a copy. Without that a caller could edit the registry underneath
// everybody else, and the evidence rule would be enforceable only until somebody
// wrote to the slice.
func TestTheRegistryCannotBeEditedThroughWhatItHandsOut(t *testing.T) {
	first := All()
	first[0].Evidence = ""
	if All()[0].Evidence == "" {
		t.Error("editing the returned slice changed the registry")
	}
}

func TestTheDescriptorRefusesWhatItMustRefuse(t *testing.T) {
	sound := Descriptor{
		ID: "git", Runtime: "git", TrustSource: "a bundle",
		Source: Measured, Evidence: "measured here",
		FixSource: Documentation, FixEvidence: "the vendor says so, at a link",
	}
	if breach := sound.Breach(); breach != "" {
		t.Fatalf("a well formed descriptor was refused: %s", breach)
	}

	cases := []struct {
		name  string
		spoil func(*Descriptor)
		says  string
	}{
		{"no id", func(d *Descriptor) { d.ID = "" }, "id"},
		{"no runtime", func(d *Descriptor) { d.Runtime = "" }, "runtime"},
		{"no trust source", func(d *Descriptor) { d.TrustSource = "" }, "where this runtime keeps"},
		{"a source outside the registry", func(d *Descriptor) { d.Source = Source("guess") }, "rule 18"},
		{"a source with no evidence", func(d *Descriptor) { d.Evidence = "" }, "rule 18"},
		// THE SECOND PAIR, AND IT IS THE ONE THAT MATTERS MOST. Where a runtime
		// keeps its anchors is a claim somebody reads; what makes it accept a new
		// one is a claim somebody RUNS.
		{"a fix source outside the registry", func(d *Descriptor) { d.FixSource = Source("probably") }, "somebody RUNS"},
		{"a fix source with no evidence", func(d *Descriptor) { d.FixEvidence = "" }, "person executes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := sound
			c.spoil(&d)
			got := d.Breach()
			if got == "" {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(got, c.says) {
				t.Errorf("the refusal %q does not name what it defends (%q)", got, c.says)
			}
		})
	}
}

// Judgement is ALLOWED and has to say so. docs/20 is blunt that a judgement must
// never be quoted as a fact - which only works if the word exists.
func TestJudgementIsADeclaredSourceRatherThanAGap(t *testing.T) {
	for _, s := range []Source{Measured, Documentation, Judgement} {
		if !s.Valid() {
			t.Errorf("%q is declared and not in the registry", s)
		}
		if s.Meaning() == "" {
			t.Errorf("%q is in the registry with no meaning", s)
		}
		if s.String() != string(s) {
			t.Errorf("%q does not print as itself", s)
		}
	}
	if Source("probably").Valid() {
		t.Error("an undeclared source was accepted")
	}
}
