package main

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
)

// THIS FILE EXISTS BECAUSE THE LAST DECLARED-BUT-UNBUILT FORMAT WAS BUILT.
//
// The flag surface keeps "declared" and "built" as separate fields on purpose:
// the surface is frozen, so a format that is going to exist is named from the
// first day and refused with a reason until it works. Until html arrived, that
// refusal had a live example and cli_test.go reached it from a command line.
// It has none now, and a mechanism with no example is a mechanism nobody notices
// has stopped working - so the two claims it makes are asked directly here.

// TestADeclaredFormatThatIsNotBuiltIsRefusedWithItsReason declares one for the
// length of this test.
//
// A SYNTHETIC DECLARATION IS THE HONEST WAY TO ASK THIS. The alternative was to
// leave a real format unbuilt so that something could be tested against it,
// which is keeping a hole in the product to keep a test company.
func TestADeclaredFormatThatIsNotBuiltIsRefusedWithItsReason(t *testing.T) {
	restore := formats
	t.Cleanup(func() { formats = restore })
	formats = append(append([]formatDecl{}, formats...),
		formatDecl{name: "papyrus", built: false, why: "papyrus is not built yet"})

	o := &options{format: "papyrus"}
	f := o.checkFormat()
	if f == nil {
		t.Fatal("a format declared and not built was accepted")
	}
	if f.code != exitcode.Config {
		t.Errorf("the refusal ended with %s, want %s", f.code.Name(), exitcode.Config.Name())
	}
	// THE REASON AND THE ALTERNATIVES BOTH HAVE TO BE IN THE SENTENCE. A refusal
	// that says only "no" leaves the person guessing what to type instead, which
	// is the failure docs/08 describes: an error is a place where somebody is
	// already stuck.
	if !strings.Contains(f.message, "papyrus is not built yet") {
		t.Errorf("the refusal does not carry the declared reason: %s", f.message)
	}
	for _, built := range builtFormatNames() {
		if !strings.Contains(f.message, built) {
			t.Errorf("the refusal does not offer %s, which is built: %s", built, f.message)
		}
	}
}

// TestEveryDeclaredFormatIsBuiltOrSaysWhyNot is the invariant behind the help
// text.
//
// writeNotBuilt PRINTS f.why FOR EVERY UNBUILT FORMAT, so a declaration with an
// empty reason produces a help page with a blank line where an explanation
// belongs - and the same empty string reaches the refusal above. Neither is a
// crash and both are silence, which is the failure inviolable rule 1 names.
func TestEveryDeclaredFormatIsBuiltOrSaysWhyNot(t *testing.T) {
	for _, f := range formats {
		if f.built && f.why != "" {
			t.Errorf("%s is built and still carries a reason for not being: %q", f.name, f.why)
		}
		if !f.built && strings.TrimSpace(f.why) == "" {
			t.Errorf("%s is declared, not built, and says nothing about why", f.name)
		}
	}
	if len(builtFormatNames()) == 0 {
		t.Fatal("no format is built, so every other test in this package is asking about nothing")
	}
}

// TestEveryBuiltFormatProducesAReport is the claim the built bit makes.
//
// IT LOOPS OVER THE DECLARATION RATHER THAN OVER A LIST WRITTEN HERE, which is
// the shape that made this test worth writing at all: the day somebody flips a
// built bit without wiring a renderer, the dispatch falls through to whatever
// its default arm is and the run still succeeds - with the wrong document. A
// hand-written list would have to be remembered on exactly that day.
//
// WHAT IT CANNOT ASK is whether each format produced its OWN document; that is
// the acceptance suite's question, because it needs the real binary. This one
// asks the cheaper half: that a format declared as working writes something, and
// ends the way every other run of this target ends.
func TestEveryBuiltFormatProducesAReport(t *testing.T) {
	for _, format := range builtFormatNames() {
		h := invoke("https://example.com", "--format", format)
		if h.code != exitcode.Inconclusive {
			t.Errorf("%s ended with %s: %s", format, h.code.Name(), h.stderr.String())
			continue
		}
		if strings.TrimSpace(h.stdout.String()) == "" {
			t.Errorf("%s is declared built and produced no report at all", format)
		}
	}
}
