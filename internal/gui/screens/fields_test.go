package screens

import (
	"testing"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TestEveryFieldNameFitsTheColumnOfNames holds every name the window puts in
// the column of names of a form to that column's width. The name is one line
// that is never cut short, so a longer one runs on into the box beside it -
// the request box of the CSR decoder did, seen in the real window.
func TestEveryFieldNameFitsTheColumnOfNames(t *testing.T) {
	newApp(t)
	fits := func(name string) bool {
		return parts.Text(parts.Strong, name).MinSize().Width <= look.LabelWidth
	}
	if fits("Certificate signing request") {
		t.Fatal("the canary fits the column - this measure cannot tell a name that is too long")
	}
	names := []string{words.T(words.SaveFolder), words.T(words.SaveName)}
	for _, o := range request.Offered {
		names = append(names, words.T(o.Label))
	}
	for _, id := range words.ToolIDs() {
		w, _ := words.Tool(id)
		for _, in := range w.Inputs {
			names = append(names, in.Label)
		}
	}
	for _, n := range names {
		if !fits(n) {
			t.Errorf("%q is wider than the column of names (look.LabelWidth)", n)
		}
	}
}
