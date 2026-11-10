//go:build cgo

package main

import (
	"testing"

	"fyne.io/fyne/v2/test"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TestTheLaunchLineCanAskForTheCatalogue - --catalogue is read wherever it
// stands, beside --software-gl or alone, and nothing else asks for it.
func TestTheLaunchLineCanAskForTheCatalogue(t *testing.T) {
	for _, c := range []struct {
		args                []string
		catalogue, software bool
	}{
		{nil, false, false},
		{[]string{catalogueFlag}, true, false},
		{[]string{"an-argument", softwareFlag, catalogueFlag}, true, true},
		{[]string{"--catalog", "catalogue", "-catalogue"}, false, false},
	} {
		l := readLaunch(c.args)
		if l.catalogue != c.catalogue || l.softwareGL != c.software {
			t.Errorf("%q read as catalogue %v, software %v", c.args, l.catalogue, l.softwareGL)
		}
	}
}

// TestTheCatalogueOpensInsteadOfTheWindowWhenAskedFor - under --catalogue the
// window shows the catalogue under its own title with the keyboard in a box,
// and without it the start screen with Diagnose.
func TestTheCatalogueOpensInsteadOfTheWindowWhenAskedFor(t *testing.T) {
	test.NewTempApp(t).Settings().SetTheme(look.Theme())

	w := test.NewTempWindow(t, nil)
	if err := fill(w, nil, readLaunch([]string{catalogueFlag}), "0.1.0", false, &held{}); err != nil {
		t.Fatalf("the catalogue did not open: %v", err)
	}
	if w.Title() != words.T(words.CatWindow) || w.Canvas().Focused() == nil {
		t.Errorf("the catalogue opened titled %q with the keyboard on %v", w.Title(), w.Canvas().Focused())
	}
	// The page of parts draws a Diagnose of its own, so the two are told
	// apart by the title of that page, which the start screen does not have.
	if !drawsText(w.Content(), words.T(words.CatParts)) {
		t.Error("the catalogue opened without its page of parts")
	}

	w = test.NewTempWindow(t, nil)
	if err := fill(w, nil, readLaunch(nil), "0.1.0", false, &held{}); err != nil {
		t.Fatalf("the window did not open: %v", err)
	}
	if w.Title() == words.T(words.CatWindow) || drawsText(w.Content(), words.T(words.CatParts)) ||
		findButton(w.Content(), words.T(words.Diagnose)) == nil {
		t.Errorf("without --catalogue the window opened titled %q, not on its start screen", w.Title())
	}
}
