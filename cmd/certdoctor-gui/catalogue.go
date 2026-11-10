//go:build cgo

package main

import (
	"fmt"

	"fyne.io/fyne/v2"

	"github.com/donislawdev/certdoctor/internal/gui/catalogue"
	"github.com/donislawdev/certdoctor/internal/gui/flow"
	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// fill puts in w what the launch line asked for: under --catalogue the hidden
// catalogue of the window's parts, and otherwise the window of version on its
// start screen, running the command line through port. software says the
// window is drawn by the software renderer shipped beside it.
func fill(w fyne.Window, picture fyne.Resource, l launch, version string, software bool, port flow.Port) error {
	if l.catalogue {
		return showCatalogue(w, picture)
	}
	newWindow(w, picture, version, software, port).showStart()
	return nil
}

// showCatalogue puts the catalogue in w (GUI rule 4), drawn from the example
// report the window carries, under a title that says it is not the window,
// held no smaller than the window may be made, and with the keyboard in the
// box whose focused state it shows.
func showCatalogue(w fyne.Window, picture fyne.Resource) error {
	example, err := model.Example()
	if err != nil {
		return fmt.Errorf(words.T(words.CatNoExample), err)
	}
	content, focus := catalogue.All(picture, example)
	w.SetTitle(words.T(words.CatWindow))
	w.SetContent(parts.AtLeast(look.WindowMinWidth, look.WindowMinHeight, content))
	w.Canvas().Focus(focus)
	return nil
}
