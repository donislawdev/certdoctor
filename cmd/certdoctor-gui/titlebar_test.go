//go:build cgo

package main

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// TestTheTitleBarIsAskedForAgainAfterEveryChangeOfSettings - the toolkit
// sets the title bar from the system's mode on every change of settings, so
// the window asks for its dark one again after each, for its own window.
func TestTheTitleBarIsAskedForAgainAfterEveryChangeOfSettings(t *testing.T) {
	a := test.NewTempApp(t)
	w := test.NewTempWindow(t, nil)
	var asked []fyne.Window
	keepDark(a.Settings(), w, func(x fyne.Window) { asked = append(asked, x) })
	if len(asked) != 0 {
		t.Fatalf("the title bar was asked for %d time(s) before anything changed", len(asked))
	}
	a.Settings().SetTheme(look.Theme())
	a.Settings().SetTheme(look.Theme())
	if len(asked) != 2 || asked[0] != w || asked[1] != w {
		t.Errorf("two changes of settings asked for the title bar %d time(s), of %v", len(asked), asked)
	}
}
