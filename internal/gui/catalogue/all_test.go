package catalogue

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TestTheWindowsCatalogueHoldsEveryPage - what --catalogue shows is the three
// pages of the catalogue, one under the other, in a scroll: none left out,
// and the box whose focused state is drawn handed back to hold the keyboard.
func TestTheWindowsCatalogueHoldsEveryPage(t *testing.T) {
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
	o, focus := All(appIcon(t), sampleReport(t))
	if _, ok := o.(*container.Scroll); !ok {
		t.Errorf("the catalogue is a %T, want it in a scroll - it is taller than any window", o)
	}
	if focus == nil {
		t.Error("the catalogue hands back no box to hold the keyboard")
	}
	for _, title := range []words.Key{words.CatParts, words.CatPalette, words.CatType} {
		if !holds(o, words.T(title)) {
			t.Errorf("the catalogue has no page %q", words.T(title))
		}
	}
}

// holds says whether o, or anything inside it, is rich text saying text.
func holds(o fyne.CanvasObject, text string) bool {
	if r, ok := o.(*widget.RichText); ok && r.String() == text {
		return true
	}
	var inside []fyne.CanvasObject
	switch x := o.(type) {
	case *container.Scroll:
		inside = []fyne.CanvasObject{x.Content}
	case *fyne.Container:
		inside = x.Objects
	case fyne.Widget:
		inside = test.WidgetRenderer(x).Objects()
	}
	for _, child := range inside {
		if holds(child, text) {
			return true
		}
	}
	return false
}
