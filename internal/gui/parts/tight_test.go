package parts

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// TestTextKeepsNoThemeOverrideAndNoRoom holds the two halves of tight.
//
// NO OVERRIDE: Fyne v2.8.2 keys its cache of font faces by the scope of a
// theme override and numbers each override anew, so a text in an override of
// its own parsed its fonts again and kept them for the life of the program -
// the page of parts allocated 2.7 GB to be drawn once (2026-11-12). The text
// parts must not bring that back.
//
// NO ROOM: what the override did - take away the inner padding a RichText
// keeps round itself - the layout does, by the same amount on every side.
func TestTextKeepsNoThemeOverrideAndNoRoom(t *testing.T) {
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
	for name, part := range map[string]fyne.CanvasObject{
		"Text": Text(Body, "words"), "Para": Para(Body, "words that wrap"), "Code": Code(Mono, "cmd"),
		"Path": Path(Body, `C:\a\b`), "Clip": Clip(Body, "clipped"), "Number": Number(Body, "42"),
		"Inked": Inked(Body, look.InkMuted, "ink"), "Changing": NewChanging(Body, "now"),
	} {
		if overridden(part) {
			t.Errorf("%s stands in a theme override, which Fyne caches fonts for one by one", name)
		}
	}
	box := tight(widget.NewRichTextWithText("words"))
	inner := box.(*fyne.Container).Objects[0]
	p := theme.CurrentForWidget(inner).Size(theme.SizeNameInnerPadding)
	if p == 0 {
		t.Fatal("the theme keeps no room round a text, so this proves nothing")
	}
	box.Resize(fyne.NewSize(200, 40))
	if inner.Position() != fyne.NewPos(-p, -p) || inner.Size() != fyne.NewSize(200+2*p, 40+2*p) {
		t.Errorf("the text is laid out at %v, %v - want its room outside the box", inner.Position(), inner.Size())
	}
	if got, want := box.MinSize(), inner.MinSize().SubtractWidthHeight(2*p, 2*p); got != want {
		t.Errorf("the box asks for %v, the text without its room is %v", got, want)
	}
}

// overridden says whether a theme override stands anywhere under o.
func overridden(o fyne.CanvasObject) bool {
	switch x := o.(type) {
	case *container.ThemeOverride:
		return true
	case *fyne.Container:
		for _, child := range x.Objects {
			if overridden(child) {
				return true
			}
		}
	case fyne.Widget:
		for _, child := range test.WidgetRenderer(x).Objects() {
			if overridden(child) {
				return true
			}
		}
	}
	return false
}
