package screens

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
)

// TestChoosingALayerShowsItsPageAndKeepsWhatWasOpen opens a store's command
// in the trust layer, goes to another layer and back, and checks the page
// shown each time is the chosen layer's - and that the command is still open
// on coming back, because a page that forgets what was opened in it makes a
// person open it again every time they look elsewhere (GUI rule 3).
func TestChoosingALayerShowsItsPageAndKeepsWhatWasOpen(t *testing.T) {
	newApp(t)
	r := fixture(t, "untrusted-root.json")
	last := len(r.Layers) - 1
	o, v := Report(icon(t), r, last, -1)
	w := test.NewTempWindow(t, o)
	w.Resize(fyne.NewSize(look.WindowWidth, look.WindowHeight))
	if v.Chosen() != last {
		t.Fatalf("the report opened on layer %d, asked for %d", v.Chosen(), last)
	}
	trust := v.pages[last]
	row := firstToOpen(trust)
	if row == nil || row.Open() {
		t.Fatalf("no closed store with a command on the trust layer: %v", row)
	}
	row.Tapped(nil)

	v.rail.Choose(0)
	if v.Chosen() != 0 || len(v.shown.Objects) != 1 || v.shown.Objects[0] != v.pages[0] {
		t.Fatalf("after choosing L0 the screen shows %v, chosen %d", v.shown.Objects, v.Chosen())
	}
	v.rail.Choose(last)
	if v.shown.Objects[0] != trust || !row.Open() {
		t.Errorf("back on the trust layer: same page %v, command open %v", v.shown.Objects[0] == trust, row.Open())
	}
}

// TestAReportOpensOnTheStoreItIsAskedTo - the screen can be drawn with a
// command open, the way the pictures of it and the width check draw it.
func TestAReportOpensOnTheStoreItIsAskedTo(t *testing.T) {
	newApp(t)
	r := fixture(t, "untrusted-root.json")
	last := len(r.Layers) - 1
	open := -1
	for i, s := range r.Layers[last].Stores {
		if s.Command != "" {
			open = i
			break
		}
	}
	_, v := Report(icon(t), r, last, open)
	if row := firstToOpen(v.pages[last]); row == nil || !row.Open() {
		t.Errorf("the store at %d is not open", open)
	}
}

// firstToOpen is the first part on a page that opens to show something -
// a store with a command - looked for through the containers the page is
// built of.
func firstToOpen(o fyne.CanvasObject) *parts.Pressable {
	if p, ok := o.(*parts.Pressable); ok && !p.Disabled() {
		return p
	}
	if c, ok := o.(*fyne.Container); ok {
		for _, child := range c.Objects {
			if found := firstToOpen(child); found != nil {
				return found
			}
		}
	}
	return nil
}
