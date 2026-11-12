package screens

import (
	"math"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
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

// TestTheVerdictAndTheLayersStayWhileALayerScrolls is OBS218 (b), measured on
// where things are drawn rather than on how the screen is built: the trust
// layer is scrolled to its end in the smallest window, and Save report, Run
// again and the list of layers must stand where they stood. The page itself
// has to have moved, or the check proves nothing.
func TestTheVerdictAndTheLayersStayWhileALayerScrolls(t *testing.T) {
	newApp(t)
	r := fixture(t, "untrusted-root.json")
	last := len(r.Layers) - 1
	o, v := Report(icon(t), r, last, -1)
	w := test.NewTempWindow(t, o)
	w.SetPadded(false)
	w.Resize(fyne.NewSize(look.WindowMinWidth, look.WindowMinHeight))

	page := v.pages[last]
	if page.Content.MinSize().Height <= page.Size().Height {
		t.Fatalf("the trust layer fits in %v without scrolling, so this check proves nothing", page.Size())
	}
	at := fyne.CurrentApp().Driver().AbsolutePositionForObject
	// The page takes all the room below the verdict, down to the window's
	// bottom edge - a page as tall as its scroll's minimum would scroll too,
	// through a slot nobody could read.
	if bottom, edge := at(page).Y+page.Size().Height, w.Canvas().Size().Height; math.Abs(float64(bottom-edge)) > 0.5 {
		t.Errorf("the layer's page ends at %.1f and the window at %.1f", bottom, edge)
	}
	still := map[string]fyne.CanvasObject{"Save report": v.Save, "Run again": v.Again, "the list of layers": v.rail}
	before := map[string]fyne.Position{}
	for name, o := range still {
		before[name] = at(o)
	}
	content := at(page.Content)

	page.ScrollToBottom()

	if at(page.Content) == content {
		t.Fatal("scrolling the trust layer to its end did not move its page")
	}
	for name, o := range still {
		if now := at(o); now != before[name] {
			t.Errorf("%s moved from %v to %v when the layer scrolled", name, before[name], now)
		}
	}
}

// TestEachLayerKeepsWhereItWasScrolledTo - going to another layer and back
// finds the page where it was left, as GUI rule 3 asks of a scroll. The page
// scrolled is one made on choosing it, not the one the screen opened on: the
// two are made in different places.
func TestEachLayerKeepsWhereItWasScrolledTo(t *testing.T) {
	newApp(t)
	r := fixture(t, "untrusted-root.json")
	last := len(r.Layers) - 1
	o, v := Report(icon(t), r, 0, -1)
	w := test.NewTempWindow(t, o)
	w.Resize(fyne.NewSize(look.WindowMinWidth, look.WindowMinHeight))

	v.rail.Choose(last)
	page := v.pages[last]
	page.ScrollToBottom()
	left := page.Offset
	if left.Y == 0 {
		t.Fatal("the trust layer did not scroll, so this check proves nothing")
	}
	v.rail.Choose(0)
	v.rail.Choose(last)
	if v.shown.Objects[0] != page || page.Offset != left {
		t.Errorf("back on the trust layer the page is at %v, it was left at %v", page.Offset, left)
	}
}

// firstToOpen is the first part on a page that opens to show something -
// a store with a command - looked for through the containers the page is
// built of.
func firstToOpen(o fyne.CanvasObject) *parts.Pressable {
	if p, ok := o.(*parts.Pressable); ok && !p.Disabled() {
		return p
	}
	if s, ok := o.(*container.Scroll); ok {
		return firstToOpen(s.Content)
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
