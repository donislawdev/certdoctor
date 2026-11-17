package parts

import (
	"image/color"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
)

// block is an empty part h tall.
func block(h float32) *canvas.Rectangle {
	r := canvas.NewRectangle(color.Transparent)
	r.SetMinSize(fyne.NewSize(10, h))
	return r
}

// revealView is how tall the scroll in these checks is.
const revealView = 400

// TestAPartThatChangedIsBroughtIntoView - each case is a page of three parts
// in a scroll 400 tall: the part to reveal, what is above it, what is below
// it, and where the page stood before. A part wholly in view leaves the page
// where it was, any other has its top at the top of the view, as far as the
// page goes.
func TestAPartThatChangedIsBroughtIntoView(t *testing.T) {
	for _, c := range []struct {
		name               string
		above, part, below float32
		from, want         float32
	}{
		{"under the bottom edge", 300, 200, 500, 0, 300},
		{"its first lines in view and the rest under the edge", 100, 600, 0, 0, 100},
		{"wholly in view", 100, 100, 500, 0, 0},
		{"wholly in view on a page scrolled down", 300, 100, 500, 100, 100},
		{"taller than the view with its top at the top", 300, 600, 0, 300, 300},
		{"above the view", 300, 100, 1000, 600, 300},
		{"near the end of the page", 600, 100, 0, 0, 300},
	} {
		t.Run(c.name, func(t *testing.T) {
			newApp(t)
			part := Layers(block(c.part))
			s := container.NewVScroll(Stack(0, block(c.above), part, block(c.below)))
			w := test.NewTempWindow(t, s)
			w.SetPadded(false)
			w.Resize(fyne.NewSize(revealView, revealView))
			s.ScrollToOffset(fyne.NewPos(0, c.from))
			if s.Offset.Y != c.from {
				t.Fatalf("the page did not start at %v but at %v, so this case proves nothing", c.from, s.Offset.Y)
			}
			Reveal(s, part)
			if s.Offset.Y != c.want {
				t.Errorf("the page stands at %v, want %v", s.Offset.Y, c.want)
			}
		})
	}
}

// TestAPartThatGrewThisMomentIsBroughtIntoView is the trap Reveal is written
// around: a page that fitted its view a moment ago, whose part grew and has
// not been laid out yet - which a scroll asked to move takes for a page that
// still fits, and holds at its top.
func TestAPartThatGrewThisMomentIsBroughtIntoView(t *testing.T) {
	newApp(t)
	part := Layers(block(50))
	s := container.NewVScroll(Stack(0, block(100), part))
	w := test.NewTempWindow(t, s)
	w.SetPadded(false)
	w.Resize(fyne.NewSize(revealView, revealView))
	if s.Content.MinSize().Height > revealView {
		t.Fatal("the page does not fit its view before the part grows, so this check proves nothing")
	}
	part.Objects = []fyne.CanvasObject{block(1000)}
	part.Refresh()
	Reveal(s, part)
	if s.Offset.Y != 100 {
		t.Errorf("the page stands at %v, want the grown part's top at 100", s.Offset.Y)
	}
}

// A scroll not laid out yet and a part that is not on its page are left as
// they are - and neither stops the program.
func TestRevealLeavesWhatItCannotPlace(t *testing.T) {
	newApp(t)
	part := Layers(block(50))
	never := container.NewVScroll(Stack(0, block(1000), part))
	Reveal(never, part)
	if never.Offset.Y != 0 {
		t.Errorf("a scroll never laid out moved to %v", never.Offset.Y)
	}
	// Scrolled down first: a part taken to stand at the page's very top
	// would move the page there.
	s := container.NewVScroll(Stack(0, block(1000), Layers(block(50))))
	w := test.NewTempWindow(t, s)
	w.SetPadded(false)
	w.Resize(fyne.NewSize(revealView, revealView))
	s.ScrollToOffset(fyne.NewPos(0, 300))
	Reveal(s, part)
	if s.Offset.Y != 300 {
		t.Errorf("a part that is not on the page moved it from 300 to %v", s.Offset.Y)
	}
}
