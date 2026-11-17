package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

// Reveal brings o into view in s, after o changed: when o is not wholly in
// view, s scrolls so the top of o is at the top of the view, as far as the
// content goes. o wholly in view leaves s where it is - a page that moves
// with nothing more to show for it loses the reader's place.
//
// "Wholly", not "its top": an answer whose first card stands at the bottom
// edge with the rest under it reads as an answer of one card (OBS241).
//
// THE CONTENT IS GIVEN ITS SIZE HERE, NOT ON THE NEXT FRAME. Fyne lays a
// scroll's content out when it next draws, and a scroll asked to move judges
// whether its content fits by the size the content has now (fyne v2.8.2,
// internal/widget/scroller.go, updateOffset) - so a page that was short
// before o grew would be held at its top. The height of o is what o asks
// for, for the same reason: its place is laid out on the next frame.
//
// o is found through the containers under s. A part reached only through a
// widget, or a scroll not laid out yet, is left where it is.
func Reveal(s *container.Scroll, o fyne.CanvasObject) {
	view := s.Size()
	if view.Height <= 0 {
		return
	}
	s.Content.Resize(s.Content.MinSize().Max(view))
	at, ok := placeIn(s.Content, o)
	if !ok {
		return
	}
	top, bottom := at.Y, at.Y+o.MinSize().Height
	if top >= s.Offset.Y && bottom <= s.Offset.Y+view.Height {
		return
	}
	s.ScrollToOffset(fyne.NewPos(s.Offset.X, top))
}

// placeIn is where o sits in root, through the containers between them.
func placeIn(root, o fyne.CanvasObject) (fyne.Position, bool) {
	if root == o {
		return fyne.Position{}, true
	}
	c, ok := root.(*fyne.Container)
	if !ok {
		return fyne.Position{}, false
	}
	for _, child := range c.Objects {
		if at, found := placeIn(child, o); found {
			return child.Position().Add(at), true
		}
	}
	return fyne.Position{}, false
}
