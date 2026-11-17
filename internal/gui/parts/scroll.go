package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// Scroll is every scrolling area of the window: the toolkit's own, with one
// notch of a mouse wheel moving it as far as a notch moves text in other
// programs.
//
// The toolkit moves an area by a fixed step for a notch (ToolkitNotch), about
// one line of the window's text, where Windows moves three by default. Measured
// on 2026-11-17 on the report of example.com: the window answered every notch
// within 15 ms - it was not slow to draw, its steps were short.
//
// An extension of the toolkit's scroll rather than a copy of it: the bars, the
// offset, the shadows and a drag on a bar stay the toolkit's, and only the
// distance a wheel asks for is answered here. One type for every area, so how
// the wheel feels is changed in one place.
type Scroll struct {
	container.Scroll
}

// VScroll is a scrolling area that moves up and down only.
func VScroll(content fyne.CanvasObject) *Scroll {
	s := &Scroll{}
	s.Direction = container.ScrollVerticalOnly
	s.Content = content
	// Before anything draws it, because the first call wins: the area has to
	// be drawn and refreshed as this type, or the wheel would reach the
	// toolkit's scroll underneath and never this one.
	s.ExtendBaseWidget(s)
	return s
}

// Scrolled moves the area by the window's distance for the notches turned.
func (s *Scroll) Scrolled(ev *fyne.ScrollEvent) {
	moved := *ev
	moved.Scrolled.DY = wheelDistance(ev.Scrolled.DY)
	s.Scroll.Scrolled(&moved)
}

// notchDistance is how far one notch moves an area: look.WheelLines lines of
// the window's body text, measured rather than written, so a notch keeps its
// meaning when the text grows or the screen is scaled.
func notchDistance() float32 {
	line := fyne.MeasureText("Ag", theme.Size(theme.SizeNameText), fyne.TextStyle{}).Height
	return look.WheelLines * line
}
