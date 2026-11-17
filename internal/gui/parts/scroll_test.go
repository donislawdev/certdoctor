//go:build !darwin

package parts

import (
	"image/color"
	"math"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// TestAWheelNotchMovesThreeLinesOfText - one notch, as the toolkit hands it
// over on Windows and Linux, moves an area of the window by look.WheelLines
// lines of its text, the area found as the driver finds it (the scrollable
// under the pointer), and a touchpad's fifth of a notch moves a fifth. The
// canary is the toolkit's own scroll, which must move one ToolkitNotch for the
// same notch - or this test could not tell the two apart.
func TestAWheelNotchMovesThreeLinesOfText(t *testing.T) {
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
	line := fyne.MeasureText("Ag", theme.Size(theme.SizeNameText), fyne.TextStyle{}).Height
	notch := look.WheelLines * line
	moved := func(s *container.Scroll, o fyne.CanvasObject, dy float32) float32 {
		w := test.NewTempWindow(t, o)
		w.Resize(fyne.NewSize(200, 300))
		test.Scroll(w.Canvas(), fyne.NewPos(50, 50), 0, dy)
		return s.Offset.Y
	}
	tall := func() fyne.CanvasObject {
		r := canvas.NewRectangle(color.Transparent)
		r.SetMinSize(fyne.NewSize(100, 5000))
		return r
	}
	toolkit := container.NewVScroll(tall())
	if got := moved(toolkit, toolkit, -ToolkitNotch); got != ToolkitNotch {
		t.Fatalf("the canary: the toolkit's own scroll moved %v for a notch, want %v", got, ToolkitNotch)
	}
	for _, c := range []struct {
		name  string
		dy    float32
		wants float32
	}{
		{"a notch", -ToolkitNotch, notch},
		{"a fifth of a notch", -ToolkitNotch / 5, notch / 5},
	} {
		ours := VScroll(tall())
		if got := moved(&ours.Scroll, ours, c.dy); math.Abs(float64(got-c.wants)) > 0.01 {
			t.Errorf("%s moved the window's scroll %v, want %v (%d lines of %v)", c.name, got, c.wants, look.WheelLines, line)
		}
	}
	if notch <= ToolkitNotch {
		t.Errorf("three lines are %v, no further than the toolkit's notch of %v", notch, ToolkitNotch)
	}
}
