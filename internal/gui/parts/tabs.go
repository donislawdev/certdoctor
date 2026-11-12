package parts

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// TabItem is how one place of the window is drawn on its bar: its name, in
// the ink of the text when it is the place shown and muted when not, with
// the bar that marks the chosen one under it. Quiet, so it does not compete
// with a screen's one primary action.
func TabItem(label string, chosen bool, state State) fyne.CanvasObject {
	fill := color.Color(color.Transparent)
	if !chosen && (state == Hover || state == Press) {
		fill = look.Colour(look.Hovered)
	}
	face := canvas.NewRectangle(fill)
	face.CornerRadius = look.RadiusControl
	if state == Focused {
		face.StrokeColor = look.Colour(look.Focus)
		face.StrokeWidth = look.StrokeFocus
	}
	ink := look.InkMuted
	if chosen {
		ink = look.Ink
	}
	mark := canvas.NewRectangle(color.Transparent)
	if chosen {
		mark.FillColor = look.Colour(look.Chosen)
	}
	mark.SetMinSize(fyne.NewSize(0, look.StrokeSelected))
	// The word in the middle of the bar's height, where the program's name
	// stands beside it, and the mark along the bottom edge under it - with a
	// clear strip as tall as the mark along the top, so the mark does not
	// push the word up out of line with the name.
	balance := canvas.NewRectangle(color.Transparent)
	balance.SetMinSize(fyne.NewSize(0, look.StrokeSelected))
	word := PadXY(look.InsetControl, 0, Middle(Inked(Strong, ink, label)))
	return Height(look.ControlHeight, Layers(face, container.NewBorder(balance, mark, nil, nil, word)))
}

// Tabs are the places of the window on its bar - Diagnose and Tools - one of
// them the place shown. Pressing another, with the pointer or with Space or
// Enter once Tab has reached it, shows that one instead.
type Tabs struct {
	widget.BaseWidget
	// OnChosen is told the place chosen, each time it is another one.
	OnChosen func(i int)

	entries []*Pressable
	chosen  int
	row     fyne.CanvasObject
}

// NewTabs are tabs named labels, the one at chosen chosen.
func NewTabs(labels []string, chosen int) *Tabs {
	t := &Tabs{chosen: chosen}
	var items []fyne.CanvasObject
	for i, label := range labels {
		entry := NewPressable(func(s State, open bool) (fyne.CanvasObject, fyne.CanvasObject) {
			return nil, TabItem(label, open, s)
		}, nil, i == chosen)
		entry.OnTapped = func() { t.Choose(i) }
		t.entries = append(t.entries, entry)
		items = append(items, entry)
	}
	t.row = Row(look.GapTight, items...)
	t.ExtendBaseWidget(t)
	return t
}

// Choose makes the place at i the chosen one. The one already chosen, or one
// there is not, changes nothing.
func (t *Tabs) Choose(i int) {
	if choose(t.entries, &t.chosen, i) && t.OnChosen != nil {
		t.OnChosen(i)
	}
}

// Chosen is the place chosen now.
func (t *Tabs) Chosen() int { return t.chosen }

// Reset makes the place at i the chosen one without telling OnChosen: a
// screen shown again shows its own place, whatever was pressed on it before
// the window left it.
func (t *Tabs) Reset(i int) { choose(t.entries, &t.chosen, i) }

func (t *Tabs) CreateRenderer() fyne.WidgetRenderer { return widget.NewSimpleRenderer(t.row) }

// choose makes entries[i] the one open among entries, and says whether that
// changed anything - the rule of every list of which one part is chosen.
func choose(entries []*Pressable, chosen *int, i int) bool {
	if i == *chosen || i < 0 || i >= len(entries) {
		return false
	}
	if *chosen >= 0 && *chosen < len(entries) {
		entries[*chosen].SetOpen(false)
	}
	*chosen = i
	entries[i].SetOpen(true)
	return true
}
