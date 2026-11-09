package parts

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
)

// RailItem is how one layer in the list down the side of the report is
// drawn: its mark, its name, its status in words, and the first line of
// what it found. chosen is the layer the page beside the list shows.
func RailItem(l model.Layer, chosen bool, state State) fyne.CanvasObject {
	tone := ToneOf(l.Status)
	fill := color.Color(color.Transparent)
	switch {
	case chosen:
		fill = look.Colour(look.Raised)
	case state == Hover || state == Press:
		fill = look.Colour(look.Hovered)
	}
	face := canvas.NewRectangle(fill)
	face.CornerRadius = look.RadiusControl
	if state == Focused {
		face.StrokeColor = look.Colour(look.Focus)
		face.StrokeWidth = look.StrokeFocus
	}
	bar := canvas.NewRectangle(color.Transparent)
	if chosen {
		bar.FillColor = look.Colour(look.Chosen)
	}
	bar.CornerRadius = look.StrokeSelected / 2
	bar.SetMinSize(fyne.NewSize(look.StrokeSelected, 0))

	sentence := l.Detail
	if sentence == "" {
		sentence = l.Reason
	}
	name := RowGrow(look.GapInline, 1,
		Text(CaptionMuted, l.ID),
		Clip(Strong, l.Name),
		Inked(CaptionStrong, look.ToneRole(tone), string(l.Status)),
	)
	text := Stack(look.GapTight, name, Clip(CaptionMuted, sentence))
	content := PadXY(look.InsetCell, 0, RowGrow(look.GapRow, 1,
		Middle(Mark(tone, look.MarkRow)),
		Middle(text),
	))
	return Height(look.RailItemHeight, Layers(face,
		RowGrow(0, 1, Tall(Inset(0, look.InsetCell, 0, look.InsetCell, bar)), Middle(content)),
	))
}

// RailEntry is one layer of the rail as a part to press: open while it is
// the chosen one.
func RailEntry(l model.Layer, chosen bool) *Pressable {
	return NewPressable(func(s State, open bool) (fyne.CanvasObject, fyne.CanvasObject) {
		return nil, RailItem(l, open, s)
	}, nil, chosen)
}

// Rail is the list of layers, in the report's causal order: L0 first, never
// sorted by how bad a status is (docs/18 section 4 rule 1). One layer is the
// chosen one, and pressing another - with the pointer, or with Space or
// Enter once Tab has reached it - chooses that one instead.
type Rail struct {
	widget.BaseWidget
	// OnChosen is told the layer chosen, each time it is another one.
	OnChosen func(layer int)

	entries []*Pressable
	chosen  int
	list    fyne.CanvasObject
}

// NewRail is the rail of layers with the one at chosen chosen.
func NewRail(title string, layers []model.Layer, chosen int) *Rail {
	r := &Rail{chosen: chosen}
	items := []fyne.CanvasObject{Inset(look.InsetCell, 0, 0, look.GapInline, Text(CaptionStrong, title))}
	for i, l := range layers {
		entry := RailEntry(l, i == chosen)
		entry.OnTapped = func() { r.Choose(i) }
		r.entries = append(r.entries, entry)
		items = append(items, entry)
	}
	r.list = Stack(look.GapTight, items...)
	r.ExtendBaseWidget(r)
	return r
}

// Choose makes the layer at i the chosen one. Choosing the one already
// chosen, or one the report does not have, changes nothing.
func (r *Rail) Choose(i int) {
	if i == r.chosen || i < 0 || i >= len(r.entries) {
		return
	}
	if r.chosen >= 0 && r.chosen < len(r.entries) {
		r.entries[r.chosen].SetOpen(false)
	}
	r.chosen = i
	r.entries[i].SetOpen(true)
	if r.OnChosen != nil {
		r.OnChosen(i)
	}
}

// Chosen is the layer chosen now.
func (r *Rail) Chosen() int { return r.chosen }

func (r *Rail) CreateRenderer() fyne.WidgetRenderer { return widget.NewSimpleRenderer(r.list) }
