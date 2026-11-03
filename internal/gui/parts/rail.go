package parts

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
)

// RailItem is one layer in the list down the side of the report: its mark,
// its name, its status in words, and the first line of what it found.
func RailItem(l model.Layer, selected bool, state State) fyne.CanvasObject {
	tone := ToneOf(l.Status)
	fill := color.Color(color.Transparent)
	switch {
	case selected:
		fill = look.Colour(look.Raised)
	case state == Hover:
		fill = look.Colour(look.Hovered)
	}
	face := canvas.NewRectangle(fill)
	face.CornerRadius = look.RadiusControl
	if state == Focused {
		face.StrokeColor = look.Colour(look.Focus)
		face.StrokeWidth = look.StrokeFocus
	}
	bar := canvas.NewRectangle(color.Transparent)
	if selected {
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

// Rail is the list of layers, in the report's causal order. The order is the
// report's: L0 first, never sorted by how bad a status is (docs/18 section 4
// rule 1).
func Rail(title string, layers []model.Layer, selected int) fyne.CanvasObject {
	items := []fyne.CanvasObject{Inset(look.InsetCell, 0, 0, look.GapInline, Text(CaptionStrong, title))}
	for i, l := range layers {
		items = append(items, RailItem(l, i == selected, Rest))
	}
	return Stack(look.GapTight, items...)
}
