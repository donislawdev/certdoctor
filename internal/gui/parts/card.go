package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// Panel is a filled, rounded surface under a content, with a hairline edge
// when edge is not empty. A card, a command and a bar are all panels.
func Panel(fill, edge look.Role, radius float32, content fyne.CanvasObject) fyne.CanvasObject {
	face := canvas.NewRectangle(look.Colour(fill))
	face.CornerRadius = radius
	if edge != "" {
		face.StrokeColor = look.Colour(edge)
		face.StrokeWidth = look.Hairline
	}
	return Layers(face, content)
}

// Card is a section of a screen: a surface with a name, an optional thing
// at the far end of the name's line, and a body.
func Card(title string, trailing fyne.CanvasObject, body ...fyne.CanvasObject) fyne.CanvasObject {
	var rows []fyne.CanvasObject
	if title != "" {
		head := []fyne.CanvasObject{Middle(Text(Heading, title))}
		if trailing != nil {
			head = append(head, trailing)
		}
		rows = append(rows, RowGrow(look.GapInline, 0, head...))
	}
	rows = append(rows, body...)
	return Panel(look.Surface, look.EdgeCard, look.RadiusCard, Pad(look.InsetCard, Stack(look.GapRow, rows...)))
}

// Rule is a hairline across, between two rows that belong to one card.
func Rule() fyne.CanvasObject {
	line := canvas.NewRectangle(look.Colour(look.Divider))
	line.SetMinSize(fyne.NewSize(0, look.Hairline))
	return line
}

// Upright is a hairline up and down, between two panes.
func Upright() fyne.CanvasObject {
	line := canvas.NewRectangle(look.Colour(look.Divider))
	line.SetMinSize(fyne.NewSize(look.Hairline, 0))
	return line
}

// Bar is a strip across the window - the top or the foot - on the card
// surface with a hairline between it and the page.
//
// Its far end keeps InsetControl less room than the page does. What stands
// there is quiet buttons, whose words start that far inside a face nobody
// sees at rest, so without it their words would end short of the line the
// cards below end on - measured on the report screen, where they stood a
// button's inset left of Run again.
func Bar(content fyne.CanvasObject) fyne.CanvasObject {
	face := canvas.NewRectangle(look.Colour(look.Surface))
	return Layers(face, Inset(look.InsetPage, look.InsetBar, look.InsetPage-look.InsetControl, look.InsetBar, content))
}

// Finding is one fact a layer found: its kind, as the report names it, over
// the report's own sentence.
func Finding(kind, summary string) fyne.CanvasObject {
	return Stack(look.GapTight, Text(CaptionStrong, words.Kind(kind)), Para(Body, summary))
}
