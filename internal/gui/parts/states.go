package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// Track is a slim bar showing how much of a whole has gone: the time a run
// has used out of its budget. A share, not a promise of what is left - the
// command line says nothing until it is done, so the window shows time and
// never invents progress through the layers.
func Track(share float32) fyne.CanvasObject {
	share = max(0, min(1, share))
	under := canvas.NewRectangle(look.Colour(look.Raised))
	under.CornerRadius = look.TrackHeight / 2
	over := canvas.NewRectangle(look.Colour(look.Accent))
	over.CornerRadius = look.TrackHeight / 2
	return Height(look.TrackHeight, fyne.NewContainerWithLayout(trackLayout{share}, under, over))
}

type trackLayout struct{ share float32 }

func (t trackLayout) MinSize([]fyne.CanvasObject) fyne.Size { return fyne.NewSize(0, look.TrackHeight) }

func (t trackLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	objects[0].Resize(size)
	objects[1].Resize(fyne.NewSize(size.Width*t.share, size.Height))
}

// Fold is a card whose body can be put away: the head names it, says in one
// line what is inside when it is closed, and carries the sign that it opens.
func Fold(title, closedLine string, open bool, body ...fyne.CanvasObject) fyne.CanvasObject {
	icon := theme.MenuExpandIcon()
	if open {
		icon = theme.MenuDropDownIcon()
	}
	sign := canvas.NewImageFromResource(theme.NewColoredResource(icon, fyne.ThemeColorName(look.InkMuted)))
	sign.FillMode = canvas.ImageFillContain
	sign.SetMinSize(fyne.NewSquareSize(look.IconControl))
	head := []fyne.CanvasObject{Middle(sign), Middle(Text(Heading, title))}
	if !open {
		head = append(head, Middle(Clip(CaptionMuted, closedLine)))
	}
	rows := []fyne.CanvasObject{RowGrow(look.GapInline, 2, head...)}
	if open {
		rows = append(rows, body...)
	}
	return Panel(look.Surface, look.EdgeCard, look.RadiusCard, Pad(look.InsetCard, Stack(look.GapRow, rows...)))
}

// MenuItem is one choice of a menu: a name and a line saying what it is for.
type MenuItem struct {
	Name, Note string
}

// Menu is a short list of choices standing over the screen, the way the
// toolkit opens a pop-up: on the raised surface, with an edge, the row
// under the pointer lit.
func Menu(items []MenuItem, lit int) fyne.CanvasObject {
	rows := make([]fyne.CanvasObject, len(items))
	for i, it := range items {
		face := canvas.NewRectangle(look.Colour(look.Raised))
		if i == lit {
			face.FillColor = look.Colour(look.Hovered)
		}
		face.CornerRadius = look.RadiusControl
		rows[i] = Layers(face, PadXY(look.InsetCell, look.GapInline, Stack(0,
			Text(Strong, it.Name), Text(CaptionMuted, it.Note))))
	}
	return Width(look.MenuWidth, Panel(look.Raised, look.EdgeControl, look.RadiusCard,
		Pad(look.GapTight, Stack(0, rows...))))
}

// Notice stands under a button that leads out of the window when the
// desktop did not open its page: what happened, and the address with Copy,
// so the page is still one paste away. It stands over the screen like a
// menu, on the same surface and edge, and goes when the pointer is pressed
// anywhere else.
func Notice(title, note, address string) fyne.CanvasObject {
	return Width(look.NoticeWidth, Panel(look.Raised, look.EdgeControl, look.RadiusCard,
		Pad(look.InsetCard, Stack(look.GapRow,
			Stack(look.GapTight, Text(Strong, title), Para(CaptionMuted, note)),
			Command(address, false, "", "", nil)))))
}

// Problem is what the window says when certdoctor itself could not run -
// a failure of this tool, not a finding about the machine. It is drawn in
// no status's hue: FAIL is a fact about somebody's system and an error is
// ours (docs/18 section 3a), and the two must never look alike.
func Problem(title, what, todo, printed string, actions ...fyne.CanvasObject) fyne.CanvasObject {
	sign := canvas.NewImageFromResource(theme.NewColoredResource(theme.ErrorIcon(), fyne.ThemeColorName(look.InkMuted)))
	sign.FillMode = canvas.ImageFillContain
	sign.SetMinSize(fyne.NewSquareSize(look.MarkLarge))
	text := []fyne.CanvasObject{Text(Heading, title)}
	if what != "" {
		text = append(text, Para(Body, what))
	}
	if printed != "" {
		text = append(text, Stack(look.GapInline,
			Text(CaptionStrong, words.T(words.Printed)),
			Command(printed, false, "", "", nil)))
	}
	if todo != "" {
		text = append(text, Para(BodyMuted, todo))
	}
	if len(actions) > 0 {
		text = append(text, Inset(0, look.GapTight, 0, 0, Row(look.GapButtons, actions...)))
	}
	return Panel(look.Surface, look.EdgeCard, look.RadiusCard, Pad(look.InsetCard,
		RowTop(look.GapField, 1, sign, Stack(look.GapRow, text...))))
}

// Empty is what a section says when it has nothing to show, in place of a
// blank: one quiet sentence.
func Empty(sentence string) fyne.CanvasObject {
	return Panel(look.Page, look.EdgeCard, look.RadiusCard, Pad(look.InsetCard, Para(BodyMuted, sentence)))
}
