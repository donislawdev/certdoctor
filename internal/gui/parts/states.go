package parts

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// Track is a slim bar showing how much of a whole has gone: the time a run
// has used out of its budget. A share, not a promise of what is left - the
// command line says nothing until it is done, so the window shows time and
// never invents progress through the layers.
//
// A widget rather than a container, because the running screen moves it every
// second while the screen stands: set in place, nothing around it is laid out
// again, and the Cancel beside it keeps its hover and its focus (GUI rule 3).
type Track struct {
	widget.BaseWidget
	share float32
}

// NewTrack is a track with share of it gone, held between nothing and all.
func NewTrack(share float32) *Track {
	t := &Track{share: max(0, min(1, share))}
	t.ExtendBaseWidget(t)
	return t
}

// SetShare moves the track to share, held between nothing and all.
func (t *Track) SetShare(share float32) {
	share = max(0, min(1, share))
	if share == t.share {
		return
	}
	t.share = share
	t.Refresh()
}

// Share is how much of the track has gone.
func (t *Track) Share() float32 { return t.share }

func (t *Track) CreateRenderer() fyne.WidgetRenderer {
	under := canvas.NewRectangle(look.Colour(look.Raised))
	under.CornerRadius = look.TrackHeight / 2
	over := canvas.NewRectangle(look.Colour(look.Accent))
	over.CornerRadius = look.TrackHeight / 2
	return &trackRenderer{track: t, under: under, over: over}
}

type trackRenderer struct {
	track       *Track
	under, over *canvas.Rectangle
}

func (r *trackRenderer) MinSize() fyne.Size { return fyne.NewSize(0, look.TrackHeight) }

func (r *trackRenderer) Layout(size fyne.Size) {
	r.under.Resize(size)
	r.over.Resize(fyne.NewSize(size.Width*r.track.share, size.Height))
}

func (r *trackRenderer) Refresh() {
	r.Layout(r.track.Size())
	canvas.Refresh(r.over)
}

func (r *trackRenderer) Objects() []fyne.CanvasObject { return []fyne.CanvasObject{r.under, r.over} }
func (r *trackRenderer) Destroy()                     {}

// Fold is a card whose body can be put away: the head names it, says in one
// line what is inside when it is closed, and carries the sign that it opens.
// The head is pressed to open and close it, and what was typed in the body
// stays there while it is put away.
//
// The room inside the card is the room of a card - InsetCard round it, GapRow
// between the head and the body - but the head's part of it is the head's,
// so the band lit under the pointer is the whole of the card's top.
func Fold(title, closedLine string, open bool, body ...fyne.CanvasObject) *Pressable {
	inside := Inset(look.InsetCard, 0, look.InsetCard, look.InsetCard, Stack(look.GapRow, body...))
	return NewPressable(func(s State, open bool) (fyne.CanvasObject, fyne.CanvasObject) {
		card := canvas.NewRectangle(look.Colour(look.Surface))
		card.CornerRadius = look.RadiusCard
		card.StrokeColor = look.Colour(look.EdgeCard)
		card.StrokeWidth = look.Hairline
		return card, foldHead(title, closedLine, s, open)
	}, inside, open)
}

// foldHead is the band across the top of a fold: the sign, the name, and
// the line saying what is inside when it is closed. It keeps a hairline
// inside the card's edge, so lit or ringed it never covers it.
func foldHead(title, closedLine string, s State, open bool) fyne.CanvasObject {
	icon := theme.MenuExpandIcon()
	if open {
		icon = theme.MenuDropDownIcon()
	}
	sign := canvas.NewImageFromResource(theme.NewColoredResource(icon, fyne.ThemeColorName(look.InkMuted)))
	sign.FillMode = canvas.ImageFillContain
	sign.SetMinSize(fyne.NewSquareSize(look.IconControl))
	words := []fyne.CanvasObject{Middle(sign), Middle(Text(Heading, title))}
	if !open {
		words = append(words, Middle(Clip(CaptionMuted, closedLine)))
	}

	band := canvas.NewRectangle(color.Transparent)
	switch s {
	case Hover, Press:
		band.FillColor = look.Colour(look.Hovered)
	case Focused:
		band.StrokeColor = look.Colour(look.Focus)
		band.StrokeWidth = look.StrokeFocus
	}
	// Rounded where the card is: all four corners when the band is the whole
	// card, the top two when the body hangs under it.
	inner := float32(look.RadiusCard - look.Hairline)
	band.TopLeftCornerRadius, band.TopRightCornerRadius = inner, inner
	under, below := float32(look.Hairline), float32(look.InsetCard-look.Hairline)
	if open {
		under, below = 0, look.GapRow
	} else {
		band.BottomLeftCornerRadius, band.BottomRightCornerRadius = inner, inner
	}
	room := float32(look.InsetCard - look.Hairline)
	return Inset(look.Hairline, look.Hairline, look.Hairline, under, Layers(band,
		Inset(room, room, room, below, RowGrow(look.GapInline, 2, words...))))
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
