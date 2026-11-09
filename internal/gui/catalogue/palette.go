// Package sheets is the catalogue screen, a page at a time: the palette
// with its measured contrast, the ladder of type, and every part in every
// state.
package catalogue

import (
	"fmt"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// Pair is one measured contrast: an ink or an edge over what is under it.
type Pair struct {
	Front, Back string
	Ratio, Need float64
}

// Pairs is every pair of colours the window really puts one over the other
// and that WCAG holds to a ratio - words at 4.5, and at 3.0 the edges of
// controls, the focus ring, the bar of the chosen entry and the glyph cut
// into a mark. A pair the window never draws is not on the list, because a
// ratio nobody sees proves nothing.
func Pairs() []Pair {
	var out []Pair
	add := func(front string, f color.NRGBA, back string, b color.NRGBA, need float64) {
		out = append(out, Pair{front, back, look.Contrast(f, b), need})
	}
	pair := func(front, back look.Role, need float64) {
		add(string(front), look.Colour(front), string(back), look.Colour(back), need)
	}
	const text, shape = 4.5, 3.0

	// Words on every surface they stand on: cards, the page, a chosen or
	// opened row, a row under the pointer, a command.
	for _, back := range []look.Role{look.Page, look.Surface, look.Raised, look.Hovered, look.Sunken} {
		pair(look.Ink, back, text)
	}
	for _, back := range []look.Role{look.Page, look.Surface, look.Raised, look.Hovered} {
		pair(look.InkMuted, back, text)
	}
	// The example inside an empty box to type in.
	pair(look.InkFaint, look.Sunken, text)
	// A status word on the page (the list of layers), on a card (the
	// verdict), on a chosen entry, and inside its own badge on each - and on
	// an entry under the pointer, where the list lights it.
	for _, t := range []look.Tone{look.TonePass, look.ToneWarn, look.ToneFail, look.ToneUnknown} {
		hue := look.ToneRole(t)
		for _, back := range []look.Role{look.Page, look.Surface, look.Raised} {
			pair(hue, back, text)
			add(string(hue), look.Colour(hue), "its tint on "+string(back), look.Tint(t, back), text)
		}
		// An entry of the list of layers under the pointer.
		pair(hue, look.Hovered, text)
		pair(look.InkOnStatus, hue, shape)
	}
	for _, back := range []look.Role{look.Accent, look.AccentHovered, look.AccentPressed} {
		pair(look.OnAccent, back, text)
	}
	// The edge of a box and of a secondary button, against what is round it.
	pair(look.EdgeControl, look.Surface, shape)
	pair(look.EdgeControl, look.Page, shape)
	// Copy stands inside the sunken line of a command or an address.
	pair(look.EdgeControl, look.Sunken, shape)
	// The primary button's face against the bar and the card it stands on.
	pair(look.Accent, look.Surface, shape)
	pair(look.Accent, look.Page, shape)
	// The ring round whatever holds the keyboard, on every surface.
	for _, back := range []look.Role{look.Page, look.Surface, look.Raised, look.Sunken} {
		pair(look.Focus, back, shape)
	}
	// The bar beside the chosen entry of a list, on that entry's face.
	pair(look.Chosen, look.Raised, shape)
	return out
}

func swatch(r look.Role) fyne.CanvasObject {
	chip := canvas.NewRectangle(look.Colour(r))
	chip.CornerRadius = look.RadiusControl
	chip.StrokeColor = look.Colour(look.EdgeControl)
	chip.StrokeWidth = look.Hairline
	chip.SetMinSize(fyne.NewSquareSize(look.SwatchSide))
	return chip
}

func swatchRow(r look.Role) fyne.CanvasObject {
	return parts.Row(look.GapField,
		swatch(r),
		parts.Middle(parts.Width(look.ColChosen*2, parts.Text(parts.Mono, string(r)))),
		parts.Middle(parts.Text(parts.MonoMuted, look.Hex(look.Colour(r)))),
	)
}

func swatches(title words.Key, roles ...look.Role) fyne.CanvasObject {
	rows := make([]fyne.CanvasObject, len(roles))
	for i, r := range roles {
		rows[i] = swatchRow(r)
	}
	return parts.Card(words.T(title), nil, parts.Stack(look.GapInline, rows...))
}

// Palette is the page of colours and of the contrast between them.
func Palette() fyne.CanvasObject {
	left := parts.Stack(look.GapCard,
		swatches(words.CatSurfaces, look.Page, look.Sunken, look.Surface, look.Raised, look.Hovered, look.EdgeCard, look.Divider, look.EdgeControl),
		swatches(words.CatInks, look.Ink, look.InkMuted, look.InkFaint, look.InkDisabled, look.InkOnStatus),
		swatches(words.CatStatuses, look.StatusPass, look.StatusWarn, look.StatusFail, look.StatusUnknown),
		swatches(words.CatAction, look.Accent, look.AccentHovered, look.AccentPressed, look.OnAccent, look.Focus, look.Chosen, look.Selection),
	)
	var rows []fyne.CanvasObject
	for _, p := range Pairs() {
		tone := look.TonePass
		if p.Ratio < p.Need {
			tone = look.ToneFail
		}
		kind := words.T(words.CatTextPair)
		if p.Need < 4.5 {
			kind = words.T(words.CatShapePair)
		}
		rows = append(rows, parts.Row(look.GapInline,
			parts.Middle(parts.Mark(tone, look.MarkInline)),
			parts.Middle(parts.Width(look.ColAnchors, parts.Number(parts.Mono, fmt.Sprintf("%.2f", p.Ratio)))),
			parts.Middle(parts.Width(look.SheetColumn/2, parts.Text(parts.MonoMuted, fmt.Sprintf("%s %.1f %s", words.T(words.CatNeed), p.Need, kind)))),
			parts.Middle(parts.Text(parts.Mono, p.Front+"  /  "+p.Back)),
		))
	}
	right := parts.Card(words.T(words.CatPairs), nil,
		parts.Para(parts.CaptionMuted, words.T(words.CatPairsNote)),
		parts.Stack(look.GapTight, rows...),
	)
	return page(words.CatPalette, parts.RowTop(look.GapCard, 1, parts.Width(look.SheetColumn, left), right))
}

func page(title words.Key, body fyne.CanvasObject) fyne.CanvasObject {
	return parts.Layers(canvas.NewRectangle(look.Colour(look.Page)),
		parts.Pad(look.InsetPage, parts.Stack(look.GapScreen, parts.Text(parts.Title, words.T(title)), body)))
}
