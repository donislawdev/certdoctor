package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
)

// ToneOf is the tone of a report status. The four words are the report's
// own and so is their meaning; the window only decides how each one looks.
func ToneOf(s model.Status) look.Tone {
	switch s {
	case model.Pass:
		return look.TonePass
	case model.Warn:
		return look.ToneWarn
	case model.Fail:
		return look.ToneFail
	case model.Unknown:
		return look.ToneUnknown
	}
	return look.ToneNeutral
}

// Badge is a status as a pill: its mark and its word on a tint of its hue.
// over is the surface the badge stands on, so the tint is mixed against
// what is really under it.
func Badge(s model.Status, over look.Role) fyne.CanvasObject {
	return badge(ToneOf(s), string(s), over)
}

// Pill is the same shape for a three-state fact that is not a status - a
// store that trusts the chain, does not, or was not assessed. It borrows
// the look of the status it maps to, and the word says which fact it is.
func Pill(t look.Tone, word string, over look.Role) fyne.CanvasObject {
	return badge(t, word, over)
}

func badge(t look.Tone, word string, over look.Role) fyne.CanvasObject {
	face := canvas.NewRectangle(look.Tint(t, over))
	face.StrokeColor = look.TintEdge(t, over)
	face.StrokeWidth = look.Hairline
	face.CornerRadius = look.BadgeHeight / 2
	ink := look.ToneRole(t)
	content := PadXY(look.InsetBadge, 0, Row(look.GapMark,
		Middle(Mark(t, look.MarkInline)),
		Middle(Inked(CaptionStrong, ink, word)),
	))
	return Height(look.BadgeHeight, Layers(face, Middle(content)))
}

// Chip is a neutral pill with a word, for a fact about a command that is
// not a status - that it needs administrator rights.
func Chip(icon fyne.Resource, word string, over look.Role) fyne.CanvasObject {
	face := canvas.NewRectangle(look.Colour(over))
	face.StrokeColor = look.Colour(look.EdgeControl)
	face.StrokeWidth = look.Hairline
	face.CornerRadius = look.BadgeHeight / 2
	parts := []fyne.CanvasObject{}
	if icon != nil {
		img := canvas.NewImageFromResource(icon)
		img.SetMinSize(fyne.NewSquareSize(look.MarkInline))
		parts = append(parts, Middle(img))
	}
	parts = append(parts, Middle(Text(CaptionStrong, word)))
	return Height(look.BadgeHeight, Layers(face, Middle(PadXY(look.InsetBadge, 0, Row(look.GapMark, parts...)))))
}
