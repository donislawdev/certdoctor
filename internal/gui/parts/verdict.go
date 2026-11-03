package parts

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// Verdict is the sentence at the top of the report, the way the HTML report
// draws it: a card with a bar of the status's hue down its leading edge and
// the large mark beside the sentence. The hue is a bar and a mark and never
// the whole card - a card filled red is a louder claim than the sentence in
// it, and the sentence is the claim (docs/26 section 7.3).
func Verdict(r model.Report) fyne.CanvasObject {
	tone := ToneOf(r.Verdict.Status)
	meta := Row(look.GapField,
		Text(CaptionMuted, fmt.Sprintf("%s %d", words.T(words.ExitCode), r.Verdict.ExitCode)),
		Text(CaptionMuted, fmt.Sprintf("%s %.1f s", words.T(words.Duration), float64(r.DurationMS)/1000)),
		Text(CaptionMuted, fmt.Sprintf("%s %s", words.T(words.Privilege), r.Privilege)),
		Text(CaptionMuted, fmt.Sprintf("%s %s/%s", words.T(words.Platform), r.OS, r.Arch)),
	)
	body := RowTop(look.GapField, 1,
		Mark(tone, look.MarkLarge),
		Stack(look.GapRow,
			Inked(Heading, look.ToneRole(tone), string(r.Verdict.Status)),
			Limit(look.ProseWidth, Para(Lead, r.Verdict.Sentence)),
			meta,
		),
	)
	face := canvas.NewRectangle(look.Colour(look.Surface))
	face.CornerRadius = look.RadiusCard
	face.StrokeColor = look.Colour(look.EdgeCard)
	face.StrokeWidth = look.Hairline
	stripe := canvas.NewRectangle(look.Colour(look.ToneRole(tone)))
	stripe.CornerRadius = look.StrokeVerdict / 2
	stripe.SetMinSize(fyne.NewSize(look.StrokeVerdict, 0))
	return Layers(face, RowGrow(0, 1,
		Tall(Inset(look.GapInline, look.InsetCard, 0, look.InsetCard, stripe)),
		Pad(look.InsetCard, body),
	))
}
