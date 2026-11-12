package parts

import (
	"fyne.io/fyne/v2"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
)

// The parts a tool's answer is drawn with. ONE PART PER KIND OF BLOCK in the
// tools' contract (ADR141 point 5), so every tool - the decoder today, dozens
// later - is drawn by these and nothing of its own.

// Check is one judgement of a tool: the mark of its status, the sentence, and
// the status in words at the end, where the eye running down the list finds
// it.
func Check(s model.Status, summary string) fyne.CanvasObject {
	return RowTop(look.GapRow, 1,
		Mark(ToneOf(s), look.MarkRow),
		Para(Body, summary),
		Badge(s, look.Surface),
	)
}

// FieldRow is one row of a table of fields: a label, a value, a note beside
// the value, and a status when the row carries a judgement.
type FieldRow struct {
	Label, Value, Note string
	Status             model.Status
}

// Fields is a table of labels and values, the labels in a column of their
// own (GUI rule 13). A value breaks after a separator or at a space, never in
// the middle of a name - a key id, an issuer - which Path keeps whole.
func Fields(rows []FieldRow) fyne.CanvasObject {
	lines := make([]fyne.CanvasObject, 0, len(rows))
	for _, r := range rows {
		value := []fyne.CanvasObject{Path(Body, r.Value)}
		if r.Note != "" {
			// A paragraph, not a line: a note is the tool's words about data
			// from somebody else, and a line that cannot wrap widens the
			// window by as much as the data is long.
			value = append(value, Para(CaptionMuted, r.Note))
		}
		row := []fyne.CanvasObject{Width(look.LabelWidth, Para(BodyMuted, r.Label)), Stack(look.GapTight, value...)}
		if r.Status != "" {
			row = append(row, Badge(r.Status, look.Surface))
		}
		lines = append(lines, RowTop(look.GapRow, 1, row...))
	}
	return Stack(look.GapRow, lines...)
}

// CodeBlock is text shown exactly - a token's header, its payload - on the
// sunken surface code is set on, in the monospaced face. It breaks anywhere
// rather than run past its card: what it holds is read here and copied with
// the Copy beside its title, which copies it whole.
func CodeBlock(body string) fyne.CanvasObject {
	return Panel(look.Sunken, look.EdgeCard, look.RadiusControl, Pad(look.InsetCell, Code(Mono, body)))
}
