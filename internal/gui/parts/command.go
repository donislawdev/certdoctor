package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// Command is a line for a person to read and copy - a command to run, or an
// address to paste - never a button that runs it (docs/26 section 7.3). The
// line sits on the sunken surface code is set on, and the only action beside
// it is Copy.
func Command(command string, needsAdmin bool, elevation, caveat string, copyButton *Button) fyne.CanvasObject {
	if copyButton == nil {
		copyButton = NewButton(Secondary, words.T(words.Copy), theme.ContentCopyIcon(), nil)
	}
	block := Panel(look.Sunken, look.EdgeCard, look.RadiusControl,
		PadXY(look.InsetCell, look.InsetCell/2, RowGrow(look.GapInline, 0,
			Middle(Code(Mono, command)),
			Middle(copyButton),
		)),
	)
	rows := []fyne.CanvasObject{block}
	if needsAdmin {
		rows = append(rows, RowTop(look.GapInline, 1,
			Chip(nil, words.T(words.NeedsAdmin), look.Surface),
			Middle(Para(CaptionMuted, elevation)),
		))
	}
	if caveat != "" {
		rows = append(rows, Para(CaptionMuted, caveat))
	}
	return Stack(look.GapInline, rows...)
}
