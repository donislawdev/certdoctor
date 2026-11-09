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
// it is Copy. copyButton nil is the Copy that copies this line.
func Command(command string, needsAdmin bool, elevation, caveat string, copyButton *Button) fyne.CanvasObject {
	if copyButton == nil {
		copyButton = CopyButton(command, false)
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

// CopyButton is the Copy beside a line: pressed, it puts the line on the
// clipboard and says Copied for look.CopiedFor, then Copy again. copied
// shows it as it is just after a press, and stays so - for the catalogue.
//
// It is as wide as the wider of the two words from the start, so the line
// beside it does not move when the words change (GUI rule 3).
func CopyButton(line string, copied bool) *Button {
	c := &copier{line: line, start: (*fyne.Animation).Start}
	c.button = NewButton(Secondary, "", nil, c.copy)
	c.button.fits = []string{words.T(words.Copy), words.T(words.Copied)}
	c.say(copied)
	return c.button
}

// copier is what a Copy button does: the clipboard, the word that says it
// happened, and the time after which it says Copy again.
type copier struct {
	line   string
	button *Button
	back   *fyne.Animation
	// start runs the time the button says Copied. The toolkit's own in the
	// window; a test holds it to look at the button in between.
	start func(*fyne.Animation)
}

func (c *copier) copy() {
	if a := fyne.CurrentApp(); a != nil {
		a.Clipboard().SetContent(c.line)
	}
	c.say(true)
	if c.back != nil {
		c.back.Stop()
	}
	c.back = fyne.NewAnimation(look.CopiedFor, func(done float32) {
		if done == 1 {
			c.say(false)
		}
	})
	c.back.Curve = fyne.AnimationLinear
	c.start(c.back)
}

// say sets the button's words and icon: Copied with a tick just after a
// press, Copy otherwise.
func (c *copier) say(copied bool) {
	c.button.Label, c.button.Icon = words.T(words.Copy), theme.ContentCopyIcon()
	if copied {
		c.button.Label, c.button.Icon = words.T(words.Copied), theme.ConfirmIcon()
	}
	c.button.Refresh()
}
