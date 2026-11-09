package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// Style is a rung of the ladder of type together with its ink. Every word on
// screen is set in one of these and nothing else.
type Style int

const (
	Title Style = iota
	Heading
	Lead
	Body
	BodyMuted
	Strong
	Caption
	CaptionMuted
	CaptionStrong
	Mono
	MonoMuted
)

type rung struct {
	size fyne.ThemeSizeName
	ink  look.Role
	bold bool
	mono bool
}

var ladder = map[Style]rung{
	Title:         {theme.SizeNameHeadingText, look.Ink, true, false},
	Heading:       {theme.SizeNameSubHeadingText, look.Ink, true, false},
	Lead:          {look.SizeLead, look.Ink, false, false},
	Body:          {theme.SizeNameText, look.Ink, false, false},
	BodyMuted:     {theme.SizeNameText, look.InkMuted, false, false},
	Strong:        {theme.SizeNameText, look.Ink, true, false},
	Caption:       {theme.SizeNameCaptionText, look.Ink, false, false},
	CaptionMuted:  {theme.SizeNameCaptionText, look.InkMuted, false, false},
	CaptionStrong: {theme.SizeNameCaptionText, look.InkMuted, true, false},
	Mono:          {look.SizeMono, look.Ink, false, true},
	MonoMuted:     {look.SizeMono, look.InkMuted, false, true},
}

// Text is one line that does not wrap.
func Text(s Style, words string) fyne.CanvasObject {
	return tight(rich(s, words, "", fyne.TextWrapOff, fyne.TextTruncateOff, fyne.TextAlignLeading))
}

// Para is text that wraps at word boundaries to the width it is given.
func Para(s Style, words string) fyne.CanvasObject {
	return tight(rich(s, words, "", fyne.TextWrapWord, fyne.TextTruncateOff, fyne.TextAlignLeading))
}

// Code is text that wraps anywhere, for a command or a path - which has no
// word boundaries worth keeping and must never be cut short.
func Code(s Style, words string) fyne.CanvasObject {
	return tight(rich(s, words, "", fyne.TextWrapBreak, fyne.TextTruncateOff, fyne.TextAlignLeading))
}

// Clip is one line that ends in an ellipsis when it does not fit.
func Clip(s Style, words string) fyne.CanvasObject {
	return tight(rich(s, words, "", fyne.TextWrapOff, fyne.TextTruncateEllipsis, fyne.TextAlignLeading))
}

// Number is one line set against the trailing edge, for a column of figures.
func Number(s Style, words string) fyne.CanvasObject {
	return tight(rich(s, words, "", fyne.TextWrapOff, fyne.TextTruncateOff, fyne.TextAlignTrailing))
}

// Changing is one line that does not wrap and that a screen sets again while
// it stands - the time a run has taken. Set in place, so nothing around it is
// built again and nothing loses its state (GUI rule 3). A widget, because the
// toolkit draws a container or a widget and nothing that only wraps one.
type Changing struct {
	widget.BaseWidget
	text  *widget.RichText
	shown fyne.CanvasObject
}

// NewChanging is a changing line in style s, showing words.
func NewChanging(s Style, words string) *Changing {
	text := rich(s, words, "", fyne.TextWrapOff, fyne.TextTruncateOff, fyne.TextAlignLeading)
	c := &Changing{text: text, shown: tight(text)}
	c.ExtendBaseWidget(c)
	return c
}

// Set shows words, and does nothing when they are the ones shown.
func (c *Changing) Set(words string) {
	segment := c.text.Segments[0].(*widget.TextSegment)
	if segment.Text == words {
		return
	}
	segment.Text = words
	c.text.Refresh()
	c.Refresh()
}

// Words are the words shown.
func (c *Changing) Words() string { return c.text.Segments[0].(*widget.TextSegment).Text }

func (c *Changing) CreateRenderer() fyne.WidgetRenderer { return widget.NewSimpleRenderer(c.shown) }

// Inked is one line in a style's size and weight but another ink - the word
// of a badge, in the hue of its status.
func Inked(s Style, ink look.Role, words string) fyne.CanvasObject {
	return tight(rich(s, words, ink, fyne.TextWrapOff, fyne.TextTruncateOff, fyne.TextAlignLeading))
}

func rich(s Style, words string, ink look.Role, wrap fyne.TextWrap, cut fyne.TextTruncation, align fyne.TextAlign) *widget.RichText {
	r := ladder[s]
	if ink == "" {
		ink = r.ink
	}
	t := widget.NewRichText(&widget.TextSegment{
		Text: words,
		Style: widget.RichTextStyle{
			ColorName: fyne.ThemeColorName(ink),
			SizeName:  r.size,
			TextStyle: fyne.TextStyle{Bold: r.bold, Monospace: r.mono},
			Alignment: align,
		},
	})
	t.Wrapping = wrap
	t.Truncation = cut
	return t
}

// tight sets text without the room the toolkit keeps round it, which is the
// room of a box to type in. Text on its own keeps none, so the distances
// between words and the things beside them are the ones look names.
func tight(o fyne.CanvasObject) fyne.CanvasObject {
	return container.NewThemeOverride(o, tightTheme{look.Theme()})
}

type tightTheme struct{ fyne.Theme }

func (t tightTheme) Size(name fyne.ThemeSizeName) float32 {
	if name == theme.SizeNameInnerPadding {
		return 0
	}
	return t.Theme.Size(name)
}
