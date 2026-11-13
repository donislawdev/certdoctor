package parts

import (
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// LimitedEntry is a box of many lines that holds no more than Limit bytes of
// text (ADR144). A paste, a key or a line break that would carry it past the
// limit is refused whole - nothing of it goes in - and OnRefused is called.
// Whole rather than cut, because a token cut at a limit is another token, and
// one cut inside its signature still decodes (OBS229).
//
// EVERY WAY TEXT IS TYPED IN IS HELD: a paste by Ctrl+V and by the box's own
// menu both arrive as TypedShortcut - Fyne v2.8.2 builds the menu on the
// widget it extends - a character as TypedRune, and Enter and Tab as TypedKey,
// because Fyne puts their line break and tab in below TypedRune. Text set by
// the program with SetText is not held; nothing sets a tool's input but a
// person and Clear.
type LimitedEntry struct {
	widget.Entry
	Limit     int
	OnRefused func()
}

// NewLimitedEntry is a box of many lines holding at most limit bytes.
func NewLimitedEntry(limit int) *LimitedEntry {
	e := &LimitedEntry{Limit: limit}
	e.MultiLine = true
	e.ExtendBaseWidget(e)
	return e
}

// TypedShortcut refuses a paste that would carry the box past its limit.
func (e *LimitedEntry) TypedShortcut(s fyne.Shortcut) {
	if paste, ok := s.(*fyne.ShortcutPaste); ok && paste.Clipboard != nil && !e.Disabled() &&
		e.past(len(paste.Clipboard.Content()), true) {
		e.refuse()
		return
	}
	e.Entry.TypedShortcut(s)
}

// TypedRune refuses a character that would carry the box past its limit.
func (e *LimitedEntry) TypedRune(r rune) {
	if !e.Disabled() && e.past(utf8.RuneLen(r), true) {
		e.refuse()
		return
	}
	e.Entry.TypedRune(r)
}

// TypedKey refuses the line break and the tab that would carry the box past
// its limit. A line break is put in beside a selection rather than over it,
// so the selection is not counted as given back.
func (e *LimitedEntry) TypedKey(k *fyne.KeyEvent) {
	switch k.Name {
	case fyne.KeyReturn, fyne.KeyEnter, fyne.KeyTab:
		if !e.Disabled() && e.past(1, k.Name == fyne.KeyTab) {
			e.refuse()
			return
		}
	}
	e.Entry.TypedKey(k)
}

// Over says whether the box holds more than its limit - which nothing typed
// can make it, and text set by the program can.
func (e *LimitedEntry) Over() bool { return len(e.Text) > e.Limit }

// past says whether adding bytes would carry the box past its limit, with
// the selection given back first when what is added replaces it.
func (e *LimitedEntry) past(adding int, replacing bool) bool {
	kept := len(e.Text)
	if replacing {
		kept -= len(e.SelectedText())
	}
	return kept+adding > e.Limit
}

func (e *LimitedEntry) refuse() {
	if e.OnRefused != nil {
		e.OnRefused()
	}
}

// FieldNote is the line under a field: its hint, or - while what was given to
// the field is refused - the sentence saying why, with the sign the window's
// own messages carry (Message), which is never a status's hue.
//
// A WIDGET, NOT A STRUCT AROUND A CONTAINER: Fyne draws the children of a
// *fyne.Container and of a widget's renderer, and of nothing else. The first
// version embedded the container, was measured and laid out, and drew nothing
// - seen on the render of the catalogue 2026-11-12, past tests that read the
// container directly.
type FieldNote struct {
	widget.BaseWidget
	hint    string
	refused bool
	shown   *fyne.Container
}

// NewFieldNote is the line under a field showing hint.
func NewFieldNote(hint string) *FieldNote {
	n := &FieldNote{hint: hint, shown: Layers()}
	n.ExtendBaseWidget(n)
	n.Clear()
	return n
}

// CreateRenderer draws what the note shows.
func (n *FieldNote) CreateRenderer() fyne.WidgetRenderer { return widget.NewSimpleRenderer(n.shown) }

// Refuse shows why what was given to the field was not taken.
func (n *FieldNote) Refuse(sentence string) {
	n.refused = true
	n.show(Message(theme.ErrorIcon(), "", sentence))
}

// Clear shows the hint again.
func (n *FieldNote) Clear() {
	n.refused = false
	n.show(Para(CaptionMuted, n.hint))
}

// Refused says whether the note shows a refusal rather than the hint.
func (n *FieldNote) Refused() bool { return n.refused }

func (n *FieldNote) show(o fyne.CanvasObject) {
	n.shown.Objects = []fyne.CanvasObject{o}
	n.shown.Refresh()
	n.Refresh()
}
