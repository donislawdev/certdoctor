package parts

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// limitedBox is a box holding at most ten bytes with text in it, on a window,
// with the clipboard holding clip, and the count of its refusals.
func limitedBox(t *testing.T, text, clip string) (*LimitedEntry, fyne.Window, *int) {
	t.Helper()
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
	e := NewLimitedEntry(10)
	e.SetText(text)
	refused := new(int)
	e.OnRefused = func() { *refused++ }
	w := test.NewTempWindow(t, e)
	fyne.CurrentApp().Clipboard().SetContent(clip)
	return e, w, refused
}

func paste(e *LimitedEntry) {
	e.TypedShortcut(&fyne.ShortcutPaste{Clipboard: fyne.CurrentApp().Clipboard()})
}

func TestABoxTakesNothingThatWouldCarryItPastItsLimit(t *testing.T) {
	for _, c := range []struct {
		name, text, clip string
		act              func(*LimitedEntry)
		wantLen          int
		refused          bool
	}{
		{"a paste that fits exactly", "12345", "67890", paste, 10, false},
		{"a paste one byte over", "12345", "678901", paste, 5, true},
		{"a paste over the whole of it, selected", "1234567890", "abcdefghij", func(e *LimitedEntry) {
			e.TypedShortcut(&fyne.ShortcutSelectAll{})
			paste(e)
		}, 10, false},
		{"a character at the limit", "1234567890", "", func(e *LimitedEntry) { e.TypedRune('x') }, 10, true},
		{"a character with room", "123456789", "", func(e *LimitedEntry) { e.TypedRune('x') }, 10, false},
		{"a character of two bytes with one left", "123456789", "", func(e *LimitedEntry) { e.TypedRune(rune(0x17c)) }, 9, true},
		{"Enter at the limit", "1234567890", "", func(e *LimitedEntry) { e.TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn}) }, 10, true},
		{"Enter with room", "123", "", func(e *LimitedEntry) { e.TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn}) }, 4, false},
		{"Tab at the limit", "1234567890", "", func(e *LimitedEntry) { e.TypedKey(&fyne.KeyEvent{Name: fyne.KeyTab}) }, 10, true},
		{"a key that adds nothing", "1234567890", "", func(e *LimitedEntry) { e.TypedKey(&fyne.KeyEvent{Name: fyne.KeyLeft}) }, 10, false},
		{"a disabled box refuses nothing itself", "1234567890", "", func(e *LimitedEntry) {
			e.Disable()
			e.TypedRune('x')
		}, 10, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, _, refused := limitedBox(t, c.text, c.clip)
			c.act(e)
			if len(e.Text) != c.wantLen || (*refused > 0) != c.refused {
				t.Errorf("holds %d bytes (%q) after %d refusal(s), want %d bytes and refused %v",
					len(e.Text), e.Text, *refused, c.wantLen, c.refused)
			}
		})
	}
}

// The box's own menu pastes through the same door as Ctrl+V - which is true
// only while Fyne builds the menu on the widget it extends, so this asks the
// menu itself rather than trusting that.
func TestTheBoxsMenuPastesThroughTheSameLimit(t *testing.T) {
	for _, c := range []struct {
		clip    string
		wantLen int
		refused bool
	}{{"678901", 5, true}, {"67890", 10, false}} {
		e, w, refused := limitedBox(t, "12345", c.clip)
		e.TappedSecondary(&fyne.PointEvent{})
		// In the language the toolkit speaks here: a test app takes the
		// system's, and only the window itself is held to English.
		tapMenuItem(t, w, lang.L("Paste"))
		if len(e.Text) != c.wantLen || (*refused > 0) != c.refused {
			t.Errorf("the menu pasting %d bytes: holds %d after %d refusal(s), want %d and refused %v",
				len(c.clip), len(e.Text), *refused, c.wantLen, c.refused)
		}
	}
}

func TestABoxKnowsWhenTheProgramPutMoreInItThanItTakes(t *testing.T) {
	e, _, _ := limitedBox(t, "1234567890", "")
	if e.Over() {
		t.Error("a box at its limit says it is over")
	}
	e.SetText(strings.Repeat("x", 11))
	if !e.Over() {
		t.Error("a box past its limit does not say so")
	}
}

func TestAFieldNoteTurnsFromTheHintToTheRefusalAndBack(t *testing.T) {
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
	n := NewFieldNote("the hint")
	test.NewTempWindow(t, n)
	if n.Refused() || !strings.Contains(textsUnder(n), "the hint") {
		t.Fatalf("a new note shows %q, refused %v", textsUnder(n), n.Refused())
	}
	n.Refuse("too long")
	if said := textsUnder(n); !n.Refused() || !strings.Contains(said, "too long") || strings.Contains(said, "the hint") {
		t.Errorf("a refusing note shows %q", said)
	}
	n.Clear()
	if n.Refused() || !strings.Contains(textsUnder(n), "the hint") {
		t.Errorf("a cleared note shows %q", textsUnder(n))
	}
}

// textsUnder are the words drawn under o, joined.
func textsUnder(o fyne.CanvasObject) string {
	var b strings.Builder
	var walk func(fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		switch x := o.(type) {
		case *widget.RichText:
			for _, s := range x.Segments {
				if text, ok := s.(*widget.TextSegment); ok {
					b.WriteString(text.Text + "\n")
				}
			}
		case *canvas.Text:
			b.WriteString(x.Text + "\n")
		case *fyne.Container:
			for _, c := range x.Objects {
				walk(c)
			}
		case fyne.Widget:
			for _, c := range test.WidgetRenderer(x).Objects() {
				walk(c)
			}
		}
	}
	walk(o)
	return b.String()
}

// tapMenuItem taps the item labelled label of the menu open over w.
func tapMenuItem(t *testing.T, w fyne.Window, label string) {
	t.Helper()
	top := w.Canvas().Overlays().Top()
	if top == nil {
		t.Fatal("no menu is open")
	}
	var found fyne.Tappable
	var seen []string
	var walk func(o fyne.CanvasObject, nearest fyne.Tappable)
	walk = func(o fyne.CanvasObject, nearest fyne.Tappable) {
		if tappable, ok := o.(fyne.Tappable); ok {
			nearest = tappable
		}
		switch x := o.(type) {
		case *canvas.Text:
			seen = append(seen, x.Text)
			if x.Text == label && found == nil {
				found = nearest
			}
		case *fyne.Container:
			for _, c := range x.Objects {
				walk(c, nearest)
			}
		case fyne.Widget:
			for _, c := range test.WidgetRenderer(x).Objects() {
				walk(c, nearest)
			}
		}
	}
	walk(top, nil)
	if found == nil {
		t.Fatalf("the menu %T has no item %s - its words: %q", top, label, seen)
	}
	found.Tapped(&fyne.PointEvent{})
}
