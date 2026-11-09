package screens

import (
	"slices"
	"strconv"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TestTheStartFormIsReadBackAsTheRequestItShows fills the start screen the way
// a person would - by typing into the fields and ticking the box, found on the
// screen by the words beside them - and reads the form back. Each option is
// read under its own switch, so a field wired to the wrong option, or an
// option the screen does not show, ends in the wrong command line.
func TestTheStartFormIsReadBackAsTheRequestItShows(t *testing.T) {
	newApp(t)
	page, form := Start(icon(t), "0.1.0", true)
	w := test.NewWindow(page)
	defer w.Close()

	test.Type(form.Address, " https://example.com ")
	values := map[string]string{"pac-url": "http://p/x.pac", "timeout": "0", "probe-timeout": "5"}
	for _, o := range request.Offered {
		switch control := fieldFor(t, page, words.T(o.Label)).(type) {
		case *widget.Entry:
			if o.Control() == request.Seconds && control.PlaceHolder != strconv.Itoa(o.Default) {
				t.Errorf("an empty %s shows %q, and means %d", o.Switch, control.PlaceHolder, o.Default)
			}
			test.Type(control, values[o.Switch])
		case *widget.Check:
			test.Tap(control)
		default:
			t.Fatalf("%s is set with %T", o.Switch, control)
		}
	}
	want := []string{"--json", "--pac-url=http://p/x.pac", "--timeout=0", "--probe-timeout=5", "--redact", "--", "https://example.com"}
	if got := form.Request().Args(); !slices.Equal(got, want) {
		t.Errorf("the filled form asks for\n %q\nwant %q", got, want)
	}
}

// fieldFor is the control in the same field as the label that reads label:
// the first entry or check met after it, in the order the screen is laid out.
func fieldFor(t *testing.T, page fyne.CanvasObject, label string) fyne.CanvasObject {
	t.Helper()
	var found fyne.CanvasObject
	seen := false
	walk(page, func(o fyne.CanvasObject) bool {
		switch v := o.(type) {
		case *widget.Label:
			seen = seen || v.Text == label
		case *widget.RichText:
			seen = seen || v.String() == label
		case *widget.Entry, *widget.Check:
			if seen {
				found = o
				return false
			}
		}
		return true
	})
	if found == nil {
		t.Fatalf("no control follows the label %q on the start screen", label)
	}
	return found
}

// walk visits o and everything inside it in layout order, depth first, until
// visit answers false.
func walk(o fyne.CanvasObject, visit func(fyne.CanvasObject) bool) bool {
	if !visit(o) {
		return false
	}
	var inside []fyne.CanvasObject
	switch v := o.(type) {
	case *fyne.Container:
		inside = v.Objects
	case fyne.Widget:
		if _, isEntry := v.(*widget.Entry); isEntry {
			return true
		}
		inside = test.WidgetRenderer(v).Objects()
	}
	for _, child := range inside {
		if !walk(child, visit) {
			return false
		}
	}
	return true
}
