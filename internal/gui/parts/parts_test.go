package parts

import (
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
)

// TestAButtonDoesWhatItSaysAndNothingWhenDisabled presses a button by pointer
// and by every key that presses one, and then the same disabled.
func TestAButtonDoesWhatItSaysAndNothingWhenDisabled(t *testing.T) {
	newApp(t)
	pressed := 0
	b := NewButton(Primary, "Diagnose", theme.SearchIcon(), func() { pressed++ })
	b.Tapped(nil)
	for _, k := range []fyne.KeyName{fyne.KeySpace, fyne.KeyReturn, fyne.KeyEnter, fyne.KeyTab} {
		b.TypedKey(&fyne.KeyEvent{Name: k})
	}
	if pressed != 4 {
		t.Fatalf("pressed %d times, want 4 - a pointer and three keys, not Tab", pressed)
	}
	b.Disable()
	b.Tapped(nil)
	b.TypedKey(&fyne.KeyEvent{Name: fyne.KeySpace})
	if pressed != 4 || !b.Disabled() {
		t.Fatalf("a disabled button was pressed: %d", pressed)
	}
	b.Enable()
	NewButton(Quiet, "no action", nil, nil).Tapped(nil)
}

// TestAButtonShowsWhatThePointerAndTheKeyboardDo follows one button through
// every state the pointer and the keyboard put it in, in the order they win.
func TestAButtonShowsWhatThePointerAndTheKeyboardDo(t *testing.T) {
	newApp(t)
	b := NewButton(Secondary, "Save report", nil, nil)
	w := test.NewTempWindow(t, b)
	w.Resize(fyne.NewSize(200, 60))
	steps := []struct {
		do   func()
		want State
	}{
		{func() {}, Rest},
		{b.FocusGained, Focused},
		{func() { b.MouseIn(nil) }, Hover},
		{func() { b.MouseDown(nil) }, Press},
		{func() { b.MouseUp(nil) }, Hover},
		{b.MouseOut, Focused},
		{b.FocusLost, Rest},
		{b.Disable, Disabled},
	}
	for i, s := range steps {
		s.do()
		if got := b.state(); got != s.want {
			t.Fatalf("step %d: state %d, want %d", i, got, s.want)
		}
	}
	b.MouseMoved(nil)
	b.TypedRune('x')
	if b.Cursor() == nil {
		t.Error("a button has no pointer cursor")
	}
	if got := NewButton(Quiet, "pinned", nil, nil).Pin(Press).state(); got != Press {
		t.Errorf("a pinned button is in state %d", got)
	}
}

// TestEveryKindOfButtonIsPaintedInEveryState asks the palette for the colours
// of every button and holds its words to the ratio for words, apart from a
// disabled one, which is kept under it on purpose.
func TestEveryKindOfButtonIsPaintedInEveryState(t *testing.T) {
	for _, k := range []Kind{Primary, Secondary, Quiet} {
		for _, s := range []State{Rest, Hover, Press, Focused, Disabled} {
			face, edge, ink := paint(k, s)
			for _, r := range []look.Role{face, edge, ink} {
				if r != "" && !look.Known(r) {
					t.Errorf("kind %d state %d is painted with %q, which has no colour", k, s, r)
				}
			}
			under := face
			if under == "" {
				under = look.Page
			}
			if s != Disabled && look.Contrast(look.Colour(ink), look.Colour(under)) < 4.5 {
				t.Errorf("kind %d state %d: %s on %s is under 4.5", k, s, ink, under)
			}
		}
	}
}

// TestAStatusHasItsToneAndItsMark - four statuses, four tones, four marks,
// and a fifth value of neither kind lands on the neutral tone.
func TestAStatusHasItsToneAndItsMark(t *testing.T) {
	newApp(t)
	seen := map[look.Tone]bool{}
	marks := map[string]bool{}
	for _, s := range []model.Status{model.Pass, model.Warn, model.Fail, model.Unknown} {
		tone := ToneOf(s)
		seen[tone] = true
		marks[markResource(tone).Name()] = true
	}
	if len(seen) != 4 || len(marks) != 4 || seen[look.ToneNeutral] {
		t.Fatalf("four statuses gave %d tones and %d marks", len(seen), len(marks))
	}
	if ToneOf("SOMETHING") != look.ToneNeutral {
		t.Error("an unknown status is not neutral")
	}
	for _, tr := range []model.Trust{model.TrustYes, model.TrustNo, model.TrustNotAssessed} {
		if tone, key := TrustTone(tr); tone == look.ToneNeutral || key == "" {
			t.Errorf("the answer %d has tone %d and words %q", tr, tone, key)
		}
	}
}

// TestTheLayoutsAddWhatTheySay measures the layouts against what they are
// told: a gap between children and none after the last, a hidden child that
// takes no room, a fixed width and height.
func TestTheLayoutsAddWhatTheySay(t *testing.T) {
	newApp(t)
	box := func() fyne.CanvasObject { return Box(40, 20, canvas.NewRectangle(nil)) }
	hidden := box()
	hidden.Hide()
	if got := Stack(10, box(), hidden, box()).MinSize(); got != fyne.NewSize(40, 50) {
		t.Errorf("Stack is %v, want 40x50", got)
	}
	if got := Row(10, box(), box(), hidden).MinSize(); got != fyne.NewSize(90, 20) {
		t.Errorf("Row is %v, want 90x20", got)
	}
	if got := Pad(5, box()).MinSize(); got != fyne.NewSize(50, 30) {
		t.Errorf("Pad is %v, want 50x30", got)
	}
	if got := PadXY(5, 1, box()).MinSize(); got != fyne.NewSize(50, 22) {
		t.Errorf("PadXY is %v, want 50x22", got)
	}
	if got := Width(70, box()).MinSize().Width; got != 70 {
		t.Errorf("Width is %v, want 70", got)
	}
	if got := Height(70, box()).MinSize().Height; got != 70 {
		t.Errorf("Height is %v, want 70", got)
	}
	// A floor on each side, and the object's own size where it asks for more.
	if got := AtLeast(70, 10, box()).MinSize(); got != fyne.NewSize(70, 20) {
		t.Errorf("AtLeast is %v, want 70x20", got)
	}
	if got := AtLeast(10, 70, box()).MinSize(); got != fyne.NewSize(40, 70) {
		t.Errorf("AtLeast is %v, want 40x70", got)
	}
	filled := box()
	floored := AtLeast(70, 10, filled)
	floored.Resize(fyne.NewSize(300, 200))
	if got := filled.Size(); got != fyne.NewSize(300, 200) {
		t.Errorf("AtLeast gives its object %v, want all of 300x200", got)
	}

	grow := box()
	line := RowGrow(10, 1, box(), grow, box())
	w := test.NewTempWindow(t, line)
	w.SetPadded(false)
	w.Resize(fyne.NewSize(300, 40))
	if got := grow.Size().Width; got != 300-40-40-20 {
		t.Errorf("the growing child is %v wide, want the 200 left over", got)
	}
}

// TestEveryPartBuildsAndDraws puts one of each part on a canvas and draws it,
// with a report the window was really given - a part that panics on real data
// would take the screen down with it.
func TestEveryPartBuildsAndDraws(t *testing.T) {
	newApp(t)
	r := sample(t)
	l5 := r.Layers[len(r.Layers)-1]
	copyButton := NewButton(Secondary, "Copy", theme.ContentCopyIcon(), nil)
	entry := widget.NewEntry()
	all := Stack(look.GapCard,
		Header(nil, "certdoctor", r.Version, NewButton(Quiet, "GitHub", nil, nil), NewButton(Quiet, "Donate", Heart(), nil)),
		Verdict(r),
		RowTop(look.GapCard, 1, Width(look.RailWidth, NewRail("Layers", r.Layers, len(r.Layers)-1)), Matrix(l5.Stores, 0)),
		MatrixHead(),
		StoreRow(l5.Stores[0], true).Pin(Hover),
		StoreRow(model.Store{Runtime: "java", Trust: model.TrustNotAssessed}, true),
		RailEntry(l5, true).Pin(Focused),
		RailItem(l5, false, Press),
		Card("Findings", Middle(Text(CaptionMuted, "3")), Finding("trust_store", "a sentence"), Rule()),
		Panel(look.Raised, look.EdgeCard, look.RadiusCard, Upright()),
		Bar(Text(Body, "bar")),
		Command("certutil -addstore Root <file>", true, "administrator", "in cmd.exe", copyButton),
		Command("echo", false, "", "", nil),
		Form(Field("Address", entry, "a note"), Field("Time limit", Own(widget.NewCheck("", nil)), "")),
		Fold("Options", "closed", false, Text(Body, "inside")),
		Fold("Options", "closed", true, Text(Body, "inside")).Pin(Focused),
		Fold("Options", "closed", false).Pin(Press),
		menuOf([]MenuItem{{Name: "HTML", Note: "a page"}, {Name: "JSON", Note: "the report"}}),
		Message(theme.ErrorIcon(), "The report was not saved", "a sentence"),
		Message(nil, "", "Saving the report"),
		NewButton(Primary, "Save", nil, nil).Fit("Save", "Replace"),
		Notice("The page did not open", "Copy the address.", "https://github.com/donislawdev/certdoctor"),
		Problem("certdoctor stopped", "what", "todo", "printed", NewButton(Primary, "Back", nil, nil)),
		Problem("certdoctor stopped", "", "todo", "", NewButton(Primary, "Back", nil, nil)),
		Empty("nothing here"),
		NewTrack(0), NewTrack(0.5), NewTrack(1), NewTrack(2), NewChanging(BodyMuted, "12 s"),
		Row(look.GapInline, Mark(look.TonePass, look.MarkInline), Badge(model.Fail, look.Page),
			Pill(look.ToneWarn, "word", look.Surface), Chip(theme.InfoIcon(), "chip", look.Surface), AppMark(nil)),
		Text(Title, "title"), Para(Lead, "lead"), Code(Mono, "code"), Clip(Heading, "clipped"),
		Number(CaptionStrong, "12"), Inked(Strong, look.StatusFail, "inked"),
		Column(look.ColumnWidth, Limit(200, Middle(Tall(Text(Caption, "tall"))))),
		Layers(Gap(10), Text(BodyMuted, "layered")),
	)
	w := test.NewTempWindow(t, Inset(0, 0, 0, 0, all))
	w.Resize(fyne.NewSize(look.WindowWidth, 4000))
	if img := w.Canvas().Capture(); img.Bounds().Dx() == 0 {
		t.Fatal("nothing was drawn")
	}
	copyButton.Tapped(nil)
}

func newApp(t *testing.T) {
	t.Helper()
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
}

func sample(t *testing.T) model.Report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "model", "testdata", "example-com.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := model.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestATrackAndALineChangeInPlace - the running screen moves the track and
// sets the time again while it stands: the share is held between nothing and
// all and drawn as that much of the width, and the words are the ones set.
func TestATrackAndALineChangeInPlace(t *testing.T) {
	newApp(t)
	track := NewTrack(0.2)
	line := NewChanging(BodyMuted, "1 s")
	w := test.NewTempWindow(t, Stack(0, track, line))
	w.Resize(fyne.NewSize(400, 100))
	for _, c := range []struct{ set, want float32 }{{0.5, 0.5}, {2, 1}, {-1, 0}, {0.25, 0.25}, {0.25, 0.25}} {
		track.SetShare(c.set)
		over := test.TempWidgetRenderer(t, track).Objects()[1]
		if track.Share() != c.want || over.Size().Width < track.Size().Width*c.want-0.5 || over.Size().Width > track.Size().Width*c.want+0.5 {
			t.Errorf("set to %v: share %v, drawn %v of %v - want %v of it", c.set, track.Share(), over.Size().Width, track.Size().Width, c.want)
		}
	}
	for _, words := range []string{"2 s", "2 s", "10 s of the 60 s limit"} {
		line.Set(words)
		if line.Words() != words {
			t.Errorf("set to %q, shows %q", words, line.Words())
		}
	}
}
