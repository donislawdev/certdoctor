package parts

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TestAFoldOpensFromItsHeadAndKeepsWhatWasTyped presses a fold by pointer and
// by every key that presses one, and checks that what was typed in it is the
// same box with the same words after it was put away and opened again.
func TestAFoldOpensFromItsHeadAndKeepsWhatWasTyped(t *testing.T) {
	newApp(t)
	box := widget.NewEntry()
	fold := Fold("Options", "closed", false, box)
	pressed := 0
	fold.OnTapped = func() { pressed++ }
	w := test.NewTempWindow(t, fold)
	w.Resize(fyne.NewSize(look.ColumnWidth, 400))

	fold.Tapped(nil)
	if !fold.Open() || !fold.body.Visible() {
		t.Fatal("a press on a closed fold did not open it")
	}
	box.SetText("http://proxy.example:3128")
	for _, k := range []fyne.KeyName{fyne.KeySpace, fyne.KeyReturn, fyne.KeyEnter} {
		was := fold.Open()
		fold.TypedKey(&fyne.KeyEvent{Name: k})
		if fold.Open() == was {
			t.Errorf("%s did not open or close the fold", k)
		}
	}
	fold.TypedKey(&fyne.KeyEvent{Name: fyne.KeyTab})
	if fold.Open() || fold.body.Visible() {
		t.Fatal("after three presses and a Tab the fold should stand closed")
	}
	if pressed != 4 {
		t.Errorf("OnTapped was told %d presses, want 4 - a pointer and three keys, not Tab", pressed)
	}
	fold.Tapped(nil)
	if box.Text != "http://proxy.example:3128" {
		t.Errorf("the box holds %q after the fold was put away and opened", box.Text)
	}
}

// TestAPressOnWhatIsOpenIsNotAPressOnThePart - a command is read under a
// store's line, so a press there must not close it, and a disabled part is
// not pressed at all.
func TestAPressOnWhatIsOpenIsNotAPressOnThePart(t *testing.T) {
	newApp(t)
	fold := Fold("Options", "closed", true, Text(Body, "inside"))
	w := test.NewTempWindow(t, fold)
	w.Resize(fyne.NewSize(look.ColumnWidth, 400))
	head := fold.headHeight
	if head <= 0 || head >= fold.Size().Height {
		t.Fatalf("the head is %v tall in a part %v tall", head, fold.Size().Height)
	}
	fold.Tapped(&fyne.PointEvent{Position: fyne.NewPos(10, head+1)})
	if !fold.Open() {
		t.Fatal("a press below the head closed the fold")
	}
	fold.Tapped(&fyne.PointEvent{Position: fyne.NewPos(10, head-1)})
	if fold.Open() {
		t.Fatal("a press on the head did not close the fold")
	}
	// One press at a time: two would put back what the first did.
	fold.Disable()
	fold.Tapped(nil)
	if fold.Open() {
		t.Fatal("a disabled fold was opened by the pointer")
	}
	fold.TypedKey(&fyne.KeyEvent{Name: fyne.KeySpace})
	if fold.Open() {
		t.Fatal("a disabled fold was opened by a key")
	}
}

// TestOpeningAPartMakesRoomForIt opens a fold with a line under it: the fold
// asks for the room of what opened, and once laid out the line stands under
// it, not under what was drawn over it.
//
// What it does not see: the window laying itself out again on its own when a
// part grows. The real canvas does that before each frame (fyne v2.8.2,
// internal/driver/common/canvas.go, EnsureMinSize); the test canvas has no
// such step, so here the layout is asked for by resizing the window.
func TestOpeningAPartMakesRoomForIt(t *testing.T) {
	newApp(t)
	fold := Fold("Options", "closed", false, Height(200, Text(Body, "inside")))
	after := Text(Body, "after")
	w := test.NewTempWindow(t, Stack(0, fold, after))
	w.Resize(fyne.NewSize(look.ColumnWidth, 600))
	closed, asked := after.Position().Y, fold.MinSize().Height
	fold.Tapped(nil)
	if got := fold.MinSize().Height; got < asked+200 {
		t.Fatalf("the open fold asks for %v, closed it asked for %v - not the room of what opened", got, asked)
	}
	w.Resize(fyne.NewSize(look.ColumnWidth, 601))
	if got := after.Position().Y; got < closed+200 {
		t.Errorf("the line under the fold stands at %v, was %v - it did not move for what opened", got, closed)
	}
}

// TestAPartIsDrawnInTheStateItIsIn follows what the drawing of a part is
// asked for as the pointer and the keyboard move: the drawing is the only
// place a state shows, so a state that never reaches it shows nowhere.
func TestAPartIsDrawnInTheStateItIsIn(t *testing.T) {
	newApp(t)
	var drawn State
	p := NewPressable(func(s State, open bool) (fyne.CanvasObject, fyne.CanvasObject) {
		drawn = s
		return nil, Text(Body, "a part")
	}, nil, false)
	test.NewTempWindow(t, p)
	for i, step := range []struct {
		do   func()
		want State
	}{
		{p.FocusGained, Focused},
		{func() { p.MouseIn(nil) }, Hover},
		{func() { p.MouseDown(nil) }, Press},
		{func() { p.MouseUp(nil) }, Hover},
		{p.MouseOut, Focused},
		{p.FocusLost, Rest},
		{p.Disable, Disabled},
	} {
		step.do()
		if drawn != step.want {
			t.Fatalf("step %d: drawn as %d, want %d", i, drawn, step.want)
		}
	}
	if p.Cursor() != desktop.DefaultCursor {
		t.Error("a disabled part shows the hand that says it does something")
	}
	p.Enable()
	if p.Cursor() != desktop.PointerCursor {
		t.Error("a part that can be pressed does not show the hand")
	}
	if got := NewPressable(func(State, bool) (fyne.CanvasObject, fyne.CanvasObject) { return nil, Gap(0) }, nil, false).Pin(Hover).state(); got != Hover {
		t.Errorf("a pinned part is in state %d", got)
	}
}

// TestARailHasOneChosenLayer chooses layers by pointer and by call, and
// checks that one entry is open at a time and that whoever listens hears of
// a change and of nothing else.
func TestARailHasOneChosenLayer(t *testing.T) {
	newApp(t)
	layers := sample(t).Layers
	rail := NewRail("Layers", layers, 1)
	var told []int
	rail.OnChosen = func(i int) { told = append(told, i) }
	test.NewTempWindow(t, rail)

	rail.entries[3].Tapped(nil)
	rail.Choose(3)
	rail.Choose(-1)
	rail.Choose(len(layers))
	rail.entries[0].TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn})
	if rail.Chosen() != 0 || len(told) != 2 || told[0] != 3 || told[1] != 0 {
		t.Fatalf("chosen %d, told %v - want 0, told [3 0]", rail.Chosen(), told)
	}
	for i, e := range rail.entries {
		if e.Open() != (i == 0) {
			t.Errorf("entry %d open %v with layer 0 chosen", i, e.Open())
		}
	}
}

// TestAStoreOpensOnlyWhenItHasACommand - a row with a command opens to show
// it, and one with nothing to open is not pressed, not lit and not reached
// with the keyboard.
func TestAStoreOpensOnlyWhenItHasACommand(t *testing.T) {
	newApp(t)
	with := StoreRow(model.Store{Runtime: "node", Trust: model.TrustNo, Command: "export NODE_EXTRA_CA_CERTS=x"}, false)
	none := StoreRow(model.Store{Runtime: "java", Trust: model.TrustNotAssessed}, true)
	test.NewTempWindow(t, Stack(0, with, none))
	with.Tapped(nil)
	if !with.Open() {
		t.Error("a press did not open a store with a command")
	}
	none.Tapped(nil)
	none.MouseIn(nil)
	if none.Open() || !none.Disabled() || none.state() != Disabled {
		t.Errorf("a store with nothing to open: open %v, disabled %v, state %d", none.Open(), none.Disabled(), none.state())
	}
	if rowSurface(Disabled, false) != look.Surface || rowSurface(Press, false) != look.Raised {
		t.Error("a row is not raised under a press, or is raised with nothing to open")
	}
}

// TestAStoreIsNamedInFullHoweverLongItsPath - where a store lives and what
// chose it are shown whole. A row with no command opens nothing, so a path
// cut to the width of its column was a path nobody could read, and two stores
// under one long folder were the same line (seen on a screen on 2026-11-10).
// The row grows by the lines that do not fit on one.
func TestAStoreIsNamedInFullHoweverLongItsPath(t *testing.T) {
	newApp(t)
	short := model.Store{Runtime: "python", Trust: model.TrustYes, Instance: `C:\Python`, ChosenBy: []string{"PATH"}}
	path, chosen := short, short
	path.Instance = `C:\Users\jdoe\AppData\Local\Programs\A deliberately long folder name\that keeps going\python.exe`
	chosen.ChosenBy = []string{"PATH", "NODE_EXTRA_CA_CERTS", "registry", "pip.ini"}
	rows := []*Pressable{StoreRow(short, false), StoreRow(path, false), StoreRow(chosen, false)}
	w := test.NewTempWindow(t, Stack(0, rows[0], rows[1], rows[2]))
	// Twice, because a line learns how many lines it is from the width the
	// first layout gave it, and the test canvas lays out once for each resize
	// (TestOpeningAPartMakesRoomForIt says why).
	w.Resize(fyne.NewSize(look.WindowMinWidth, 600))
	w.Resize(fyne.NewSize(look.WindowMinWidth, 601))
	one := rows[0].MinSize().Height
	for i, what := range []string{"a long path", "a long list of what chose the store"} {
		if got := rows[i+1].MinSize().Height; got <= one {
			t.Errorf("a row with %s is %v tall, as tall as a row of one line (%v) - it was cut, not shown", what, got, one)
		}
	}
}

// TestCopyPutsTheLineOnTheClipboardAndSaysSo presses Copy and looks at it
// before and after the time it says Copied, and checks it is as wide saying
// either, so the line beside it does not move.
func TestCopyPutsTheLineOnTheClipboardAndSaysSo(t *testing.T) {
	newApp(t)
	var running []*fyne.Animation
	c := &copier{line: "certutil -user -addstore Root x.pem", start: func(a *fyne.Animation) { running = append(running, a) }}
	c.button = NewButton(Secondary, "", nil, c.copy)
	c.button.fits = []string{words.T(words.Copy), words.T(words.Copied)}
	c.say(false)
	test.NewTempWindow(t, c.button)
	before := c.button.MinSize()

	c.button.Tapped(nil)
	if got := fyne.CurrentApp().Clipboard().Content(); got != c.line {
		t.Fatalf("the clipboard holds %q", got)
	}
	if c.button.Label != words.T(words.Copied) || c.button.MinSize() != before {
		t.Fatalf("after a press the button says %q at %v, was %v", c.button.Label, c.button.MinSize(), before)
	}
	c.button.Tapped(nil)
	if len(running) != 2 {
		t.Fatalf("%d times were started for two presses", len(running))
	}
	running[1].Tick(0.5)
	if c.button.Label != words.T(words.Copied) {
		t.Error("the button stopped saying Copied before its time was up")
	}
	running[1].Tick(1)
	if c.button.Label != words.T(words.Copy) {
		t.Errorf("after its time the button says %q", c.button.Label)
	}

	shown := CopyButton("x", true)
	if shown.Label != words.T(words.Copied) {
		t.Errorf("a Copy shown just after a press says %q", shown.Label)
	}
}

// TestAMenuChoiceIsPressedLikeAnyPart opens the menu Save report opens and
// chooses from it the ways a person can: a click, Space and Enter on the
// choice holding the keyboard, the arrows to move it round, and Escape to
// leave without choosing.
func TestAMenuChoiceIsPressedLikeAnyPart(t *testing.T) {
	newApp(t)
	var chosen []int
	left := 0
	menu, rows := Menu([]MenuItem{{"HTML", "a page"}, {"Markdown", "text"}, {"JSON", "the report"}},
		func(i int) { chosen = append(chosen, i) }, func() { left++ })
	w := test.NewTempWindow(t, menu)
	w.Resize(fyne.NewSize(look.MenuWidth*2, 400))

	rows[1].Tapped(&fyne.PointEvent{})
	rows[2].TypedKey(&fyne.KeyEvent{Name: fyne.KeySpace})
	rows[0].TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn})
	if want := []int{1, 2, 0}; len(chosen) != 3 || chosen[0] != want[0] || chosen[1] != want[1] || chosen[2] != want[2] {
		t.Fatalf("a click on the second, Space on the third and Return on the first chose %v, want %v", chosen, want)
	}

	w.Canvas().Focus(rows[0])
	for _, step := range []struct {
		key  fyne.KeyName
		want int
	}{{fyne.KeyDown, 1}, {fyne.KeyDown, 2}, {fyne.KeyDown, 0}, {fyne.KeyUp, 2}, {fyne.KeyUp, 1}} {
		w.Canvas().Focused().TypedKey(&fyne.KeyEvent{Name: step.key})
		if got := w.Canvas().Focused(); got != rows[step.want] {
			t.Fatalf("%s moved the keyboard to %v, want the choice at %d", step.key, got, step.want)
		}
	}
	rows[1].TypedKey(&fyne.KeyEvent{Name: fyne.KeyEscape})
	rows[1].TypedKey(&fyne.KeyEvent{Name: fyne.KeyTab})
	if left != 1 || len(chosen) != 3 {
		t.Errorf("Escape and Tab left the menu %d time(s) and chose %v - Escape leaves once and chooses nothing", left, chosen)
	}
	if rows[1].Disabled() || rows[1].state() != Focused {
		t.Errorf("the choice holding the keyboard is drawn %v", rows[1].state())
	}
}

// TestAButtonFittedToItsWordsKeepsItsWidth - Save becomes Replace in the save
// dialog, and the Cancel beside it must not move when it does.
func TestAButtonFittedToItsWordsKeepsItsWidth(t *testing.T) {
	newApp(t)
	save := NewButton(Primary, "Save", nil, nil).Fit("Save", "Replace")
	wide := NewButton(Primary, "Replace", nil, nil)
	test.NewTempWindow(t, Stack(0, save, wide))
	before := save.MinSize()
	if before.Width != wide.MinSize().Width {
		t.Fatalf("Save fitted to Replace is %v wide, Replace is %v", before.Width, wide.MinSize().Width)
	}
	save.Label = "Replace"
	save.Refresh()
	if save.MinSize() != before {
		t.Errorf("saying Replace the button is %v, was %v", save.MinSize(), before)
	}
}

// menuOf is a menu that chooses nothing, for a part drawn on its own.
func menuOf(items []MenuItem) fyne.CanvasObject {
	m, _ := Menu(items, nil, nil)
	return m
}
