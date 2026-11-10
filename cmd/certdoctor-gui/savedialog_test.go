//go:build cgo

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// reported is a window showing the example.com report, its run begun at the
// test's clock, 2026-11-09 12:00 UTC.
func reported(t *testing.T) (*window, *held) {
	t.Helper()
	win, h, _ := testWindow(t)
	win.form.Address.SetText("https://example.com")
	win.diagnose()
	h.runs[0].done(flow.Process{Out: exampleReport(t), Code: 4})
	if win.flow.Phase() != flow.Reported {
		t.Fatalf("the example report left the window on %d", win.flow.Phase())
	}
	return win, h
}

// TestSaveReportOpensItsMenuAndTheDialogForTheChoice presses Save report on
// the report screen and chooses from its menu with the keyboard, the way a
// person without a mouse does.
func TestSaveReportOpensItsMenuAndTheDialogForTheChoice(t *testing.T) {
	win, _ := reported(t)
	save, ok := findButton(win.w.Content(), words.T(words.SaveReport)).(*parts.Button)
	if !ok || save.Disabled() {
		t.Fatal("the report screen has no Save report to press")
	}
	save.Tapped(nil)
	row, ok := win.w.Canvas().Focused().(*parts.Pressable)
	if !ok {
		t.Fatalf("the menu opened with the keyboard on %v, want its first choice", win.w.Canvas().Focused())
	}
	row.TypedKey(&fyne.KeyEvent{Name: fyne.KeyDown})
	win.w.Canvas().Focused().TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn})
	if win.saving == nil || win.saving.save.Format() != request.SaveFormats[1] {
		t.Fatalf("Down and Return in the menu opened %+v, want the dialog for %s", win.saving, request.SaveFormats[1].Value)
	}
	if win.w.Canvas().Focused() != win.saving.view.Name {
		t.Error("the dialog opened without the keyboard in the name")
	}
}

// TestSaveReportWritesTheReportTheWindowDrew - the dialog opens in the folder
// last saved to under the name the run suggests, and the command line is
// handed the very bytes the window drew, with --from, --format and --out.
func TestSaveReportWritesTheReportTheWindowDrew(t *testing.T) {
	win, h := reported(t)
	folder := t.TempDir()
	win.prefs.SetString(lastFolder, folder)
	win.saveAs(request.SaveFormats[0])
	d := win.saving
	name := "certdoctor-example.com-20261109T120000Z.html"
	if d.view.Folder.Text != folder || d.view.Name.Text != name {
		t.Fatalf("the dialog opened in %q with %q, want %q and %q", d.view.Folder.Text, d.view.Name.Text, folder, name)
	}
	// Saved somewhere else this time: the folder kept for the next copy is
	// the one this copy went to.
	folder = t.TempDir()
	d.view.Folder.SetText(folder)

	d.view.Save.Tapped(nil)
	if len(h.runs) != 2 {
		t.Fatalf("Save started %d run(s) after the diagnosis, want one", len(h.runs)-1)
	}
	run := h.runs[1]
	if want := request.SaveArgs(request.SaveFormats[0], filepath.Join(folder, name)); !slices.Equal(run.args, want) {
		t.Errorf("the copy was asked as %q, want %q", run.args, want)
	}
	if !slices.Equal(run.input, exampleReport(t)) {
		t.Errorf("the command line was handed %d bytes, want the %d the window drew", len(run.input), len(exampleReport(t)))
	}
	if deadline, ok := run.ctx.Deadline(); !ok || time.Until(deadline) > flow.Grace {
		t.Errorf("writing the copy ends at %v (%v), want within %v", deadline, ok, flow.Grace)
	}
	if !d.view.Name.Disabled() || !d.view.Cancel.Disabled() {
		t.Error("the dialog can be used while the copy is written")
	}

	run.done(flow.Process{Code: 0, Printed: []byte("certdoctor: report written\n")})
	if d.save.Step() != flow.SaveDone || run.ctx.Err() == nil || win.prefs.String(lastFolder) != folder {
		t.Fatalf("a copy written left the dialog at %d, its run's context %v, the folder kept %q",
			d.save.Step(), run.ctx.Err(), win.prefs.String(lastFolder))
	}
	if win.w.Canvas().Focused() != d.view.Close {
		t.Error("the copy written does not give the keyboard to Close")
	}
	d.view.Close.Tapped(nil)
	if win.saving != nil || len(win.w.Canvas().Overlays().List()) != 0 {
		t.Error("Close left the dialog standing")
	}
}

// TestAFileInTheWayIsReplacedOnlyWhenAskedTo - Save over a file that is there
// runs nothing and says so, a second press replaces it, and a refusal of the
// command line is shown in its own words with the form to try again.
func TestAFileInTheWayIsReplacedOnlyWhenAskedTo(t *testing.T) {
	win, h := reported(t)
	folder := t.TempDir()
	win.prefs.SetString(lastFolder, folder)
	asked := []string{}
	win.present = func(p string) bool {
		asked = append(asked, p)
		return true
	}
	win.saveAs(request.SaveFormats[2])
	d := win.saving
	d.view.Name.SetText("old")
	d.view.Save.Tapped(nil)
	path := filepath.Join(folder, "old.json")
	if len(h.runs) != 1 || d.save.Step() != flow.SaveTaken || !slices.Equal(asked, []string{path}) {
		t.Fatalf("Save over a file in the way ran %d time(s), the dialog is at %d, asked about %q",
			len(h.runs)-1, d.save.Step(), asked)
	}
	if d.view.Save.Label != words.T(words.SaveReplace) {
		t.Errorf("the dialog asks with %q, want %q", d.view.Save.Label, words.T(words.SaveReplace))
	}
	d.view.Save.Tapped(nil)
	if len(h.runs) != 2 || h.runs[1].args[2] != "--out="+path {
		t.Fatalf("Replace ran %d time(s)", len(h.runs)-1)
	}

	h.runs[1].done(flow.Process{Code: 6, Printed: []byte("certdoctor: moving the finished report to " + path + ": Access is denied.\n")})
	if d.save.Step() != flow.SaveFailed || d.view.Save.Disabled() || d.view.Name.Disabled() {
		t.Fatalf("a refusal left the dialog at %d, Save disabled %v", d.save.Step(), d.view.Save.Disabled())
	}
	if d.save.Said() != "Moving the finished report to "+path+": Access is denied." {
		t.Errorf("the refusal is said as %q", d.save.Said())
	}
	if win.prefs.String(lastFolder) != folder {
		t.Error("a copy that was not written moved the folder kept")
	}
	d.view.Cancel.Tapped(nil)
	if win.saving != nil {
		t.Error("Cancel left the dialog standing")
	}
}

// TestTheDialogOpensAtHomeTheFirstTime - with no folder kept, the person's own
// folder rather than wherever the window was started from.
func TestTheDialogOpensAtHomeTheFirstTime(t *testing.T) {
	win, _ := reported(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home folder on this system:", err)
	}
	win.saveAs(request.SaveFormats[0])
	if got := win.saving.view.Folder.Text; got != home {
		t.Errorf("the dialog opened in %q, want %q", got, home)
	}
}

// TestClosingTheWindowEndsTheCopy - a copy left being written would write for
// a window that is gone.
func TestClosingTheWindowEndsTheCopy(t *testing.T) {
	test.NewTempApp(t)
	h := &held{}
	win := newWindow(test.NewWindow(nil), nil, "0.1.0", false, h)
	win.wait = h.wait
	win.present = func(string) bool { return false }
	win.form.Address.SetText("https://example.com")
	win.diagnose()
	h.runs[0].done(flow.Process{Out: exampleReport(t), Code: 4})
	win.prefs.SetString(lastFolder, t.TempDir())
	win.saveAs(request.SaveFormats[0])
	win.saving.view.Save.Tapped(nil)
	win.w.Close()
	if len(h.runs) != 2 || h.runs[1].ctx.Err() == nil {
		t.Error("closing the window left the copy being written")
	}
}

// findButton is the button with these words on a drawn screen, looked for
// through the containers the screen is built of and the scroll it stands in.
func findButton(o fyne.CanvasObject, label string) fyne.CanvasObject {
	switch x := o.(type) {
	case *parts.Button:
		if x.Label == label {
			return x
		}
	case *container.Scroll:
		return findButton(x.Content, label)
	case *fyne.Container:
		for _, child := range x.Objects {
			if found := findButton(child, label); found != nil {
				return found
			}
		}
	}
	return nil
}

// TestChooseOpensTheFolderDialogOverTheDialog - Choose stands the toolkit's
// folder dialog over the save dialog, in the window's words rather than the
// system's language (OBS206). Choosing a folder in it is not driven here: the
// answer comes back through URI.Path, read in fyne v2.8.2.
func TestChooseOpensTheFolderDialogOverTheDialog(t *testing.T) {
	win, _ := reported(t)
	win.prefs.SetString(lastFolder, t.TempDir())
	win.saveAs(request.SaveFormats[0])
	before := len(win.w.Canvas().Overlays().List())
	win.saving.view.Choose.Tapped(nil)
	if got := len(win.w.Canvas().Overlays().List()); got != before+1 {
		t.Fatalf("Choose left %d things over the screen, want the save dialog and the folder dialog over it (%d)", got, before+1)
	}
	top := win.w.Canvas().Overlays().Top()
	for _, said := range []string{words.T(words.SaveChooseTitle), words.T(words.SaveUseFolder), words.T(words.Cancel)} {
		if !shows(top, said) {
			t.Errorf("the folder dialog does not say %q", said)
		}
	}
	// At the size look names and not at the least the toolkit can draw it
	// in, which is where it opens when nobody asks: five places and a row and
	// a half of folders, seen on a screen on 2026-11-10. What stands over the
	// screen is the toolkit's own container, and the dialog is the pop-up
	// inside it.
	want := fyne.NewSize(look.ChooserWidth, look.ChooserHeight)
	var dialog *widget.PopUp
	for _, o := range test.WidgetRenderer(top.(fyne.Widget)).Objects() {
		if pop, ok := o.(*widget.PopUp); ok {
			dialog = pop
		}
	}
	if dialog == nil {
		t.Fatal("nothing over the screen is the folder dialog's pop-up")
	}
	if got := dialog.Size(); got != want {
		t.Errorf("the folder dialog is %v, want %v", got, want)
	}
	if least := dialog.MinSize(); least.Width >= want.Width || least.Height >= want.Height {
		t.Errorf("the folder dialog cannot be drawn in less than %v, and look asks for %v - the size asked for no longer decides", least, want)
	}
}

// shows says whether o, or anything drawn inside it, shows words - a label or
// a button of the toolkit's, looked for through containers and widgets alike.
func shows(o fyne.CanvasObject, words string) bool {
	switch x := o.(type) {
	case *widget.Label:
		if x.Text == words {
			return true
		}
	case *widget.Button:
		if x.Text == words {
			return true
		}
	}
	var inside []fyne.CanvasObject
	switch x := o.(type) {
	case *fyne.Container:
		inside = x.Objects
	case fyne.Widget:
		inside = test.WidgetRenderer(x).Objects()
	}
	for _, child := range inside {
		if shows(child, words) {
			return true
		}
	}
	return false
}
