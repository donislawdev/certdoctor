package screens

import (
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// longName stands for a name a person typed that keeps going, and a folder
// several levels down.
var (
	longName   = strings.Repeat("certdoctor-a-deliberately-long-name-", 4) + "20261110T133005Z.html"
	longFolder = `C:\Users\jdoe\Documents\A deliberately long folder name\that keeps going\Reports for the ticket`
)

// TestTheSaveDialogFitsTheSmallestWindow draws the dialog in every step, with
// the longest words each step can carry, and fails when it asks for more room
// than the smallest window has - or when what it holds asks for more width
// than the dialog gives it, which the dialog would cut rather than show.
func TestTheSaveDialogFitsTheSmallestWindow(t *testing.T) {
	newApp(t)
	steps := map[string]func(*SaveView){
		"asking":   func(v *SaveView) { v.Asking() },
		"unusable": func(v *SaveView) { v.Unusable(words.T(words.SaveForbidden)) },
		"taken":    func(v *SaveView) { v.Taken(longName) },
		"writing":  func(v *SaveView) { v.Writing() },
		"failed":   func(v *SaveView) { v.Failed(longPrinted + ".") },
		"done":     func(v *SaveView) { v.Done(longFolder + `\` + longName) },
	}
	for name, step := range steps {
		for _, f := range request.SaveFormats {
			o, v := SaveDialog(f, longFolder, longName)
			step(v)
			w := test.NewWindow(o)
			w.SetPadded(false)
			w.Resize(fyne.NewSize(look.WindowMinWidth, look.WindowMinHeight))
			w.Resize(fyne.NewSize(look.WindowMinWidth, look.WindowMinHeight))
			size := o.MinSize()
			inside := o.(*fyne.Container).Objects[0].MinSize()
			if size.Width > look.WindowMinWidth || size.Height > look.WindowMinHeight || inside.Width > look.DialogWidth {
				t.Errorf("%s as %s asks for %v, holding %v - the smallest window is %vx%v and the dialog %v wide",
					name, f.Value, size, inside, look.WindowMinWidth, look.WindowMinHeight, look.DialogWidth)
			}
			w.Close()
		}
	}
}

// TestTheSaveDialogShowsTheStepItIsTold - Replace in place of Save without the
// button moving, nothing to press while the copy is written, and Close with
// the path once it is.
func TestTheSaveDialogShowsTheStepItIsTold(t *testing.T) {
	newApp(t)
	o, v := SaveDialog(request.SaveFormats[0], longFolder, "report.html")
	test.NewTempWindow(t, o)
	width := v.Save.MinSize().Width

	v.Taken("report.html")
	if v.Save.Label != words.T(words.SaveReplace) || v.Save.MinSize().Width != width || !v.said.Visible() {
		t.Errorf("a file in the way shows %q at %v wide, was %v, with the message shown %v",
			v.Save.Label, v.Save.MinSize().Width, width, v.said.Visible())
	}
	v.Writing()
	for name, d := range map[string]fyne.Disableable{"Folder": v.Folder, "Name": v.Name, "Choose": v.Choose, "Cancel": v.Cancel, "Save": v.Save} {
		if !d.Disabled() {
			t.Errorf("%s can be used while the copy is written", name)
		}
	}
	v.SetReady(true)
	if !v.Save.Disabled() || v.Save.Label != words.T(words.SaveButton) {
		t.Error("Save could be pressed again while the copy is written")
	}
	v.Asking()
	v.SetReady(false)
	if v.Folder.Disabled() || !v.Save.Disabled() || v.said.Visible() {
		t.Error("the form is not usable again, or Save can be pressed with nothing to save under, or a message stayed")
	}
	v.SetReady(true)
	if v.Save.Disabled() {
		t.Error("Save cannot be pressed with a folder and a name")
	}
	v.Done(`C:\r\report.html`)
	if v.form.Visible() || v.asking.Visible() || !v.done.Visible() || !v.finished.Visible() {
		t.Error("the copy written still shows the form, or not where it is and Close")
	}
	if findButton(o, words.T(words.Copy)) == nil {
		t.Errorf("the path of the copy has no %q beside it", words.T(words.Copy))
	}
}

// TestTheSaveMenuIsTheFormatsInTheirOrder - the menu and the dialog read one
// list, so the third choice opens the dialog for the third format.
func TestTheSaveMenuIsTheFormatsInTheirOrder(t *testing.T) {
	newApp(t)
	items := SaveChoices()
	if len(items) != len(request.SaveFormats) {
		t.Fatalf("%d choices for %d formats", len(items), len(request.SaveFormats))
	}
	for i, f := range request.SaveFormats {
		if items[i].Name != words.T(f.Name) || items[i].Note != words.T(f.Note) {
			t.Errorf("choice %d is %+v, want the words of %s", i, items[i], f.Value)
		}
		o, _ := SaveDialog(f, "", "")
		title := fmt.Sprintf(words.T(words.SaveTitle), words.T(f.Name))
		if !holdsText(o, title) {
			t.Errorf("the dialog for %s does not say %q", f.Value, title)
		}
	}
}

// holdsText says whether a drawn screen shows words as one piece of text,
// looked for through the containers it is built of - a line of text stands in
// a theme of its own, which is a container too.
func holdsText(o fyne.CanvasObject, words string) bool {
	switch x := o.(type) {
	case *widget.RichText:
		return x.String() == words
	case *container.ThemeOverride:
		return holdsText(x.Content, words)
	case *fyne.Container:
		for _, child := range x.Objects {
			if holdsText(child, words) {
				return true
			}
		}
	}
	return false
}
