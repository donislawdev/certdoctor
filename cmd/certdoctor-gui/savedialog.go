//go:build cgo

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/screens"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// lastFolder is the preference that keeps the folder a report was last saved
// to: what the window keeps on disk besides a report, with its size (D21).
const lastFolder = "save.folder"

// saveMenu opens the formats Save report offers under its button, right edges
// in line, with the keyboard on the first. Escape puts it away and gives the
// keyboard back to the button.
func (win *window) saveMenu(button *parts.Button) {
	var pop *widget.PopUp
	menu, rows := parts.Menu(screens.SaveChoices(),
		func(i int) {
			pop.Hide()
			win.saveAs(request.SaveFormats[i])
		},
		func() {
			pop.Hide()
			win.w.Canvas().Focus(button)
		})
	pop = widget.NewPopUp(menu, win.w.Canvas())
	at := fyne.CurrentApp().Driver().AbsolutePositionForObject(button)
	pop.ShowAtPosition(fyne.NewPos(at.X+button.Size().Width-menu.MinSize().Width, at.Y+button.Size().Height+look.GapTight))
	win.w.Canvas().Focus(rows[0])
}

// saveDialog is one Save report dialog standing over the report: the copy
// whose steps flow keeps, the view it is drawn with, the bytes it writes, and
// the end of the run writing them while there is one.
type saveDialog struct {
	win      *window
	save     *flow.Save
	view     *screens.SaveView
	pop      *widget.PopUp
	document []byte
	stop     context.CancelFunc
}

// saveAs opens the dialog for a copy of the report on the screen in format f:
// in the folder last saved to, under the name the run suggests, with that
// name chosen so typing replaces it.
func (win *window) saveAs(f request.Format) {
	o := win.flow.Outcome()
	content, view := screens.SaveDialog(f, win.startFolder(), flow.SuggestedName(o.Report.Target, f, win.flow.Began()))
	d := &saveDialog{win: win, save: flow.NewSave(f), view: view, document: o.Document}
	d.pop = widget.NewModalPopUp(content, win.w.Canvas())
	view.Folder.OnChanged = func(string) { d.changed() }
	view.Name.OnChanged = func(string) { d.changed() }
	view.Folder.OnSubmitted = func(string) { d.press() }
	view.Name.OnSubmitted = func(string) { d.press() }
	view.Choose.OnTapped = d.choose
	view.Cancel.OnTapped = d.close
	view.Save.OnTapped = d.press
	view.Close.OnTapped = d.close
	d.show()
	d.pop.Show()
	win.saving = d
	win.w.Canvas().Focus(view.Name)
	view.Name.TypedShortcut(&fyne.ShortcutSelectAll{})
}

// startFolder is where the dialog opens: the folder a report was last saved
// to, or the person's home folder the first time. It is not looked at on
// disk - a folder gone since is said to be gone by the command line when it
// tries, in its own words.
func (win *window) startFolder() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	return win.prefs.StringWithFallback(lastFolder, home)
}

// changed is the folder or the name typed again.
func (d *saveDialog) changed() {
	d.save.Changed()
	d.show()
}

// press is Save or Replace: flow says whether anything runs, and the command
// line writes the copy from the report the window drew, handed to it on
// standard input, within flow.Grace - a run that writes a file it read a
// moment ago and is still going half a minute later is not going to end.
func (d *saveDialog) press() {
	args := d.save.Press(d.view.Folder.Text, d.view.Name.Text, d.win.present)
	d.show()
	if args == nil {
		return
	}
	ctx, stop := context.WithTimeout(context.Background(), flow.Grace)
	d.stop = stop
	d.win.wait(ctx, d.win.port, args, d.document, d.finish)
}

// finish shows what came of writing the copy, and keeps its folder for the
// next one once it is there.
func (d *saveDialog) finish(p flow.Process) {
	d.end()
	d.save.Finish(p)
	if d.save.Step() == flow.SaveDone {
		d.win.prefs.SetString(lastFolder, filepath.Dir(d.save.Path()))
	}
	d.show()
}

// show draws the step the copy is on, and fits the dialog round it - from its
// top, so the form a person is reading does not move.
func (d *saveDialog) show() {
	v := d.view
	switch d.save.Step() {
	case flow.SaveAsking:
		v.Asking()
	case flow.SaveUnusable:
		v.Unusable(d.save.Said())
	case flow.SaveTaken:
		v.Taken(filepath.Base(d.save.Path()))
	case flow.SaveWriting:
		v.Writing()
	case flow.SaveFailed:
		v.Failed(d.save.Said())
	case flow.SaveDone:
		v.Done(d.save.Path())
		d.win.w.Canvas().Focus(v.Close)
	}
	v.SetReady(flow.SaveReady(v.Folder.Text, v.Name.Text))
	d.pop.Resize(d.pop.MinSize())
}

// choose opens the toolkit's folder dialog over this one, in the folder typed
// when it is a whole path, and puts the folder chosen into the field. The
// toolkit takes the words of its dialog from the system's language, so its
// title and its two buttons are given the window's.
func (d *saveDialog) choose() {
	fd := dialog.NewFolderOpen(func(u fyne.ListableURI, err error) {
		if err == nil && u != nil {
			d.view.Folder.SetText(filepath.FromSlash(u.Path()))
		}
	}, d.win.w)
	if folder := strings.TrimSpace(d.view.Folder.Text); filepath.IsAbs(folder) {
		if at, err := storage.ListerForURI(storage.NewFileURI(folder)); err == nil {
			fd.SetLocation(at)
		}
	}
	fd.SetTitleText(words.T(words.SaveChooseTitle))
	fd.SetConfirmText(words.T(words.SaveUseFolder))
	fd.SetDismissText(words.T(words.Cancel))
	fd.Show()
}

// close puts the dialog away. Cancel and Close are the only ways out, and
// neither can be pressed while the copy is being written.
func (d *saveDialog) close() {
	d.end()
	d.pop.Hide()
	d.win.saving = nil
}

// end ends the run writing the copy while there is one, and releases its
// deadline once it has ended.
func (d *saveDialog) end() {
	if d.stop != nil {
		d.stop()
		d.stop = nil
	}
}
