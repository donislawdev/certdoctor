package screens

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// SaveChoices is what Save report offers: the formats the command line
// writes a copy in, from the report this run made, in the order of
// request.SaveFormats - the list the dialog is opened with too.
func SaveChoices() []parts.MenuItem {
	items := make([]parts.MenuItem, len(request.SaveFormats))
	for i, f := range request.SaveFormats {
		items[i] = parts.MenuItem{Name: words.T(f.Name), Note: words.T(f.Note)}
	}
	return items
}

// SaveView is the Save report dialog as whoever runs the window wires it: the
// folder and the name to type, Choose for the folder, Cancel and Save - and
// Close once the copy is written. What it says is set from outside, one
// method a step, and nothing here decides which step it is on.
type SaveView struct {
	Folder, Name                *widget.Entry
	Choose, Cancel, Save, Close *parts.Button

	form             fyne.CanvasObject
	said, done       *fyne.Container
	asking, finished *fyne.Container
}

// SaveDialog is the dialog Save report opens for format: what it saves, the
// folder and the name the copy is written under - folder and name to start
// with - and Save as its one primary action. It stands over the report, as
// wide as the start screen's column.
func SaveDialog(format request.Format, folder, name string) (fyne.CanvasObject, *SaveView) {
	v := &SaveView{
		Folder: widget.NewEntry(),
		Name:   widget.NewEntry(),
		Choose: parts.NewButton(parts.Secondary, words.T(words.SaveChoose), theme.FolderOpenIcon(), nil),
		Cancel: parts.NewButton(parts.Secondary, words.T(words.Cancel), theme.CancelIcon(), nil),
		Save: parts.NewButton(parts.Primary, words.T(words.SaveButton), theme.DocumentSaveIcon(), nil).
			Fit(words.T(words.SaveButton), words.T(words.SaveReplace)),
		Close: parts.NewButton(parts.Primary, words.T(words.SaveClose), nil, nil),
		said:  parts.Stack(0),
		done:  parts.Stack(look.GapRow),
	}
	v.Folder.SetText(folder)
	v.Name.SetText(name)
	head := parts.Stack(look.GapTight,
		parts.Text(parts.Heading, fmt.Sprintf(words.T(words.SaveTitle), words.T(format.Name))),
		parts.Para(parts.CaptionMuted, words.T(format.Note)),
	)
	v.form = parts.Form(
		parts.Field(words.T(words.SaveFolder), parts.RowGrow(look.GapInline, 0, v.Folder, v.Choose), ""),
		parts.Field(words.T(words.SaveName), v.Name, fmt.Sprintf(words.T(words.SaveEnding), format.Ending)),
	)
	v.asking = parts.RowGrow(look.GapButtons, 0, parts.Gap(0), v.Cancel, v.Save)
	v.finished = parts.RowGrow(look.GapButtons, 0, parts.Gap(0), v.Close)
	v.said.Hide()
	v.done.Hide()
	v.finished.Hide()
	return parts.Width(look.DialogWidth, parts.Panel(look.Surface, look.EdgeControl, look.RadiusCard,
		parts.Pad(look.InsetCard, parts.Stack(look.GapCard, head, v.form, v.said, v.done, v.asking, v.finished)))), v
}

// SaveDialogFor is the dialog for choice of the menu SaveChoices makes - for
// whoever knows the menu and not the formats behind it, as the catalogue
// does.
func SaveDialogFor(choice int, folder, name string) (fyne.CanvasObject, *SaveView) {
	return SaveDialog(request.SaveFormats[choice], folder, name)
}

// Asking is the form with nothing said under it.
func (v *SaveView) Asking() { v.answer(nil, words.SaveButton, true) }

// Unusable is the form with why the folder or the name cannot be saved to.
func (v *SaveView) Unusable(why string) {
	v.answer(parts.Message(theme.ErrorIcon(), "", why), words.SaveButton, true)
}

// Taken is the form with the name of the file already in the folder, and
// with Save saying Replace.
func (v *SaveView) Taken(name string) {
	v.answer(parts.Message(theme.QuestionIcon(), fmt.Sprintf(words.T(words.SaveTaken), name), words.T(words.SaveTakenWhat)),
		words.SaveReplace, true)
}

// Writing is the form while the command line writes the copy: nothing in it
// can be pressed or typed into until it is done.
func (v *SaveView) Writing() {
	v.answer(parts.Para(parts.BodyMuted, words.T(words.SaveWriting)), words.SaveButton, false)
}

// Failed is the form with why the copy was not written, to change and try
// again.
func (v *SaveView) Failed(why string) {
	v.answer(parts.Message(theme.ErrorIcon(), words.T(words.SaveFailed), why), words.SaveButton, true)
}

// Done is where the copy is, with Copy beside it, and Close in place of the
// form and its buttons.
func (v *SaveView) Done(path string) {
	v.done.Objects = []fyne.CanvasObject{
		parts.Message(theme.ConfirmIcon(), words.T(words.SaveDone), words.T(words.SaveDoneWhat)),
		parts.Command(path, false, "", "", nil),
	}
	v.done.Refresh()
	for _, o := range []fyne.CanvasObject{v.form, v.said, v.asking} {
		o.Hide()
	}
	v.done.Show()
	v.finished.Show()
}

// SetReady lets Save be pressed only when there is a folder and a name to
// save under.
func (v *SaveView) SetReady(ready bool) {
	if ready && !v.Folder.Disabled() {
		v.Save.Enable()
		return
	}
	v.Save.Disable()
}

// answer puts said under the form, or nothing, gives Save the words of label,
// and lets the form be used or not.
func (v *SaveView) answer(said fyne.CanvasObject, label words.Key, usable bool) {
	if said == nil {
		v.said.Objects = nil
		v.said.Hide()
	} else {
		v.said.Objects = []fyne.CanvasObject{said}
		v.said.Show()
	}
	v.said.Refresh()
	v.Save.Label = words.T(label)
	v.Save.Refresh()
	for _, d := range []fyne.Disableable{v.Folder, v.Name, v.Choose, v.Cancel, v.Save} {
		if usable {
			d.Enable()
		} else {
			d.Disable()
		}
	}
}
