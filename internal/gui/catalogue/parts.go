package catalogue

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/screens"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TypeLadder is the page of type: every rung with what it is used for.
func TypeLadder(sample model.Report) fyne.CanvasObject {
	rungs := []struct {
		style parts.Style
		name  string
		text  string
	}{
		{parts.Title, "Title 22 bold", words.T(words.StartTitle)},
		{parts.Heading, "Heading 16 bold", "Trust matrix"},
		{parts.Lead, "Lead 16", sample.Verdict.Sentence},
		{parts.Body, "Body 14", sample.Layers[5].Detail},
		{parts.BodyMuted, "Body 14 muted", words.T(words.StartLead)},
		{parts.Strong, "Body 14 bold", "system-store"},
		{parts.Caption, "Caption 12", words.T(words.StartPromise)},
		{parts.CaptionMuted, "Caption 12 muted", words.T(words.TargetHint)},
		{parts.CaptionStrong, "Caption 12 bold muted", words.T(words.ColTrusts)},
		{parts.Mono, "Mono 13", `certutil -user -addstore Root "<certificate.pem>"`},
		{parts.MonoMuted, "Mono 13 muted", `C:\Program Files\OpenJDK\jdk-26.0.2.1`},
	}
	rows := make([]fyne.CanvasObject, 0, len(rungs))
	for _, r := range rungs {
		rows = append(rows, parts.RowTop(look.GapCard, 1,
			parts.Width(look.SheetColumn/2, parts.Text(parts.MonoMuted, r.name)),
			parts.Limit(look.ProseWidth, parts.Para(r.style, r.text)),
		))
	}
	return page(words.CatType, parts.Card("", nil, parts.Stack(look.GapCard, rows...)))
}

func labelled(name words.Key, o fyne.CanvasObject) fyne.CanvasObject {
	return parts.Stack(look.GapInline, o, parts.Text(parts.CaptionMuted, words.T(name)))
}

var states = []struct {
	state parts.State
	name  words.Key
}{
	{parts.Rest, words.CatRest},
	{parts.Hover, words.CatHover},
	{parts.Press, words.CatPress},
	{parts.Focused, words.CatFocus},
	{parts.Disabled, words.CatDisabled},
}

func buttons() fyne.CanvasObject {
	kinds := []struct {
		kind  parts.Kind
		name  words.Key
		label words.Key
		icon  fyne.Resource
	}{
		{parts.Primary, words.CatPrimary, words.Diagnose, theme.SearchIcon()},
		{parts.Secondary, words.CatSecondary, words.SaveReport, theme.DocumentSaveIcon()},
		{parts.Quiet, words.CatQuiet, words.NewTarget, theme.NavigateBackIcon()},
		{parts.Quiet, words.CatQuietHeart, words.LinkDonate, parts.Heart()},
	}
	var rows []fyne.CanvasObject
	for _, k := range kinds {
		var cells []fyne.CanvasObject
		for _, s := range states {
			cells = append(cells, labelled(s.name, parts.NewButton(k.kind, words.T(k.label), k.icon, nil).Pin(s.state)))
		}
		rows = append(rows, parts.Field(words.T(k.name), parts.Row(look.GapCard, cells...), ""))
	}
	return parts.Card(words.T(words.CatButtons), nil, parts.Form(rows...))
}

// Fields is the boxes to type in; the one to show with the keyboard in it
// is handed back so the caller can focus it on a real canvas.
func fields() (fyne.CanvasObject, fyne.Focusable) {
	empty := widget.NewEntry()
	empty.SetPlaceHolder(words.T(words.TargetExample))
	filled := widget.NewEntry()
	filled.SetText("https://untrusted-root.badssl.com")
	focused := widget.NewEntry()
	focused.SetText("https://example.com")
	off := widget.NewEntry()
	off.SetText("https://example.com")
	off.Disable()
	box := func(e fyne.CanvasObject) fyne.CanvasObject { return parts.Width(look.ColumnWidth/3, e) }
	checkOff := widget.NewCheck(words.T(words.OptRedact), nil)
	checkOn := widget.NewCheck(words.T(words.OptRedact), nil)
	checkOn.SetChecked(true)
	checkDisabled := widget.NewCheck(words.T(words.OptRedact), nil)
	checkDisabled.Disable()
	return parts.Card(words.T(words.CatFields), nil,
		parts.Row(look.GapCard,
			labelled(words.CatEmpty, box(empty)),
			labelled(words.CatFilled, box(filled)),
			labelled(words.CatFocus, box(focused)),
			labelled(words.CatDisabled, box(off)),
		),
		parts.Row(look.GapCard,
			labelled(words.CatRest, checkOff),
			labelled(words.CatChecked, checkOn),
			labelled(words.CatDisabled, checkDisabled),
		),
	), focused
}

func commands(r model.Report) fyne.CanvasObject {
	stores := r.Layers[5].Stores
	var user, machine model.Store
	for _, s := range stores {
		if s.Instance == "CurrentUser" {
			user = s
		}
		if s.Instance == "LocalMachine" {
			machine = s
		}
	}
	long := `keytool -importcert -noprompt -trustcacerts -alias certdoctor-authority -file "<certificate.pem>" -keystore "C:\Program Files\OpenJDK\jdk-26.0.2.1\lib\security\cacerts" -storepass changeit`
	return parts.Card(words.T(words.CatCommands), nil,
		parts.Command(user.Command, user.NeedsAdmin, user.Elevation, user.Caveat, nil),
		parts.Command(machine.Command, machine.NeedsAdmin, machine.Elevation, machine.Caveat,
			parts.NewButton(parts.Secondary, words.T(words.Copied), theme.ConfirmIcon(), nil)),
		parts.Command(long, true, machine.Elevation, "", nil),
	)
}

func matrix(r model.Report) fyne.CanvasObject {
	stores := r.Layers[5].Stores
	pick := func(t model.Trust) model.Store {
		for _, s := range stores {
			if s.Trust == t {
				return s
			}
		}
		return model.Store{Runtime: "pip", Instance: "-", Trust: t}
	}
	yes, no := pick(model.TrustYes), pick(model.TrustNo)
	not := model.Store{Runtime: "java", Instance: `C:\Program Files\Java\jre1.8.0_503`, Trust: model.TrustNotAssessed, ChosenBy: []string{"JAVA_HOME"}}
	long := yes
	long.Instance = `C:\Users\jdoe\AppData\Local\Programs\A deliberately long folder name\that keeps going\python.exe`
	long.ChosenBy = []string{"PATH", "py launcher", "registry"}
	rows := []fyne.CanvasObject{
		parts.MatrixHead(), parts.Rule(),
		labelledRow(words.CatRest, parts.MatrixRow(yes, false, parts.Rest)),
		labelledRow(words.CatHover, parts.MatrixRow(no, false, parts.Hover)),
		labelledRow(words.CatFocus, parts.MatrixRow(not, false, parts.Focused)),
		labelledRow(words.CatSampleLong, parts.MatrixRow(long, false, parts.Rest)),
		labelledRow(words.CatOpen, parts.MatrixRow(no, true, parts.Rest)),
	}
	return parts.Card(words.T(words.CatMatrix), nil, parts.Stack(look.GapTight, rows...))
}

func labelledRow(name words.Key, o fyne.CanvasObject) fyne.CanvasObject {
	return parts.Stack(look.GapTight, o, parts.Inset(look.InsetCell, 0, 0, 0, parts.Text(parts.CaptionMuted, words.T(name))))
}

func rail(r model.Report) fyne.CanvasObject {
	l := r.Layers
	long := l[2]
	long.Name = words.T(words.CatSampleLong)
	items := []struct {
		layer    model.Layer
		selected bool
		state    parts.State
		name     words.Key
	}{
		{l[5], true, parts.Rest, words.CatSelected},
		{l[0], false, parts.Rest, words.CatRest},
		{l[2], false, parts.Hover, words.CatHover},
		{l[4], false, parts.Focused, words.CatFocus},
		{long, false, parts.Rest, words.CatSampleLong},
	}
	var cells []fyne.CanvasObject
	for _, it := range items {
		cells = append(cells, parts.Width(look.RailWidth, labelled(it.name, parts.RailItem(it.layer, it.selected, it.state))))
	}
	return parts.Card(words.T(words.CatRail), nil, parts.Row(look.GapCard, cells[:3]...), parts.Row(look.GapCard, cells[3:]...))
}

func marks() fyne.CanvasObject {
	tones := []look.Tone{look.TonePass, look.ToneWarn, look.ToneFail, look.ToneUnknown}
	var cells []fyne.CanvasObject
	for _, size := range []float32{look.MarkInline, look.MarkRow, look.MarkLarge} {
		for _, t := range tones {
			cells = append(cells, parts.Middle(parts.Mark(t, size)))
		}
		cells = append(cells, parts.Gap(look.GapCard))
	}
	return parts.Card(words.T(words.CatMarks), nil, parts.Row(look.GapField, cells...))
}

func badges() fyne.CanvasObject {
	var row1, row2 []fyne.CanvasObject
	for _, s := range []model.Status{model.Pass, model.Warn, model.Fail, model.Unknown} {
		row1 = append(row1, parts.Badge(s, look.Surface))
	}
	for _, t := range []model.Trust{model.TrustYes, model.TrustNo, model.TrustNotAssessed} {
		tone, word := parts.TrustTone(t)
		row2 = append(row2, parts.Pill(tone, words.T(word), look.Surface))
	}
	row2 = append(row2, parts.Chip(nil, words.T(words.NeedsAdmin), look.Surface))
	return parts.Card(words.T(words.CatBadges), nil, parts.Row(look.GapField, row1...), parts.Row(look.GapField, row2...))
}

// header is the bar across the top as every screen has it, and with a
// version string as long as a build of the release candidates writes.
func header(icon fyne.Resource, r model.Report) fyne.CanvasObject {
	name := words.T(words.AppName)
	return parts.Card(words.T(words.CatHeader), nil,
		parts.Header(icon, name, r.Version, screens.Links()...),
		parts.Header(icon, name, "0.1.0-rc.12+20261103.2a8b152dirty", screens.Links()...),
	)
}

// Parts is the page of every part in every state, and the box to type in
// that should hold the keyboard when it is drawn.
func Parts(icon fyne.Resource, r model.Report) (fyne.CanvasObject, fyne.Focusable) {
	f, focus := fields()
	body := parts.Stack(look.GapCard,
		header(icon, r),
		parts.RowTop(look.GapCard, -1, marks(), badges()),
		buttons(),
		f,
		commands(r),
		matrix(r),
		rail(r),
		parts.Card(words.T(words.CatVerdict), nil, parts.Verdict(r)),
		screenStates(),
	)
	return page(words.CatParts, body), focus
}

// screenStates is the parts that stand for a state of a screen rather than for a
// piece of a report: the bar of time used, a fold closed and open, the
// menu, the notice for a page the desktop did not open, what the window
// says when it has nothing to show, and the card for when certdoctor itself
// could not run.
func screenStates() fyne.CanvasObject {
	tracks := parts.Row(look.GapCard,
		parts.Width(look.SheetColumn/2, labelled(words.CatTrackStart, parts.NewTrack(0))),
		parts.Width(look.SheetColumn/2, labelled(words.CatTrackHalf, parts.NewTrack(0.4))),
		parts.Width(look.SheetColumn/2, labelled(words.CatTrackFull, parts.NewTrack(1))),
		parts.Width(look.SheetColumn/2, labelled(words.CatChanging,
			parts.NewChanging(parts.BodyMuted, fmt.Sprintf(words.T(words.RunningElapsed), "12", "60")))),
	)
	folds := parts.RowTop(look.GapCard, -1,
		parts.Width(look.SheetColumn, parts.Fold(words.T(words.OptionsCard), words.T(words.OptionsClosed), false)),
		parts.Width(look.SheetColumn, parts.Fold(words.T(words.OptionsCard), words.T(words.OptionsClosed), true,
			parts.Para(parts.CaptionMuted, words.T(words.OptionsNote)))),
	)
	menus := parts.RowTop(look.GapCard, -1,
		labelled(words.CatRest, parts.Menu(screens.SaveChoices(), -1)),
		labelled(words.CatHover, parts.Menu(screens.SaveChoices(), 1)),
	)
	notice := parts.Own(parts.Notice(words.T(words.LinkFailed), words.T(words.LinkFailedNote), words.RepositoryURL))
	problem := parts.Problem(words.T(words.RefusedTitle), "", words.T(words.RefusedTodo), words.T(words.CatSampleLong),
		parts.NewButton(parts.Primary, words.T(words.Back), theme.NavigateBackIcon(), nil))
	return parts.Card(words.T(words.CatStates), nil, tracks, folds, menus, notice, parts.Empty(words.T(words.EmptyLayer)), problem)
}
