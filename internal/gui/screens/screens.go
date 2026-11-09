// Package screens puts parts together into the window's screens. A screen
// sets no colour, distance, size or word of its own.
package screens

import (
	"strconv"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/request"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// head is the bar across the top of every screen, with the buttons that
// lead out of the window at its far end. On every screen rather than some:
// a button that is there on one screen and gone on the next is one people
// conclude they imagined. Quiet, so neither competes with the screen's one
// primary action.
func head(icon fyne.Resource, version string) fyne.CanvasObject {
	return parts.Header(icon, words.T(words.AppName), version, Links()...)
}

// Links is the buttons that leave the window for a page in the browser:
// the project on GitHub - the code, the releases and the place to report a
// problem - and Donate, with the heart. One list, so a third is one line
// here (GUI rule 5). GitHub has no picture: the toolkit ships no mark for
// the site, and the site's own mark is somebody else's trademark.
func Links() []fyne.CanvasObject {
	return []fyne.CanvasObject{
		parts.NewButton(parts.Quiet, words.T(words.LinkGitHub), nil, nil),
		parts.NewButton(parts.Quiet, words.T(words.LinkDonate), parts.Heart(), nil),
	}
}

// StartForm is what the start screen hands to whoever runs the window: the
// address field, the one primary action, the fold holding the options, and
// the form read as a request.
type StartForm struct {
	Address  *widget.Entry
	Diagnose *parts.Button
	Options  *parts.Pressable
	typed    map[string]*widget.Entry
	ticked   map[string]*widget.Check
}

// Request reads the form as it stands now.
func (f *StartForm) Request() request.Request {
	r := request.Request{Address: f.Address.Text, Typed: map[string]string{}, Ticked: map[string]bool{}}
	for name, e := range f.typed {
		r.Typed[name] = e.Text
	}
	for name, c := range f.ticked {
		r.Ticked[name] = c.Checked
	}
	return r
}

// Start is the first screen: what to diagnose, and the switches of the
// command line the window offers, one field each, in the order and with the
// words the window's list of them gives (ADR121 point 3). Diagnose is the one
// primary action.
//
// software says the window is drawn by the software renderer shipped beside
// it rather than by the graphics driver (ADR125 point 2). Said here, on the
// screen a person sees first after a double click, because the standard error
// that says it too is one they do not see - and only when it is so.
func Start(icon fyne.Resource, version string, optionsOpen, software bool) (fyne.CanvasObject, *StartForm) {
	form := &StartForm{
		Address:  widget.NewEntry(),
		Diagnose: parts.NewButton(parts.Primary, words.T(words.Diagnose), theme.SearchIcon(), nil),
		typed:    map[string]*widget.Entry{},
		ticked:   map[string]*widget.Check{},
	}
	form.Address.SetPlaceHolder(words.T(words.TargetExample))

	var fields []fyne.CanvasObject
	for _, o := range request.Offered {
		fields = append(fields, parts.Field(words.T(o.Label), form.control(o), words.T(o.Hint)))
	}
	target := parts.Card(words.T(words.TargetCardNew), nil,
		parts.Stack(look.GapTight,
			parts.RowGrow(look.GapButtons, 0, form.Address, form.Diagnose),
			parts.Para(parts.CaptionMuted, words.T(words.TargetHint)),
		),
	)
	form.Options = parts.Fold(words.T(words.OptionsCard), words.T(words.OptionsClosed), optionsOpen,
		parts.Para(parts.CaptionMuted, words.T(words.OptionsNote)),
		parts.Form(fields...),
	)
	intro := parts.Stack(look.GapRow,
		parts.Text(parts.Title, words.T(words.StartTitle)),
		parts.Para(parts.BodyMuted, words.T(words.StartLead)),
	)
	sections := []fyne.CanvasObject{intro, target, form.Options, parts.Para(parts.CaptionMuted, words.T(words.StartPromise))}
	if software {
		sections = append(sections, parts.Para(parts.CaptionMuted, words.T(words.SoftwareDrawing)))
	}
	body := parts.Column(look.ColumnWidth, parts.Inset(0, look.InsetPage, 0, look.InsetPage,
		parts.Stack(look.GapCard, sections...)))
	page := container.NewBorder(head(icon, version), nil, nil, nil,
		container.NewVScroll(parts.PadXY(look.InsetPage, 0, body)))
	return page, form
}

// control is the field one option is set with, kept by its switch so the form
// can be read back. A number of seconds is a short field with its unit beside
// it, showing the number an empty field means.
func (f *StartForm) control(o request.Option) fyne.CanvasObject {
	switch o.Control() {
	case request.Tick:
		tick := widget.NewCheck("", nil)
		f.ticked[o.Switch] = tick
		return parts.Height(look.ControlHeight, parts.Own(tick))
	case request.Seconds:
		seconds := widget.NewEntry()
		seconds.SetPlaceHolder(strconv.Itoa(o.Default))
		f.typed[o.Switch] = seconds
		return parts.Row(look.GapInline,
			parts.Width(look.FieldWidthShort, seconds),
			parts.Middle(parts.Text(parts.BodyMuted, words.T(words.OptTimeoutUnit))))
	default:
		line := widget.NewEntry()
		line.SetPlaceHolder(words.T(o.Example))
		f.typed[o.Switch] = line
		return line
	}
}

// ReportView is the report screen as whoever runs the window wires it: back
// to the form, save what this run made, run it again - and the layer shown.
type ReportView struct {
	New, Save, Again *parts.Button

	rail   *parts.Rail
	shown  *fyne.Container
	report model.Report
	// pages is each layer's page, made the first time it is chosen and kept,
	// so a command opened in one layer is still open on coming back to it.
	pages map[int]fyne.CanvasObject
}

// Chosen is the layer the screen shows.
func (v *ReportView) Chosen() int { return v.rail.Chosen() }

// show puts the page of layer i beside the rail.
func (v *ReportView) show(i int) {
	page, ok := v.pages[i]
	if !ok {
		page = layerDetail(v.report.Layers[i], -1)
		v.pages[i] = page
	}
	v.shown.Objects = []fyne.CanvasObject{page}
	v.shown.Refresh()
}

// Report is the screen after a run: what was diagnosed and the actions on
// it, the verdict, then the layers down the side in the report's order and
// the chosen layer beside them. selected is the layer it opens on, and open
// the store of that layer whose command it opens on, -1 for none.
func Report(icon fyne.Resource, r model.Report, selected int, open int) (fyne.CanvasObject, *ReportView) {
	v := &ReportView{
		New:    parts.NewButton(parts.Quiet, words.T(words.NewTarget), theme.NavigateBackIcon(), nil),
		Save:   parts.NewButton(parts.Secondary, words.T(words.SaveReport), theme.DocumentSaveIcon(), nil),
		Again:  parts.NewButton(parts.Primary, words.T(words.RunAgain), theme.ViewRefreshIcon(), nil),
		rail:   parts.NewRail(words.T(words.LayersHead), r.Layers, selected),
		report: r,
		pages:  map[int]fyne.CanvasObject{selected: layerDetail(r.Layers[selected], open)},
	}
	v.shown = parts.Stack(0, v.pages[selected])
	v.rail.OnChosen = v.show
	actions := parts.Row(look.GapButtons, v.New, v.Save, v.Again)
	title := parts.RowGrow(look.GapCard, 0,
		parts.Middle(parts.Stack(look.GapTight,
			parts.Text(parts.CaptionStrong, words.T(words.ReportFor)),
			parts.Clip(parts.Title, r.Target),
		)),
		parts.Middle(actions),
	)
	lower := parts.RowTop(look.GapCard, 1, parts.Width(look.RailWidth, v.rail), v.shown)
	body := parts.Column(look.PageWidth, parts.Pad(look.InsetPage, parts.Stack(look.GapCard, title, parts.Verdict(r), lower)))
	return container.NewBorder(head(icon, r.Version), nil, nil, nil, container.NewVScroll(body)), v
}

// SaveChoices is what Save report offers: the three formats the command
// line writes, each saved by the command line from the report this run made.
func SaveChoices() []parts.MenuItem {
	return []parts.MenuItem{
		{Name: words.T(words.SaveHTML), Note: words.T(words.SaveHTMLNote)},
		{Name: words.T(words.SaveMD), Note: words.T(words.SaveMDNote)},
		{Name: words.T(words.SaveJSON), Note: words.T(words.SaveJSONNote)},
	}
}

func layerDetail(l model.Layer, open int) fyne.CanvasObject {
	title := parts.Row(look.GapInline,
		parts.Middle(parts.Text(parts.Heading, l.Name)),
		parts.Middle(parts.Text(parts.BodyMuted, l.ID)),
		parts.Middle(parts.Badge(l.Status, look.Page)),
	)
	head := []fyne.CanvasObject{parts.Height(look.ControlHeight, parts.Middle(title))}
	if l.Reason != "" {
		head = append(head, parts.Text(parts.Strong, words.Reason(l.Reason)))
	}
	head = append(head, parts.Para(parts.BodyMuted, l.Detail))
	cards := []fyne.CanvasObject{parts.Stack(look.GapTight, head...)}
	// One card a kind of finding, in the order the report lists them: the
	// kind is the card's name and how many there are, and the report's own
	// sentences are the rows.
	for _, g := range groups(l.Findings) {
		var rows []fyne.CanvasObject
		for i, summary := range g.summaries {
			if i > 0 {
				rows = append(rows, parts.Rule())
			}
			rows = append(rows, parts.Para(parts.Body, summary))
		}
		cards = append(cards, parts.Card(words.Kind(g.kind), parts.Middle(parts.Text(parts.CaptionMuted, strconv.Itoa(len(g.summaries)))), parts.Stack(look.GapRow, rows...)))
	}
	if len(l.Stores) > 0 {
		cards = append(cards, parts.Card(words.T(words.MatrixCard), parts.Middle(parts.Text(parts.CaptionMuted, strconv.Itoa(len(l.Stores)))), parts.Matrix(l.Stores, open)))
	}
	if len(cards) == 1 {
		cards = append(cards, parts.Empty(words.T(words.EmptyLayer)))
	}
	return parts.Stack(look.GapCard, cards...)
}

type group struct {
	kind      string
	summaries []string
}

func groups(findings []model.Finding) []group {
	var out []group
	at := map[string]int{}
	for _, f := range findings {
		i, ok := at[f.Kind]
		if !ok {
			i = len(out)
			at[f.Kind] = i
			out = append(out, group{kind: f.Kind})
		}
		out[i].summaries = append(out[i].summaries, f.Summary)
	}
	return out
}

// RunningView is what the running screen hands to whoever runs the window:
// Cancel, and the time used, set in place every second while the screen
// stands.
type RunningView struct {
	Cancel *parts.Button
	time   *parts.Changing
	track  *parts.Track
}

// Show sets the time used: the words, the share of the limit gone, and whether
// there is a limit to draw a share of - without one the track is not shown,
// because a bar that never fills says something false.
func (v *RunningView) Show(text string, share float32, bounded bool) {
	v.time.Set(text)
	v.track.SetShare(share)
	if bounded {
		v.track.Show()
	} else {
		v.track.Hide()
	}
}

// Words are the time used as the screen says it now.
func (v *RunningView) Words() string { return v.time.Words() }

// Running is the screen while the command line works: what is being
// diagnosed, the time used out of the limit, and Cancel.
func Running(icon fyne.Resource, version, target string) (fyne.CanvasObject, *RunningView) {
	v := &RunningView{
		Cancel: parts.NewButton(parts.Secondary, words.T(words.Cancel), theme.CancelIcon(), nil),
		time:   parts.NewChanging(parts.BodyMuted, ""),
		track:  parts.NewTrack(0),
	}
	card := parts.Card("", nil,
		parts.Stack(look.GapTight,
			parts.Text(parts.CaptionStrong, words.T(words.RunningTitle)),
			parts.Clip(parts.Title, target),
		),
		parts.Para(parts.BodyMuted, words.T(words.RunningLayers)),
		v.track,
		parts.RowGrow(look.GapButtons, 0, parts.Middle(v.time), v.Cancel),
		parts.Para(parts.CaptionMuted, words.T(words.RunningNote)),
	)
	body := parts.Column(look.ColumnWidth, parts.Inset(0, look.InsetPage, 0, look.InsetPage, card))
	return container.NewBorder(head(icon, version), nil, nil, nil,
		container.NewVScroll(parts.PadXY(look.InsetPage, 0, body))), v
}

// Trouble is the screen when certdoctor itself could not run, and Back, which
// leads to the form as it was.
func Trouble(icon fyne.Resource, version, title, what, todo, printed string) (fyne.CanvasObject, *parts.Button) {
	back := parts.NewButton(parts.Primary, words.T(words.Back), theme.NavigateBackIcon(), nil)
	card := parts.Problem(title, what, todo, printed, back)
	body := parts.Column(look.ColumnWidth, parts.Inset(0, look.InsetPage, 0, look.InsetPage, card))
	return container.NewBorder(head(icon, version), nil, nil, nil,
		container.NewVScroll(parts.PadXY(look.InsetPage, 0, body))), back
}
