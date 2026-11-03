// Package screens puts parts together into the window's screens. A screen
// sets no colour, distance, size or word of its own.
package screens

import (
	"fmt"
	"strconv"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
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

// Start is the first screen: what to diagnose, and the switches the command
// line takes. Diagnose is the one primary action.
func Start(icon fyne.Resource, version string, optionsOpen bool) (fyne.CanvasObject, *widget.Entry) {
	address := widget.NewEntry()
	address.SetPlaceHolder(words.T(words.TargetExample))
	diagnose := parts.NewButton(parts.Primary, words.T(words.Diagnose), theme.SearchIcon(), nil)

	pac := widget.NewEntry()
	pac.SetPlaceHolder(words.T(words.OptPACExample))
	timeout := widget.NewEntry()
	timeout.SetPlaceHolder(words.T(words.OptTimeoutExample))
	redact := widget.NewCheck("", nil)

	target := parts.Card(words.T(words.TargetCardNew), nil,
		parts.Stack(look.GapTight,
			parts.RowGrow(look.GapButtons, 0, address, diagnose),
			parts.Para(parts.CaptionMuted, words.T(words.TargetHint)),
		),
	)
	options := parts.Fold(words.T(words.OptionsCard), words.T(words.OptionsClosed), optionsOpen,
		parts.Para(parts.CaptionMuted, words.T(words.OptionsNote)),
		parts.Form(
			parts.Field(words.T(words.OptPAC), pac, words.T(words.OptPACHint)),
			parts.Field(words.T(words.OptTimeout), parts.Row(look.GapInline,
				parts.Width(look.FieldWidthShort, timeout),
				parts.Middle(parts.Text(parts.BodyMuted, words.T(words.OptTimeoutUnit)))), ""),
			parts.Field(words.T(words.OptRedact), parts.Height(look.ControlHeight, parts.Own(redact)), words.T(words.OptRedactHint)),
		),
	)
	intro := parts.Stack(look.GapRow,
		parts.Text(parts.Title, words.T(words.StartTitle)),
		parts.Para(parts.BodyMuted, words.T(words.StartLead)),
	)
	promise := parts.Para(parts.CaptionMuted, words.T(words.StartPromise))
	body := parts.Column(look.ColumnWidth, parts.Inset(0, look.InsetPage, 0, look.InsetPage,
		parts.Stack(look.GapCard, intro, target, options, promise)))
	page := container.NewBorder(head(icon, version), nil, nil, nil,
		container.NewVScroll(parts.PadXY(look.InsetPage, 0, body)))
	return page, address
}

// Report is the screen after a run: what was diagnosed and the actions on
// it, the verdict, then the layers down the side in the report's order and
// the chosen layer beside them.
func Report(icon fyne.Resource, r model.Report, selected int, open int) (fyne.CanvasObject, *parts.Button) {
	save := parts.NewButton(parts.Secondary, words.T(words.SaveReport), theme.DocumentSaveIcon(), nil)
	actions := parts.Row(look.GapButtons,
		parts.NewButton(parts.Quiet, words.T(words.NewTarget), theme.NavigateBackIcon(), nil),
		save,
		parts.NewButton(parts.Primary, words.T(words.RunAgain), theme.ViewRefreshIcon(), nil),
	)
	title := parts.RowGrow(look.GapCard, 0,
		parts.Middle(parts.Stack(look.GapTight,
			parts.Text(parts.CaptionStrong, words.T(words.ReportFor)),
			parts.Clip(parts.Title, r.Target),
		)),
		parts.Middle(actions),
	)
	rail := parts.Width(look.RailWidth, parts.Rail(words.T(words.LayersHead), r.Layers, selected))
	detail := layerDetail(r.Layers[selected], open)
	lower := parts.RowTop(look.GapCard, 1, rail, detail)
	body := parts.Column(look.PageWidth, parts.Pad(look.InsetPage, parts.Stack(look.GapCard, title, parts.Verdict(r), lower)))
	return container.NewBorder(head(icon, r.Version), nil, nil, nil, container.NewVScroll(body)), save
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

// Running is the screen while the command line works: what is being
// diagnosed, the time used out of the limit, and Cancel.
func Running(icon fyne.Resource, version, target string, elapsed float64, limit int) fyne.CanvasObject {
	card := parts.Card("", nil,
		parts.Stack(look.GapTight,
			parts.Text(parts.CaptionStrong, words.T(words.RunningTitle)),
			parts.Clip(parts.Title, target),
		),
		parts.Para(parts.BodyMuted, words.T(words.RunningLayers)),
		parts.Track(float32(elapsed/float64(limit))),
		parts.RowGrow(look.GapButtons, 0,
			parts.Middle(parts.Text(parts.BodyMuted, fmt.Sprintf(words.T(words.RunningElapsed), elapsed, limit))),
			parts.NewButton(parts.Secondary, words.T(words.Cancel), theme.CancelIcon(), nil),
		),
		parts.Para(parts.CaptionMuted, words.T(words.RunningNote)),
	)
	body := parts.Column(look.ColumnWidth, parts.Inset(0, look.InsetPage, 0, look.InsetPage, card))
	return container.NewBorder(head(icon, version), nil, nil, nil,
		container.NewVScroll(parts.PadXY(look.InsetPage, 0, body)))
}

// Trouble is the screen when certdoctor itself could not run.
func Trouble(icon fyne.Resource, version, title, what, todo, printed string) fyne.CanvasObject {
	card := parts.Problem(title, what, todo, printed,
		parts.NewButton(parts.Primary, words.T(words.Back), theme.NavigateBackIcon(), nil))
	body := parts.Column(look.ColumnWidth, parts.Inset(0, look.InsetPage, 0, look.InsetPage, card))
	return container.NewBorder(head(icon, version), nil, nil, nil,
		container.NewVScroll(parts.PadXY(look.InsetPage, 0, body)))
}
