package screens

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/words"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// ToolsView is the Tools screen as whoever runs the window wires it: the
// list, the page of each tool, and the bar.
//
// ONE SCREEN DRAWS EVERY TOOL (ADR141 points 5 and 11). The list is built
// from the contract's list, a page's form from the tool's inputs, its answer
// from the blocks the command line sends - so a tool added to the contract
// appears here with its words in the catalogue and nothing else written.
type ToolsView struct {
	Links []Link
	Tabs  *parts.Tabs
	List  *parts.ToolList
	// Pages are the page of every tool, by id - each built once and kept, so
	// what was typed into one and the answer it shows are there on coming
	// back to it (GUI rule 3).
	Pages map[string]*ToolPage
	shown *fyne.Container
}

// Tools is the screen of the tools, with the first tool on the list shown.
func Tools(icon fyne.Resource, version string) (fyne.CanvasObject, *ToolsView) {
	v := &ToolsView{Pages: map[string]*ToolPage{}}
	var groups []parts.ToolGroup
	for _, c := range spec.Categories {
		group := parts.ToolGroup{Title: words.Category(string(c))}
		for _, t := range spec.All {
			if t.Category == c {
				w, _ := words.Tool(t.ID)
				group.Tools = append(group.Tools, parts.ToolEntry{ID: t.ID, Title: w.Title, Summary: w.Summary})
				v.Pages[t.ID] = toolPage(t)
			}
		}
		groups = append(groups, group)
	}
	first := spec.All[0].ID
	// No heading over the list: the screen's own title says Tools just above
	// it, and the box to search says what the list is for.
	v.List = parts.NewToolList("", words.T(words.ToolsSearch), words.T(words.ToolsNoMatch), groups, first)
	v.List.OnChosen = v.show
	v.List.Search.OnChanged = func(query string) { v.List.Filter(func(id string) bool { return Matches(id, query) }) }
	v.shown = parts.Layers(v.Pages[first].scroll)

	intro := parts.Stack(look.GapRow,
		parts.Text(parts.Title, words.T(words.ToolsTitle)),
		parts.Para(parts.BodyMuted, words.T(words.ToolsLead)),
	)
	top := parts.Column(look.PageWidth, parts.Inset(look.InsetPage, look.InsetPage, look.InsetPage, look.GapCard, intro))
	rail := container.NewVScroll(parts.Inset(0, 0, 0, look.InsetPage, v.List))
	lower := parts.ColumnFill(look.PageWidth, parts.Inset(look.InsetPage, 0, 0, 0,
		parts.RowTop(look.GapCard, 1, parts.Tall(parts.Width(look.RailWidth, rail)), parts.Tall(v.shown))))
	bar, links, tabs := head(icon, version, PlaceTools)
	v.Links, v.Tabs = links, tabs
	return container.NewBorder(bar, nil, nil, nil, container.NewBorder(top, nil, nil, nil, lower)), v
}

// Matches says whether the tool id is shown while query is in the search box:
// by the contract's words for it and by the window's, so a person finds a
// tool by what they read on screen (spec.Tool.Match).
func Matches(id, query string) bool {
	t, ok := spec.Find(id)
	if !ok {
		return false
	}
	w, _ := words.Tool(id)
	return t.Match(query, w.Title, w.Summary)
}

// Shown is the tool whose page the screen shows.
func (v *ToolsView) Shown() string { return v.List.Chosen() }

// show puts the page of the tool id beside the list.
func (v *ToolsView) show(id string) {
	if p, ok := v.Pages[id]; ok {
		v.shown.Objects = []fyne.CanvasObject{p.scroll}
		v.shown.Refresh()
	}
}

// ToolPage is one tool's page: its form, its one primary action, and the
// place its answer is shown in.
type ToolPage struct {
	Tool   spec.Tool
	Inputs map[string]*widget.Entry
	Run    *parts.Button
	Clear  *parts.Button
	words  words.ToolWords
	answer *fyne.Container
	scroll *container.Scroll
}

// toolPage is the page of t, ready for its input.
func toolPage(t spec.Tool) *ToolPage {
	w, _ := words.Tool(t.ID)
	p := &ToolPage{Tool: t, Inputs: map[string]*widget.Entry{}, words: w,
		Run:   parts.NewButton(parts.Primary, w.Action, theme.MediaPlayIcon(), nil),
		Clear: parts.NewButton(parts.Quiet, words.T(words.ToolClear), theme.ContentClearIcon(), nil),
	}
	var fields []fyne.CanvasObject
	for _, in := range t.Inputs {
		iw := w.Inputs[in.Name]
		box := widget.NewMultiLineEntry()
		box.Wrapping = fyne.TextWrapBreak
		box.TextStyle = fyne.TextStyle{Monospace: true}
		box.SetPlaceHolder(iw.Example)
		box.SetMinRowsVisible(look.ToolInputRows)
		p.Inputs[in.Name] = box
		fields = append(fields, parts.Field(iw.Label, box, iw.Hint))
	}
	form := parts.Card("", nil, append(fields, parts.Row(look.GapButtons, p.Run, p.Clear))...)
	intro := parts.Stack(look.GapRow, parts.Text(parts.Heading, w.Title), parts.Para(parts.BodyMuted, w.Summary))
	p.answer = parts.Layers()
	p.ShowReady()
	p.scroll = container.NewVScroll(parts.Inset(0, 0, look.InsetPage, look.InsetPage,
		parts.Column(look.ProseWidth, parts.Stack(look.GapCard, intro, form, p.answer))))
	return p
}

// Request is what is typed into the page, by input.
func (p *ToolPage) Request() map[string]string {
	r := map[string]string{}
	for name, box := range p.Inputs {
		r[name] = box.Text
	}
	return r
}

// Ready says whether every input has something typed in it.
func (p *ToolPage) Ready() bool {
	for _, box := range p.Inputs {
		if box.Text == "" {
			return false
		}
	}
	return true
}

func (p *ToolPage) set(o fyne.CanvasObject) {
	p.answer.Objects = []fyne.CanvasObject{o}
	p.answer.Refresh()
}

// ShowReady is the page before its action was pressed, or after Clear.
func (p *ToolPage) ShowReady() { p.set(parts.Empty(p.words.Ready)) }

// ShowRunning is the page while the command line reads the input.
func (p *ToolPage) ShowRunning() { p.set(parts.Empty(words.T(words.ToolRunning))) }

// ShowRefusal is the tool saying what it was given is not something it can
// read, in the command line's own sentence.
func (p *ToolPage) ShowRefusal(sentence string) {
	p.set(parts.Problem(words.T(words.ToolRefusedTitle), sentence, words.T(words.ToolRefusedTodo), ""))
}

// ShowProblem is the tool not answering at all, in the window's words.
func (p *ToolPage) ShowProblem(title, what, todo, printed string) {
	p.set(parts.Problem(title, what, todo, printed))
}

// ShowAnswer is the tool's answer: what it did to the input, its checks,
// then every block of its view, each drawn by the part of its kind.
func (p *ToolPage) ShowAnswer(d spec.Document) {
	var cards []fyne.CanvasObject
	if len(d.Notes) > 0 {
		var notes []fyne.CanvasObject
		for _, n := range d.Notes {
			notes = append(notes, parts.Para(parts.BodyMuted, n))
		}
		cards = append(cards, parts.Card(words.T(words.ToolNotes), nil, notes...))
	}
	if len(d.Checks) > 0 {
		var checks []fyne.CanvasObject
		for _, c := range d.Checks {
			checks = append(checks, parts.Check(model.Status(c.Status), c.Summary))
		}
		cards = append(cards, parts.Card(words.T(words.ToolChecks), nil, checks...))
	}
	for _, b := range d.View {
		cards = append(cards, block(b))
	}
	p.set(parts.Stack(look.GapCard, cards...))
}

// block is one block of a tool's view as a card.
func block(b spec.DocumentBlock) fyne.CanvasObject {
	switch spec.BlockKind(b.Kind) {
	case spec.Fields:
		var rows []parts.FieldRow
		for _, f := range *b.Fields {
			rows = append(rows, parts.FieldRow{Label: f.Label, Value: f.Value, Note: deref(f.Note),
				Status: model.Status(deref(f.Status))})
		}
		return parts.Card(b.Title, nil, parts.Fields(rows))
	case spec.Code:
		return parts.Card(b.Title, parts.CopyButton(*b.Body, false), parts.CodeBlock(*b.Body))
	default:
		return parts.Card(b.Title, nil, parts.Para(parts.Body, *b.Body))
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
