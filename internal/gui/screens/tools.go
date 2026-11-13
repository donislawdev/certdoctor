package screens

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"

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
	Inputs map[string]*parts.LimitedEntry
	// Notes are the line under each input: its hint, or why what was pasted
	// was not taken (ADR144).
	Notes map[string]*parts.FieldNote
	Run   *parts.Button
	Clear *parts.Button
	// OnEdited is called after the text of an input changed.
	OnEdited func()
	words    words.ToolWords
	answer   *fyne.Container
	scroll   *container.Scroll
}

// toolPage is the page of t, ready for its input.
//
// AN INPUT TAKES NO MORE THAN look.ToolInputBytes (ADR144), whatever the
// tool reads: a tool reading less refuses the rest itself, in the command
// line's own sentence, as it does any input it cannot use.
func toolPage(t spec.Tool) *ToolPage {
	w, _ := words.Tool(t.ID)
	p := &ToolPage{Tool: t, Inputs: map[string]*parts.LimitedEntry{}, Notes: map[string]*parts.FieldNote{}, words: w,
		Run:   parts.NewButton(parts.Primary, w.Action, theme.MediaPlayIcon(), nil),
		Clear: parts.NewButton(parts.Quiet, words.T(words.ToolClear), theme.ContentClearIcon(), nil),
	}
	var fields []fyne.CanvasObject
	for i, in := range t.Inputs {
		box, note, field := toolInput(t, i)
		box.OnChanged = func(string) { p.edited(box, note) }
		p.Inputs[in.Name], p.Notes[in.Name] = box, note
		fields = append(fields, field)
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

// Ready says whether every input has something typed in it, and no more than
// it takes.
func (p *ToolPage) Ready() bool {
	for _, box := range p.Inputs {
		if box.Text == "" || box.Over() {
			return false
		}
	}
	return true
}

// ClearInputs empties every input and shows its hint again.
func (p *ToolPage) ClearInputs() {
	for name, box := range p.Inputs {
		box.SetText("")
		p.Notes[name].Clear()
	}
}

// ToolInput is the field of input i of the tool id as its page has it - the
// box, the line under it, and both beside the input's name - for the
// catalogue, which shows the part the page shows rather than a copy of it.
// The box says why it refused a paste through its OnRefused.
func ToolInput(id string, i int) (*parts.LimitedEntry, *parts.FieldNote, fyne.CanvasObject, bool) {
	t, ok := spec.Find(id)
	if !ok || i >= len(t.Inputs) {
		return nil, nil, nil, false
	}
	box, note, field := toolInput(t, i)
	return box, note, field, true
}

// toolInput is the field of input i of t.
func toolInput(t spec.Tool, i int) (*parts.LimitedEntry, *parts.FieldNote, fyne.CanvasObject) {
	w, _ := words.Tool(t.ID)
	iw := w.Inputs[t.Inputs[i].Name]
	box := parts.NewLimitedEntry(look.ToolInputBytes)
	box.Wrapping = fyne.TextWrapBreak
	box.TextStyle = fyne.TextStyle{Monospace: true}
	box.SetPlaceHolder(iw.Example)
	box.SetMinRowsVisible(look.ToolInputRows)
	note := parts.NewFieldNote(iw.Hint)
	refused := words.InputTooLong(look.ToolInputBytes, t.Inputs[i].MaxBytes, t.ID, t.FileSwitch(i))
	box.OnRefused = func() { note.Refuse(refused) }
	return box, note, parts.FieldWith(iw.Label, box, note)
}

// edited keeps an input's note true to what is in it - the hint, or the
// refusal while the input holds more than it takes, which text set by the
// program can make it - and tells the window.
func (p *ToolPage) edited(box *parts.LimitedEntry, note *parts.FieldNote) {
	if box.Over() {
		box.OnRefused()
	} else {
		note.Clear()
	}
	if p.OnEdited != nil {
		p.OnEdited()
	}
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
