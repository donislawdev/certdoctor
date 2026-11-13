package screens

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/words"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// longAnswer is a tool's document with every kind of block, every optional
// part, and words as long as they come - each with no space to break at.
func longAnswer(t *testing.T) spec.Document {
	t.Helper()
	jwt, _ := spec.Find("jwt")
	out := spec.Outcome{
		Notes:  []string{longPrinted},
		Checks: []spec.Check{{ID: "expiry", Status: "FAIL", Summary: longPrinted}, {ID: "signature", Status: "UNKNOWN", Summary: "Not checked."}},
		Data:   map[string]string{},
		View: []spec.Block{
			{Kind: spec.Fields, Title: "Token", Fields: []spec.Field{
				{Label: "Key ID", Value: longPrinted, Note: longPrinted, Status: "WARN"},
				{Label: longPrinted, Value: "RS256"},
			}},
			{Kind: spec.Code, Title: "Payload", Language: "json", Body: "{\n  \"x\": \"" + longPrinted + "\"\n}"},
			{Kind: spec.Text, Title: "Note", Body: longPrinted},
		},
	}
	d, err := spec.NewDocument(jwt, "0.1.0", "2026-11-12T12:00:00Z", out)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// toolScreens are the Tools screen in every state its page takes, for the
// checks every screen is held to.
func toolScreens(t *testing.T, ic fyne.Resource) []screen {
	t.Helper()
	answer := longAnswer(t)
	state := func(name string, show func(*ToolPage)) screen {
		return screen{"tools " + name, func() fyne.CanvasObject {
			o, v := Tools(ic, "0.1.0")
			v.Pages["jwt"].Inputs["token"].SetText(longPrinted)
			show(v.Pages["jwt"])
			return o
		}}
	}
	return []screen{
		state("ready", func(*ToolPage) {}),
		state("reading", (*ToolPage).ShowRunning),
		state("answer", func(p *ToolPage) { p.ShowAnswer(answer) }),
		state("refusal", func(p *ToolPage) { p.ShowRefusal(longPrinted) }),
		state("problem", func(p *ToolPage) { p.ShowProblem("Title", longPrinted, longPrinted, longPrinted) }),
	}
}

// TestEveryToolHasTheWindowsWords holds the contract's list of tools and the
// window's words for them to each other in both directions: a tool added to
// the list without words would show bare ids, and words left behind by a tool
// that went would never be drawn.
func TestEveryToolHasTheWindowsWords(t *testing.T) {
	for _, tool := range spec.All {
		w, ok := words.Tool(tool.ID)
		if !ok || w.Title == "" || w.Summary == "" || w.Action == "" || w.Ready == "" {
			t.Errorf("the window has no words, or not all of them, for the tool %q: %+v", tool.ID, w)
			continue
		}
		for _, in := range tool.Inputs {
			if iw := w.Inputs[in.Name]; iw.Label == "" || iw.Hint == "" {
				t.Errorf("%s: no words for the input %q", tool.ID, in.Name)
			}
		}
		if len(w.Inputs) != len(tool.Inputs) {
			t.Errorf("%s: words for %d input(s), and the tool takes %d", tool.ID, len(w.Inputs), len(tool.Inputs))
		}
	}
	for _, id := range words.ToolIDs() {
		if _, ok := spec.Find(id); !ok {
			t.Errorf("the window has words for %q, which is not on the list of tools", id)
		}
	}
	for _, c := range spec.Categories {
		if words.Category(string(c)) == string(c) {
			t.Errorf("the category %q has no heading in the window", c)
		}
	}
}

func TestTheToolListNarrowsAsASearchIsTyped(t *testing.T) {
	newApp(t)
	_, v := Tools(icon(t), "0.1.0")
	for query, shown := range map[string]bool{"": true, "jwt": true, "BEARER": true, "Decoder": true, "certificate": false} {
		if got := Matches("jwt", query); got != shown {
			t.Errorf("Matches(jwt, %q) = %v, want %v", query, got, shown)
		}
	}
	first := v.Shown()
	if first != spec.All[0].ID {
		t.Errorf("the page shown first is %q, want the first tool on the list", first)
	}
	v.List.Search.SetText("certificate")
	if v.List.Showing("jwt") || !v.List.Showing("cert") {
		t.Error("typing a search that leaves the JWT decoder out left it on the list, or took the other one off")
	}
	if v.Shown() != first {
		t.Error("the page beside the list changed while a search was typed")
	}
	v.List.Search.SetText("token")
	if !v.List.Showing("jwt") || v.Shown() != first || Matches("no-such-tool", "") {
		t.Error("a search that matches the decoder does not show it, or moved the page")
	}
}

func TestAToolsAnswerIsDrawnWithEveryKindOfBlock(t *testing.T) {
	newApp(t)
	_, v := Tools(icon(t), "0.1.0")
	p := v.Pages["jwt"]
	p.ShowAnswer(longAnswer(t))
	drawn := strings.Join(texts(p.answer), "\n")
	for _, want := range []string{words.T(words.ToolNotes), words.T(words.ToolChecks), "Token", "Key ID", "Payload",
		"Note", "Not checked."} {
		if !strings.Contains(drawn, want) {
			t.Errorf("the answer does not show %q:\n%s", want, drawn)
		}
	}
	if findButton(p.answer, words.T(words.Copy)) == nil {
		t.Error("the code block has no Copy")
	}
	p.ShowReady()
	if drawn := strings.Join(texts(p.answer), "\n"); !strings.Contains(drawn, p.words.Ready) {
		t.Errorf("after Clear the page says %q", drawn)
	}
}

func TestAToolsPageIsReadyOnlyWithEveryInput(t *testing.T) {
	newApp(t)
	_, v := Tools(icon(t), "0.1.0")
	p := v.Pages["jwt"]
	if p.Ready() {
		t.Error("an empty page is ready")
	}
	p.Inputs["token"].SetText("eyJ")
	if !p.Ready() || p.Request()["token"] != "eyJ" {
		t.Errorf("a page with its token typed: ready %v, request %v", p.Ready(), p.Request())
	}
}

// A token over what the window takes is not put in, and the line under the
// box says so with the command line's way to read it; text over it put in by
// the program leaves the page not ready; Clear brings the hint back (ADR144).
func TestAnInputOverWhatTheWindowTakesIsRefusedUnderItsBox(t *testing.T) {
	newApp(t)
	_, v := Tools(icon(t), "0.1.0")
	p := v.Pages["jwt"]
	box, note := p.Inputs["token"], p.Notes["token"]
	if box.Limit != look.ToolInputBytes {
		t.Fatalf("the token box takes %d bytes, want %d", box.Limit, look.ToolInputBytes)
	}
	fyne.CurrentApp().Clipboard().SetContent(strings.Repeat("a", look.ToolInputBytes+1))
	box.TypedShortcut(&fyne.ShortcutPaste{Clipboard: fyne.CurrentApp().Clipboard()})
	// Read from the page down rather than from the note: a note Fyne does not
	// draw - the first version of the part - is not reached from the page.
	said := strings.Join(texts(p.scroll), " ")
	if box.Text != "" || !note.Refused() || !strings.Contains(said, "certdoctor tool jwt --file <file>") {
		t.Errorf("a paste over the limit: %d bytes in the box, note %q", len(box.Text), said)
	}
	box.SetText(strings.Repeat("a", look.ToolInputBytes+1))
	if p.Ready() || !note.Refused() {
		t.Errorf("text over the limit set by the program: ready %v, refused %v", p.Ready(), note.Refused())
	}
	p.ClearInputs()
	if box.Text != "" || note.Refused() {
		t.Errorf("after Clear: %d bytes, refused %v", len(box.Text), note.Refused())
	}
}

// The catalogue's field is the page's: the same limit and the same refusal -
// and an input the contract does not have is no field at all.
func TestTheCatalogueGetsTheFieldThePageHas(t *testing.T) {
	newApp(t)
	box, note, field, ok := ToolInput("jwt", 0)
	if !ok || box.Limit != look.ToolInputBytes || field == nil {
		t.Fatalf("the decoder's token field: ok %v", ok)
	}
	box.OnRefused()
	if !note.Refused() || !strings.Contains(strings.Join(texts(field), " "), "certdoctor tool jwt --file <file>") {
		t.Error("the catalogue's field does not refuse the way the page's does")
	}
	for _, c := range []struct {
		id string
		i  int
	}{{"no-such-tool", 0}, {"jwt", 1}} {
		if _, _, _, ok := ToolInput(c.id, c.i); ok {
			t.Errorf("input %d of %s was built", c.i, c.id)
		}
	}
}

// texts are the words drawn under o, through the containers, scrolls and
// widgets a screen is built of.
func texts(o fyne.CanvasObject) []string {
	switch x := o.(type) {
	case *widget.RichText:
		var b strings.Builder
		for _, s := range x.Segments {
			if t, ok := s.(*widget.TextSegment); ok {
				b.WriteString(t.Text)
			}
		}
		return []string{b.String()}
	case *fyne.Container:
		var all []string
		for _, child := range x.Objects {
			all = append(all, texts(child)...)
		}
		return all
	case *container.Scroll:
		return texts(x.Content)
	case *parts.Button:
		return []string{x.Label}
	case fyne.Widget:
		r := x.CreateRenderer()
		var all []string
		for _, child := range r.Objects() {
			all = append(all, texts(child)...)
		}
		return all
	}
	return nil
}
