package render

import (
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// toolPage is a page with every kind of block, a row with a status and rows
// without, a value longer than its column and a value carrying an escape
// sequence aimed at the terminal.
func toolPage() ToolPage {
	tool, _ := spec.Find("jwt")
	return ToolPage{
		Tool:        tool,
		Version:     "0.1.0",
		EvaluatedAt: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC),
		Outcome: spec.Outcome{
			Notes: []string{"Took off \"Bearer\" in front of the token."},
			Checks: []spec.Check{
				{ID: "expiry", Status: status.Fail, Summary: "Expired 3 hours ago " + strings.Repeat("and longer ", 12)},
				{ID: "signature", Status: status.Unknown, Summary: "Not checked."},
			},
			View: []spec.Block{
				{Kind: spec.Fields, Title: "Times", Fields: []spec.Field{
					{Label: "Issued (iat)", Value: "2026-11-12 09:00:00 UTC", Note: "3 hours ago"},
					{Label: "Expires (exp)", Value: "2026-11-12 09:00:00 UTC", Note: "3 hours ago", Status: status.Fail},
					{Label: "Key ID", Value: strings.Repeat("k", 60), Note: "long"},
					{Label: "Type", Value: "\x1b[31mJWT\x1b[0m"},
				}},
				{Kind: spec.Code, Title: "Payload", Language: "json", Body: "{\n  \"a\": \"\x1b]0;x\x07\"\n}"},
				{Kind: spec.Text, Title: "Note", Body: "A paragraph " + strings.Repeat("that wraps ", 15)},
			},
		},
	}
}

func TestEveryToolIsDrawnByOneDrawing(t *testing.T) {
	var b strings.Builder
	if err := (Terminal{}).RenderTool(&b, toolPage()); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	for _, want := range []string{
		"certdoctor 0.1.0   tool jwt - JWT decoder\njudged at 2026-11-12T12:00:00Z\n",
		"\nNOTES\n  Took off \"Bearer\" in front of the token.\n",
		"\nCHECKS\n", "FAIL     Expired 3 hours ago",
		"\nTIMES\n", "Issued (iat)   2026-11-12 09:00:00 UTC                   3 hours ago",
		"Key ID         " + strings.Repeat("k", 60) + "  long",
		"\nPAYLOAD\n  {\n", "\nNOTE\n  A paragraph that wraps",
		"\n" + toolFooter + "\n",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not say %q:\n%s", want, page)
		}
	}
	if strings.ContainsAny(page, "\x1b\x07") {
		t.Errorf("an escape sequence from the input reached the terminal:\n%q", page)
	}
	for _, line := range strings.Split(page, "\n") {
		if utf8.RuneCountInString(line) > pageWidth && !strings.Contains(line, strings.Repeat("k", 60)) {
			t.Errorf("prose ran past the page: %q", line)
		}
	}
}

func TestAFieldWithAStatusIsMarkedAndTheOthersLineUp(t *testing.T) {
	var b strings.Builder
	if err := (Terminal{}).RenderTool(&b, toolPage()); err != nil {
		t.Fatal(err)
	}
	var issued, expires string
	for _, line := range strings.Split(b.String(), "\n") {
		switch {
		case strings.Contains(line, "Issued (iat)"):
			issued = line
		case strings.Contains(line, "Expires (exp)"):
			expires = line
		}
	}
	marker := Of(status.Fail).Marker(GlyphASCII)
	if !strings.HasPrefix(expires, "  "+marker+" ") || strings.Index(issued, "Issued") != strings.Index(expires, "Expires") {
		t.Errorf("rows do not line up behind the marker:\n%q\n%q", issued, expires)
	}
}

// TestANoteWrapsUnderItsColumn holds a note that runs past the page to the
// page, every line after its first starting under the note - with a status
// marker in colour in front of the row, whose escape sequence takes no room on
// the screen and so may not push the continuation right.
func TestANoteWrapsUnderItsColumn(t *testing.T) {
	note := strings.Repeat("several words of a note ", 8) + "end"
	for _, colour := range []ColorMode{ColorOff, ColorOn} {
		page := toolPage()
		page.Outcome.View = []spec.Block{{Kind: spec.Fields, Title: "Rows", Fields: []spec.Field{
			{Label: "Label", Value: "value", Note: note, Status: status.Warn},
			{Label: "Longer label", Value: "v", Note: "short"},
		}}}
		var b strings.Builder
		if err := (Terminal{Color: colour}).RenderTool(&b, page); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(escapeSequence.ReplaceAllString(b.String(), ""), "\n")
		start := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "several") })
		if start < 0 {
			t.Fatalf("colour %v: no row with the note:\n%s", colour, b.String())
		}
		column := strings.Index(lines[start], "several")
		var words []string
		for i := start; i < len(lines) && !strings.Contains(lines[i], "Longer label"); i++ {
			if utf8.RuneCountInString(lines[i]) > pageWidth {
				t.Errorf("colour %v: the note ran past the page: %q", colour, lines[i])
			}
			if i > start && (len(lines[i]) <= column || strings.TrimSpace(lines[i][:column]) != "" ||
				lines[i][column] == ' ') {
				t.Errorf("colour %v: a line of the note does not start under it (column %d): %q", colour, column, lines[i])
			}
			words = append(words, strings.Fields(lines[i])...)
		}
		if got := strings.Join(words, " "); !strings.HasSuffix(got, strings.Join(strings.Fields(note), " ")) {
			t.Errorf("colour %v: the note lost words: %q", colour, got)
		}
		if start+1 >= len(lines) || strings.Contains(lines[start+1], "Longer label") {
			t.Errorf("colour %v: a note longer than the page stayed on one line: %q", colour, lines[start])
		}
	}
}

func TestTheDocumentCarriesTheViewSafeToDrawAndTheDataAsItCame(t *testing.T) {
	out := toolPage().Outcome
	out.Data = map[string]string{"typ": "\x1b[31mJWT"}
	out.Notes = append(out.Notes, "right"+string(rune(0x202e))+"left")
	shown := Shown(out)
	if shown.Data.(map[string]string)["typ"] != "\x1b[31mJWT" {
		t.Error("the data was changed - a script reads it as it came")
	}
	var words []string
	words = append(words, shown.Notes...)
	for _, b := range shown.View {
		words = append(words, b.Title, b.Body)
		for _, f := range b.Fields {
			words = append(words, f.Label, f.Value, f.Note)
		}
	}
	for _, w := range words {
		if strings.ContainsAny(w, "\x1b\x07"+string(rune(0x202e))) {
			t.Errorf("a word reached the document unsafe to draw: %q", w)
		}
	}
	if code := shown.View[1].Body; !strings.Contains(code, "\n") || !strings.Contains(code, `\u`+`001b]0;x\u`+`0007`) {
		t.Errorf("the code block lost its line breaks or its escapes: %q", code)
	}
}

func TestWrapKeepsASentenceWithinThePage(t *testing.T) {
	lines := Wrap(strings.Repeat("word ", 60), 10)
	if len(lines) < 3 {
		t.Fatalf("300 characters came back as %d line(s)", len(lines))
	}
	for _, line := range lines {
		if utf8.RuneCountInString(line) > pageWidth-10 {
			t.Errorf("a line of %d after an indent of 10: %q", utf8.RuneCountInString(line), line)
		}
	}
}
