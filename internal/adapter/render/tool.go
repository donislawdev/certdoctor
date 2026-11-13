package render

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// ToolPage is one tool's outcome as a person at a console reads it.
type ToolPage struct {
	Tool        spec.Tool
	Version     string
	EvaluatedAt time.Time
	Outcome     spec.Outcome
}

// toolFooter is the sentence a tool's page ends with, for the same reason a
// report ends with one: what it shows came out of somebody's token or file,
// and the person about to paste it somewhere is the one who decides.
const toolFooter = "This shows what the input carries. Read it before pasting it anywhere."

// RenderTool writes a tool's page, or nothing, assembled in a buffer and
// written once - the promise Render keeps for a report.
//
// ONE DRAWING FOR EVERY TOOL (ADR141 point 5). It knows the three kinds of
// block and no tool: a tool added tomorrow is drawn by this, unchanged. And
// everything a tool shows passes through visible, because all of it came out
// of bytes a person handed over and may carry an escape sequence aimed at
// this terminal.
func (t Terminal) RenderTool(w io.Writer, p ToolPage) error {
	var b strings.Builder
	fmt.Fprintf(&b, "certdoctor %s   tool %s - %s\n", visible(p.Version), p.Tool.ID, p.Tool.Title)
	fmt.Fprintf(&b, "judged at %s\n", p.EvaluatedAt.UTC().Format(time.RFC3339))
	if len(p.Outcome.Notes) > 0 {
		b.WriteString("\nNOTES\n")
		for _, note := range p.Outcome.Notes {
			writeFlow(&b, "  ", 2, 2, prose(visible(note)))
		}
	}
	t.writeChecks(&b, p.Outcome.Checks)
	for _, block := range p.Outcome.View {
		t.writeBlock(&b, block)
	}
	fmt.Fprintf(&b, "\n%s\n", toolFooter)
	_, err := io.WriteString(w, b.String())
	return err
}

// Shown is out with every word a person is shown made safe to draw: notes,
// checks and every part of the view through visible, line by line, so a
// line break stays a line break. Data is left as it came - a script reads it
// and does its own drawing.
//
// IT IS WHAT THE DOCUMENT CARRIES, so the window - which draws the view and
// interprets nothing - gets the same escaping the terminal does, from the
// one rule that makes it, rather than a second copy of the rule in the
// window (ADR141 point 9). A bidirectional override in a token's claim
// reorders text in a window as surely as in a terminal.
func Shown(out spec.Outcome) spec.Outcome {
	shown := spec.Outcome{Data: out.Data}
	for _, note := range out.Notes {
		shown.Notes = append(shown.Notes, visible(note))
	}
	for _, c := range out.Checks {
		shown.Checks = append(shown.Checks, spec.Check{ID: visible(c.ID), Status: c.Status, Summary: visible(c.Summary)})
	}
	for _, b := range out.View {
		s := spec.Block{Kind: b.Kind, Title: visible(b.Title), Language: visible(b.Language), Body: visibleLines(b.Body)}
		for _, f := range b.Fields {
			s.Fields = append(s.Fields, spec.Field{Label: visible(f.Label), Value: visible(f.Value),
				Note: visible(f.Note), Status: f.Status})
		}
		shown.View = append(shown.View, s)
	}
	return shown
}

// visibleLines is visible applied to each line of text, the breaks kept.
func visibleLines(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = visible(line)
	}
	return strings.Join(lines, "\n")
}

// writeChecks writes one line per check - its marker, its status and its
// sentence wrapped under itself.
func (t Terminal) writeChecks(b *strings.Builder, checks []spec.Check) {
	if len(checks) == 0 {
		return
	}
	b.WriteString("\nCHECKS\n")
	labelWidth := 0
	for _, c := range checks {
		labelWidth = max(labelWidth, widthOf(Label(c.Status)))
	}
	for _, c := range checks {
		lead := "  " + t.badge(c.Status) + " " + Paint(c.Status, t.Color, pad(Label(c.Status), labelWidth))
		leadWidth := 2 + widthOf(Of(c.Status).Marker(t.Glyph)) + 1 + labelWidth
		pieces := prose(visible(c.Summary))
		if len(pieces) > 0 {
			pieces[0].gap += 2
		}
		writeFlow(b, lead, leadWidth, leadWidth+2, pieces)
	}
}

// writeBlock writes one block under its title.
//
// A CODE BLOCK IS WRITTEN LINE FOR LINE AND NEVER WRAPPED: it is data, and a
// line of JSON broken by the page is a different line when copied (ADR109).
// A Text block is prose and wraps at its spaces.
func (t Terminal) writeBlock(b *strings.Builder, block spec.Block) {
	fmt.Fprintf(b, "\n%s\n", strings.ToUpper(visible(block.Title)))
	switch block.Kind {
	case spec.Fields:
		t.writeFields(b, block.Fields)
	case spec.Code:
		for _, line := range strings.Split(block.Body, "\n") {
			writeTrimmed(b, "  "+visible(line))
		}
	default:
		writeFlow(b, "  ", 2, 2, prose(visible(block.Body)))
	}
}

// valueColumn is the widest a value column is measured to. A longer value -
// a key id of a thousand characters - runs past it on its own line rather
// than pushing every note in the block off the page.
const valueColumn = 40

// writeFields writes a table of labels and values, a note beside each value
// that has one, and the marker of a status in front of each row that carries
// a judgement. The columns are measured, not chosen.
//
// A NOTE IS PROSE AND WRAPS at the page's width, every line after its first
// under the note column - the rule the report's pages follow (ADR109). The
// label and the value are data and never break.
func (t Terminal) writeFields(b *strings.Builder, fields []spec.Field) {
	labelWidth, valueWidth, markWidth := 0, 0, 0
	for _, f := range fields {
		labelWidth = max(labelWidth, widthOf(visible(f.Label)))
		valueWidth = min(max(valueWidth, widthOf(visible(f.Value))), valueColumn)
		if f.Status != "" {
			markWidth = t.markerWidth()
		}
	}
	for _, f := range fields {
		line := "  " + t.fieldMark(f.Status, markWidth) + pad(visible(f.Label), labelWidth) + "  "
		if f.Note == "" {
			writeTrimmed(b, line+visible(f.Value))
			continue
		}
		// Counted rather than measured: the marker may carry a colour, and its
		// escape sequence takes no room on the screen (writeFlow).
		noteColumn := 2 + markWidth + labelWidth + 2 + max(valueWidth, widthOf(visible(f.Value))) + 2
		lead := line + pad(visible(f.Value), valueWidth) + "  "
		writeFlow(b, lead, noteColumn, noteColumn, prose(visible(f.Note)))
	}
}

// markerWidth is the room the widest status marker takes, with its space.
func (t Terminal) markerWidth() int {
	widest := 0
	for _, s := range status.All {
		widest = max(widest, widthOf(Of(s).Marker(t.Glyph)))
	}
	return widest + 1
}

// fieldMark is the marker of a row's status padded to width, or width spaces
// for a row that carries none.
func (t Terminal) fieldMark(s status.Status, width int) string {
	if width == 0 {
		return ""
	}
	if s == "" {
		return strings.Repeat(" ", width)
	}
	return t.badge(s) + strings.Repeat(" ", width-widthOf(Of(s).Marker(t.Glyph)))
}
