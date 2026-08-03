package render

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Terminal renders a report for a person at a console.
//
// It takes its colour and glyph modes as fields rather than working them out,
// because deciding them means asking the operating system and this type is
// meant to be renderable into a buffer in a test. The zero value is the safe
// one: no colour and plain ASCII markers, which are readable in every terminal,
// every log file and every ticket.
type Terminal struct {
	Color ColorMode
	Glyph GlyphMode
}

// footer is the sentence the report ends with, every time.
//
// It is not boilerplate. The report carries internal host names and file system
// paths because that is what makes it useful in a ticket, and the person about
// to paste it is the only one who can decide whether that is all right. Masking
// is a filter and not a guarantee, and saying so is the difference between a
// tool that leaked something and a tool that warned you first.
const footer = "This report contains internal names and paths. Read it before pasting it anywhere."

// Render writes the whole report, or nothing.
//
// It assembles into a buffer and writes once. A renderer that streamed would
// leave half a report on standard output when it failed halfway, and half a
// report looks exactly like a whole one to whatever reads it next.
func (t Terminal) Render(w io.Writer, r report.Report) error {
	var b strings.Builder

	t.writeHeading(&b, r)
	t.writeVerdict(&b, r)
	t.writeLayers(&b, r)
	t.writeNotes(&b, r)
	fmt.Fprintf(&b, "\n%s\n", footer)

	_, err := io.WriteString(w, b.String())
	return err
}

func (t Terminal) writeHeading(b *strings.Builder, r report.Report) {
	fmt.Fprintf(b, "%s %s   %s\n", r.Tool.Name, r.Tool.Version, r.Run.Target)
	fmt.Fprintf(b, "%s   %s   privilege: %s   took %s\n",
		r.Run.StartedAt.UTC().Format(time.RFC3339),
		r.Run.Platform.OS+"/"+r.Run.Platform.Arch,
		r.Run.PrivilegeLevel,
		r.Run.Duration.Round(time.Millisecond))
}

func (t Terminal) writeVerdict(b *strings.Builder, r report.Report) {
	fmt.Fprintf(b, "\n%s %s\n", t.badge(r.Verdict.Status), Paint(r.Verdict.Status, t.Color, r.Verdict.Sentence))
	fmt.Fprintf(b, "exit %d %s\n", r.Verdict.ExitCode.Int(), r.Verdict.ExitCode.Name())
}

// writeLayers prints one row per layer, in the order the report carries them.
//
// Column widths are measured rather than chosen. A width picked by hand looks
// right on the author's machine and truncates the first path longer than the
// one they happened to test with, and paths are the part of this report nobody
// can guess the length of.
func (t Terminal) writeLayers(b *strings.Builder, r report.Report) {
	b.WriteString("\nLAYERS\n")

	idWidth, labelWidth, nameWidth := 0, 0, 0
	for _, row := range r.Layers {
		idWidth = max(idWidth, widthOf(row.ID.String()))
		labelWidth = max(labelWidth, widthOf(Label(row.Status)))
		nameWidth = max(nameWidth, widthOf(row.ID.Name()))
	}

	for _, row := range r.Layers {
		var line strings.Builder
		fmt.Fprintf(&line, "  %s %s  %s  %s",
			t.badge(row.Status),
			Paint(row.Status, t.Color, pad(Label(row.Status), labelWidth)),
			pad(row.ID.String(), idWidth),
			pad(row.ID.Name(), nameWidth))
		if row.Reason != "" {
			fmt.Fprintf(&line, "  %s", row.Reason)
		}
		if row.Detail != "" {
			fmt.Fprintf(&line, "  %s", row.Detail)
		}
		// A row that ends short of the widest one would otherwise carry the
		// padding out to the line end. Trailing spaces are invisible until the
		// report is pasted somewhere that shows them, and then they look like
		// the tool is careless about everything else too.
		b.WriteString(strings.TrimRight(line.String(), " "))
		b.WriteString("\n")
	}
}

// writeNotes prints what the run did not do. It prints the heading even when
// there is nothing under it, because an absent section reads as an absent
// question, and "nothing was skipped" is an answer worth seeing.
func (t Terminal) writeNotes(b *strings.Builder, r report.Report) {
	b.WriteString("\nNOTES\n")
	if len(r.Notes) == 0 {
		b.WriteString("  nothing was skipped and nothing was left undetermined\n")
		return
	}
	for _, note := range r.Notes {
		b.WriteString("  - ")
		if note.Layer != "" {
			fmt.Fprintf(b, "%s ", note.Layer)
		}
		if note.Field != "" {
			fmt.Fprintf(b, "%s ", note.Field)
		}
		fmt.Fprintf(b, "[%s] %s\n", note.Kind, note.Detail)
	}
}

// badge is the marker for a status, taken from the dictionary. No call site in
// this file writes a glyph, and the guard on literal appearance is what keeps
// that true rather than anybody's care.
func (t Terminal) badge(s status.Status) string {
	return Paint(s, t.Color, Of(s).Marker(t.Glyph))
}

// widthOf is the column width of a string, COUNTED IN RUNES.
//
// The unit is named because the standard of code requires every place that
// measures or cuts text to say which one it uses - bytes, code points and
// grapheme clusters are three different numbers. This counted bytes, which is
// the same number only while everything in the column is ASCII. Everything is
// today: layer identifiers, status words and the names in the registry. The
// trust matrix brings paths from somebody else's machine into a column, with an
// account name that may be in Cyrillic or CJK, and byte counting would have
// misaligned the table there and looked like a defect in that layer.
//
// A rune is not a display cell either, and that limit is stated rather than
// hidden: a wide character occupies two columns in a terminal and one rune here.
// Closing that needs a width table this program does not carry and will not add
// for the sake of alignment.
func widthOf(s string) int { return utf8.RuneCountInString(s) }

func pad(s string, width int) string {
	if widthOf(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-widthOf(s))
}
