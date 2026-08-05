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

// writeHeading prints the line that says which build looked at what, when.
//
// THE TIMESTAMP IS DELIBERATELY COARSER HERE THAN IN THE MACHINE READABLE
// REPORT, and the difference is a decision rather than an oversight. The
// document carries nanoseconds so that two runs inside one second can be put in
// order by whatever reads them. A person reading a heading cannot use them and
// has to read past them, so this stops at the second. Both are UTC, and that
// part is not a preference - a report is written on one machine and read on
// another.
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
		writeTrimmed(b, line.String())
		t.writeFindings(b, row)
	}
}

// writeTrimmed ends one assembled line, without the padding that ran off it.
//
// A row that stops short of the widest one would otherwise carry its padding out
// to the line end. Trailing spaces are invisible until the report is pasted
// somewhere that shows them, and then they look like the tool is careless about
// everything else too.
//
// IT IS ONE FUNCTION BECAUSE THE RULE IS ONE RULE. Two column blocks now end
// their lines - the layer rows and the findings beneath them - and writing the
// same trim twice would mean one of them could lose it while the other kept it.
// It also gave the mutation register two places matching one anchor, which is
// reported as a skip: a mutation that proves nothing, in the quietest way this
// register can fail.
func writeTrimmed(b *strings.Builder, line string) {
	b.WriteString(strings.TrimRight(line, " "))
	b.WriteString("\n")
}

// writeFindings prints what one layer established, underneath its own row.
//
// THREE STATES AND ALL THREE ARE VISIBLE HERE. A layer that never looked prints
// nothing - it has already said so in its row and in the notes, and a line
// saying "nothing" would read as a result. A layer that looked and found nothing
// says exactly that, because an absent section reads as a question nobody asked.
// A layer that found something prints one line per finding.
//
// The columns are measured within the layer rather than across the report. Two
// layers' findings have nothing to do with each other, and one long path from
// the trust matrix would otherwise set the width for every environment variable
// in L0.
func (t Terminal) writeFindings(b *strings.Builder, row report.LayerResult) {
	if row.Findings == nil {
		return
	}
	if len(row.Findings) == 0 {
		b.WriteString("      nothing was found\n")
		return
	}

	summaryWidth, sourceWidth := 0, 0
	for _, finding := range row.Findings {
		summaryWidth = max(summaryWidth, widthOf(finding.Summary))
		sourceWidth = max(sourceWidth, widthOf(finding.Source.String()))
	}

	for _, finding := range row.Findings {
		var line strings.Builder
		fmt.Fprintf(&line, "      %s  %s",
			pad(finding.Summary, summaryWidth),
			pad(finding.Source.String(), sourceWidth))
		if value := findingValue(finding); value != "" {
			fmt.Fprintf(&line, "  %s", value)
		}
		writeTrimmed(b, line.String())
	}
}

// findingValue is the part of a finding that only means anything once the kind
// is known. It is the empty string for a kind this renderer has no handling for,
// which is how a kind added later still reaches this page through its summary
// instead of vanishing from it.
//
// A CONTRACT FOR WHOEVER PRODUCES A FINDING, because this is where it bites: a
// variable that is SET TO NOTHING has no value to print, so its summary is the
// only thing that can say so. The difference between unset and set to nothing
// decides whether some tools proxy at all, and it must not survive only in the
// machine readable document.
func findingValue(finding report.Finding) string {
	switch {
	case finding.EnvironmentVariable != nil:
		variable := finding.EnvironmentVariable
		if !variable.Set {
			return ""
		}
		return variable.Value
	case finding.NameResolution != nil:
		return resolutionValue(*finding.NameResolution)
	}
	return ""
}

// resolutionValue is the addresses, and the time it took to get them.
//
// THE RESPONSE CODE IS DELIBERATELY NOT HERE. It belongs in the summary, which
// is the line every surface renders without knowing the kind - and a row saying
// SERVFAIL only in a column this renderer happens to print would be invisible in
// markdown the day that renderer exists.
//
// The duration rides along rather than getting a column of its own, because a
// column invites reading down it. D13: two answers' times are not comparable -
// whichever query went second benefited from whatever the first one warmed, and
// that has now been measured twice.
func resolutionValue(answer report.NameResolution) string {
	value := strings.Join(answer.Addresses, ", ")
	if answer.DurationMS <= 0 {
		return value
	}
	if value == "" {
		return fmt.Sprintf("%d ms", answer.DurationMS)
	}
	return fmt.Sprintf("%s  %d ms", value, answer.DurationMS)
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
