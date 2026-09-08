package render

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// Markdown renders a report as a document somebody pastes into a ticket.
//
// IT HAS NO OPTIONS, AND THE ABSENCE IS THE POINT. Terminal takes colour and
// glyph modes because it is writing for a device with capabilities; this format
// is read by whatever renders it later - a code host, a ticket tracker, a text
// editor - and none of that is knowable from here. A switch nobody could set
// correctly is worse than no switch.
//
// IT INVENTS NO NAMES. Every heading, label and word below comes from the
// vocabulary already fixed elsewhere: layer identifiers and their names from the
// layer registry, status words from Label, per-kind values from findingValue -
// the same function the terminal calls. Inviolable rule 10 says a concept enters
// the dictionary before it enters the code, and the cheapest way to keep that
// true for a second document surface is to add nothing to name.
//
// THERE IS NO SHARED DOCUMENT MODEL BEHIND THIS AND THE TERMINAL, deliberately.
// Two renderers walking one report can drift, and the answer to that is the
// parity test rather than an abstraction invented before the second case is
// known - the third surface will say whether the shape they share is real.
type Markdown struct{}

// Render writes the whole report, or nothing.
//
// It assembles into a buffer and writes once, for the reason Terminal.Render
// gives: half a report looks exactly like a whole one to whatever reads it next.
func (m Markdown) Render(w io.Writer, r report.Report) error {
	var b strings.Builder

	m.writeHeading(&b, r)
	m.writeVerdict(&b, r)
	m.writeLayers(&b, r)
	m.writeFindings(&b, r)
	m.writeNotes(&b, r)
	fmt.Fprintf(&b, "\n---\n\n%s\n", footer)

	_, err := io.WriteString(w, b.String())
	return err
}

// writeHeading says which build looked at what, when.
//
// THE TIMESTAMP IS THE TERMINAL'S, NOT THE DOCUMENT'S, and that is a decision
// rather than a copy. Terminal.writeHeading explains it: the machine readable
// report carries nanoseconds so two runs inside one second can be ordered, and a
// person cannot use them. This page is read by a person too.
func (m Markdown) writeHeading(b *strings.Builder, r report.Report) {
	fmt.Fprintf(b, "# %s %s - %s\n\n",
		mdText(r.Tool.Name), mdText(r.Tool.Version), mdText(r.Run.Target))
	fmt.Fprintf(b, "%s - %s - privilege: %s - took %s\n",
		mdText(r.Run.StartedAt.UTC().Format(time.RFC3339)),
		mdText(r.Run.Platform.OS+"/"+r.Run.Platform.Arch),
		mdText(string(r.Run.PrivilegeLevel)),
		mdText(r.Run.Duration.Round(time.Millisecond).String()))
}

// writeVerdict prints the one sentence this whole run exists to produce.
func (m Markdown) writeVerdict(b *strings.Builder, r report.Report) {
	fmt.Fprintf(b, "\n## Verdict\n\n**%s** - %s\n\n",
		mdText(Label(r.Verdict.Status)), mdText(r.Verdict.Sentence))
	fmt.Fprintf(b, "exit %d %s\n", r.Verdict.ExitCode.Int(), mdText(r.Verdict.ExitCode.Name()))
}

// writeLayers prints the overview, one row per layer, in the report's order.
//
// A TABLE HERE AND A LIST BELOW, and the split is about what each part is for.
// This one is scanned: eight rows, four short columns, the answer to "which
// layer went wrong" visible without reading. The findings are read, and a table
// of them would put a certificate chain and a remediation command into cells.
//
// NO COLUMN IS MEASURED, unlike the terminal's. Widths are the renderer's
// problem there because the output IS the final artefact; here whatever renders
// this decides, and padding would only make the source harder to read.
func (m Markdown) writeLayers(b *strings.Builder, r report.Report) {
	b.WriteString("\n## Layers\n\n")
	b.WriteString("| Layer | | Status | Reason | Detail |\n")
	b.WriteString("|---|---|---|---|---|\n")

	for _, row := range r.Layers {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n",
			mdText(row.ID.String()),
			mdText(row.ID.Name()),
			mdText(Label(row.Status)),
			mdText(string(row.Reason)),
			mdText(row.Detail))
	}
}

// writeFindings prints one section per layer that has any.
//
// THREE STATES AND ALL THREE ARE VISIBLE, the same three the terminal prints. A
// layer that never looked says so, a layer that looked and found nothing says
// that instead, and the difference between them is the whole of ADR20 - a null
// and an empty list are two different answers.
//
// A LAYER WITH NOTHING TO SHOW GETS NO SECTION, which is the one place this page
// is deliberately shorter than the terminal. The overview above already carries
// its status, its reason and its sentence; a heading followed by one line saying
// nothing was found is noise in a document somebody scrolls.
func (m Markdown) writeFindings(b *strings.Builder, r report.Report) {
	for _, row := range r.Layers {
		if len(row.Findings) == 0 {
			continue
		}
		fmt.Fprintf(b, "\n### %s %s\n\n", mdText(row.ID.String()), mdText(row.ID.Name()))
		for _, finding := range row.Findings {
			m.writeFinding(b, finding)
		}
	}
}

// writeFinding prints one finding and everything hanging off it.
//
// THE ORDER IS THE TERMINAL'S ORDER. Not because the two must match - they need
// not, and the parity test asks about presence rather than sequence - but
// because two people comparing a pasted report against a console should not have
// to work out whether they are looking at the same run.
func (m Markdown) writeFinding(b *strings.Builder, finding report.Finding) {
	line := "- " + mdText(finding.Summary)
	if value := findingValue(finding); value != "" {
		line += "  " + mdCode(value)
	}
	fmt.Fprintf(b, "%s  *(%s)*\n", line, mdText(finding.Source.String()))

	m.writeChain(b, finding)
	m.writeFix(b, finding)
	m.writeAuthority(b, finding)
	m.writeCaveats(b, finding)
	m.writeAsked(b, finding)
}

// writeChain prints the certificates one server presented.
//
// THE FINGERPRINT IS PRINTED WHOLE, for the reason Terminal.writeChain gives:
// shortening it is the quiet truncation the evidence contract forbids, and half
// a fingerprint cannot be compared against anything. This surface has more room
// than a console, not less, so there was never a reason to consider it.
func (m Markdown) writeChain(b *strings.Builder, finding report.Finding) {
	if finding.TLSHandshake == nil || len(finding.TLSHandshake.Chain) == 0 {
		return
	}
	for i, certificate := range finding.TLSHandshake.Chain {
		subject := subjectLine(certificate)
		if certificate.IsCA {
			subject += " (CA)"
		}
		fmt.Fprintf(b, "  - %d. %s\n", i+1, mdText(subject))
		if names := namesLine(certificate); names != "" {
			fmt.Fprintf(b, "    - names: %s\n", mdCode(names))
		}
		fmt.Fprintf(b, "    - issued by: %s\n", mdCode(certificate.Issuer))
		fmt.Fprintf(b, "    - sha256: %s\n", mdCode(certificate.FingerprintSHA256))
		fmt.Fprintf(b, "    - valid: %s to %s\n",
			mdCode(certificate.NotBefore.UTC().Format(time.RFC3339)),
			mdCode(certificate.NotAfter.UTC().Format(time.RFC3339)))
	}
}

// writeFix prints the only line this program ever asks somebody to run.
//
// IT IS A FENCED BLOCK RATHER THAN A CODE SPAN, and that is the one place this
// surface can do something a console cannot: a fenced block is what a reader
// copies with one gesture in every renderer that shows this file. The command
// was quoted for a named platform before it got here - a shell that re-splits it
// would be running something else.
func (m Markdown) writeFix(b *strings.Builder, finding report.Finding) {
	if finding.TrustStore == nil || finding.TrustStore.Fix == nil {
		return
	}
	fix := finding.TrustStore.Fix
	if fix.RequiresElevation {
		fmt.Fprintf(b, "  - needs elevated rights: %s\n", mdText(fix.Elevation))
	}
	fmt.Fprintf(b, "  - run:\n\n%s\n", fencedBlock(fix.Command))
	if len(fix.Placeholders) > 0 {
		fmt.Fprintf(b, "  - replace first: %s\n", mdCode(strings.Join(fix.Placeholders, ", ")))
	}
	if fix.Caveat != "" {
		fmt.Fprintf(b, "  - note: %s\n", mdText(fix.Caveat))
	}
}

// writeAuthority prints who signed the chain and how widely this machine holds
// that signer.
func (m Markdown) writeAuthority(b *strings.Builder, finding report.Finding) {
	if finding.SigningAuthority == nil {
		return
	}
	authority := finding.SigningAuthority
	fmt.Fprintf(b, "  - signed by: %s\n", mdCode(authority.Issuer))
	fmt.Fprintf(b, "  - evidence: leaf fingerprint %s\n", mdCode(authority.LeafFingerprint))
	fmt.Fprintf(b, "  - how widely this machine holds it: %s\n", mdText(string(authority.HeldBy)))
	if len(authority.TrustingStores) > 0 {
		fmt.Fprintf(b, "  - held by: %s\n", mdCode(strings.Join(authority.TrustingStores, ", ")))
	}
	if len(authority.RefusingStores) > 0 {
		fmt.Fprintf(b, "  - not held by: %s\n", mdCode(strings.Join(authority.RefusingStores, ", ")))
	}
	if inspection := authority.Inspection; inspection != nil {
		fmt.Fprintf(b, "  - inspection product: %s, named in the issuer's %s\n",
			mdText(inspection.Product), mdText(inspection.MatchedAttribute))
	}
	// PRINTED LAST AND ALWAYS, the discipline inviolable rule 21 asks for: a
	// heuristic names itself as one wherever it is shown.
	if authority.Caveat != "" {
		fmt.Fprintf(b, "  - note: %s\n", mdText(authority.Caveat))
	}
}

// writeCaveats prints our own sentences about what a row does not settle.
//
// THEY REACH THIS SURFACE FROM THE DAY IT EXISTS, which is the whole lesson of
// the slice that added them to the console: three bodies carried these lists to
// the machine readable document alone, and the reason a verdict came out as it
// did was therefore invisible to the person reading it. A new surface is exactly
// where that happens again if nobody looks.
func (m Markdown) writeCaveats(b *strings.Builder, finding report.Finding) {
	for _, caveat := range caveatsOf(finding) {
		fmt.Fprintf(b, "  - note: %s\n", mdText(caveat))
	}
}

// writeAsked prints the names a PAC file sent to a resolver.
//
// IT IS ON THIS PAGE FOR THE REASON IT IS ON THE OTHER ONE: somebody else's file
// chooses these, no guard in this program can see that channel, and printing
// what was asked is the only honest answer to it. A surface that dropped them
// would be the one place the channel goes unwatched.
func (m Markdown) writeAsked(b *strings.Builder, finding report.Finding) {
	if finding.PACScript == nil || len(finding.PACScript.Asked) == 0 {
		return
	}
	fmt.Fprintf(b, "  - asked a resolver about %d name(s):\n", len(finding.PACScript.Asked))
	for _, name := range finding.PACScript.Asked {
		fmt.Fprintf(b, "    - %s\n", mdCode(name))
	}
}

// writeNotes prints what this run did not do, and never omits the section.
//
// AN EMPTY SECTION IS PRINTED RATHER THAN SKIPPED, unlike an empty layer above,
// and the difference is inviolable rule 1. A layer with no findings has already
// said everything it has to say in the overview table. A report with no notes is
// making a claim - that nothing was skipped - and a claim made by silence cannot
// be told from a section somebody forgot to write.
func (m Markdown) writeNotes(b *strings.Builder, r report.Report) {
	b.WriteString("\n## Notes\n\n")
	if len(r.Notes) == 0 {
		b.WriteString("nothing was skipped and nothing was left undetermined\n")
		return
	}
	for _, note := range r.Notes {
		b.WriteString("- ")
		if note.Layer != "" {
			fmt.Fprintf(b, "%s ", mdText(string(note.Layer)))
		}
		if note.Field != "" {
			fmt.Fprintf(b, "%s ", mdText(note.Field))
		}
		fmt.Fprintf(b, "[%s] %s\n", mdText(string(note.Kind)), mdText(note.Detail))
	}
}

// mdText makes text from the machine being diagnosed safe to put in this
// document, and it is applied to every such piece unconditionally.
//
// IT IS THE MARKDOWN COUSIN OF visible AND IT HAS A SECOND JOB THAT ONE DOES
// NOT. visible stops a terminal ACTING on bytes it was shown; those bytes are
// still dangerous here for the same reason, because this file gets read with cat
// as often as it gets rendered - so visible runs first and its result is escaped
// on top.
//
// WHAT THE SECOND JOB IS. Markdown is turned into HTML by whatever the reader
// pastes it into. A host name containing ](http://elsewhere) becomes a LINK
// pointing somewhere nobody chose, and one containing a raw tag becomes markup.
// Neither is a rendering defect - it is somebody else's text deciding what a
// page does, which is the same shape as the terminal escape this program already
// refuses to pass through.
//
// THE LIST IS THE INLINE SET THAT CAN CHANGE STRUCTURE, not every character with
// a meaning somewhere. Block level markers - a leading hash, a leading dash -
// are not escaped because every line this renderer emits already begins with
// text of its own choosing. The pipe is here because a table row would otherwise
// gain a column from a value.
func mdText(s string) string {
	return mdEscape(visible(s))
}

// THE UNDERSCORE IS DELIBERATELY ABSENT, AND IT WAS PUT BACK ONCE BEFORE BEING
// TAKEN OUT AGAIN. Markdown does not emphasise an underscore inside a word, and
// the values that reach this function are full of them: every environment
// variable this program reports is spelled that way. Escaping it turned
// HTTP_PROXY into HTTP\_PROXY on twenty-three consecutive lines of a real run -
// a page harder to read, in exchange for nothing, since an underscore cannot
// change structure and the worst it can do at a word boundary is italicise.
//
// The asterisk stays, because a wildcard certificate name is a common value here
// and two of them on one line really do emphasise the text between.
var mdEscaper = strings.NewReplacer(
	`\`, `\\`,
	"`", "\\`",
	`*`, `\*`,
	`[`, `\[`,
	`]`, `\]`,
	`<`, `\<`,
	`>`, `\>`,
	`|`, `\|`,
	"\n", " ",
	"\r", " ",
)

func mdEscape(s string) string { return mdEscaper.Replace(s) }

// mdCode puts one atomic value - an address, a path, a fingerprint, a variable's
// contents - into a code span.
//
// A CODE SPAN IS SAFER THAN ESCAPING, NOT PRETTIER. Inside one, markdown means
// nothing except the backtick that ends it, so a value cannot become a link or a
// tag however it is spelled. The fence is grown past the longest run of
// backticks the value holds, which is the specification's own way of putting a
// backtick inside a code span, and a pipe is still escaped because a table row
// is split before its cells are parsed.
func mdCode(s string) string {
	s = visible(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")

	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
			continue
		}
		run = 0
	}
	fence := strings.Repeat("`", longest+1)

	// A value that begins or ends with a backtick needs a space of its own
	// inside the span, which the specification strips again on both sides.
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		pad = " "
	}
	return fence + pad + strings.ReplaceAll(s, "|", `\|`) + pad + fence
}

// fencedBlock puts a value inside a fenced block, where nothing at all is
// interpreted, and returns the whole block including its fences.
//
// THE ONE THING THAT CAN STILL GO WRONG IS THE FENCE ITSELF, so a value carrying
// a run of backticks gets a longer one - the same rule mdCode follows. Without
// it, a command holding three backticks would close its own block and every
// character after it would be read as markup rather than shown.
func fencedBlock(s string) string {
	body := strings.ReplaceAll(strings.ReplaceAll(visible(s), "\r\n", "\n"), "\r", "\n")

	longest, run := 0, 0
	for _, r := range body {
		if r == '`' {
			run++
			longest = max(longest, run)
			continue
		}
		run = 0
	}

	fence := strings.Repeat("`", max(3, longest+1))
	return fence + "\n" + body + "\n" + fence + "\n"
}
