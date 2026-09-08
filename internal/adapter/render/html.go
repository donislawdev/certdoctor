package render

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// HTML renders a report as one page somebody opens, scrolls and forwards.
//
// IT IS A SEPARATE RENDERER RATHER THAN MARKDOWN REPAINTED, and the argument is
// about the reader rather than about the code. Four things a person reaches for
// in this report cannot exist on the other two surfaces: a remediation command
// that can be taken in one gesture, a certificate chain that is present without
// being in the way, a link straight to the layer that went wrong, and ONE FILE
// that survives being attached to a mail. A markdown-to-HTML converter would be
// a new dependency, and a hand-written one would be a parser grown in the exact
// place where escaping decides whether somebody else's host name becomes markup.
//
// IT INVENTS NO NAMES, the discipline the markdown renderer records. Headings,
// labels and status words come from the layer registry, from Label and from
// findingValue - the same function the terminal calls. Inviolable rule 10.
//
// THERE IS STILL NO SHARED DOCUMENT MODEL, AND THIS IS THE SURFACE THAT WAS
// SUPPOSED TO SETTLE THAT. ADR96 left the question open deliberately: two
// renderers walking one report could be a coincidence, three would be a shape.
// Writing this one answered it - the shape is NOT there. The walk over layers
// and findings is genuinely common, but everything hanging off it differs by
// more than formatting: the terminal measures columns because it owns its final
// bytes, markdown prints a flat list because whatever renders it decides the
// rest, and this page nests, collapses and links because those are the things
// it can do and the others cannot. An abstraction over the three would have one
// implementation per surface behind an interface that only ever hid the walk -
// and the walk is the cheap half. The parity test stays the answer.
type HTML struct{}

// Render writes the whole page, or nothing.
//
// It assembles into a buffer and writes once, the reason both other renderers
// give: half a report looks exactly like a whole one to whatever reads it next.
// Here there is a second reason on top - a page cut off mid-element is not a
// short report, it is a broken document that a browser will still try to draw.
func (h HTML) Render(w io.Writer, r report.Report) error {
	var b strings.Builder

	h.writeOpening(&b, r)
	h.writeHeading(&b, r)
	h.writeVerdict(&b, r)
	h.writeLayers(&b, r)
	h.writeFindings(&b, r)
	h.writeNotes(&b, r)
	h.writeClosing(&b)

	_, err := io.WriteString(w, b.String())
	return err
}

// writeOpening emits the document head, including the whole stylesheet.
//
// THE STYLESHEET IS INLINE AND THERE IS NO SCRIPT AT ALL, and both halves of
// that are requirements rather than convenience. The page is meant to be
// attached to a mail or dropped into a ticket, so a run that reached out for a
// font or a stylesheet would be a report that renders differently depending on
// whether the reader's network allows it - and, worse, one that ANNOUNCES being
// opened to a third party. A diagnostic tool whose own inviolable rule 16 says
// the set of destinations is finite cannot ship a document that adds one.
//
// NO SCRIPT IS THE OWNER'S DECISION, TAKEN WITH THE COST NAMED. A real "copy"
// button needs the clipboard API, and the price of it is that this page starts
// carrying executable code into the inbox of a security team - which is exactly
// who reads a report about interception. So the command block is selected in
// one gesture by CSS instead of copied in one gesture by script: the affordance
// is weaker and the file stays inert.
func (h HTML) writeOpening(b *strings.Builder, r report.Report) {
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	fmt.Fprintf(b, "<title>%s %s - %s</title>\n",
		htmlText(r.Tool.Name), htmlText(r.Tool.Version), htmlText(r.Run.Target))
	fmt.Fprintf(b, "<style>\n%s</style>\n", stylesheet)
	b.WriteString("</head>\n<body>\n")
}

// writeClosing closes the page with the same sentence the other surfaces end on.
func (h HTML) writeClosing(b *strings.Builder) {
	fmt.Fprintf(b, "<footer><p>%s</p></footer>\n", htmlText(footer))
	b.WriteString("</body>\n</html>\n")
}

// writeHeading says which build looked at what, when.
//
// THE TIMESTAMP IS THE ONE A PERSON CAN USE, not the one the machine readable
// document carries. Terminal.writeHeading explains the split: nanoseconds exist
// so two runs inside one second can be ordered by a program, and nobody reads
// them. This page is read by a person, so it gets seconds.
func (h HTML) writeHeading(b *strings.Builder, r report.Report) {
	fmt.Fprintf(b, "<header>\n<h1>%s %s</h1>\n", htmlText(r.Tool.Name), htmlText(r.Tool.Version))
	fmt.Fprintf(b, "<p class=\"target\">%s</p>\n", htmlText(r.Run.Target))
	fmt.Fprintf(b, "<p class=\"meta\">%s - %s - privilege: %s - took %s</p>\n",
		htmlText(r.Run.StartedAt.UTC().Format(time.RFC3339)),
		htmlText(r.Run.Platform.OS+"/"+r.Run.Platform.Arch),
		htmlText(string(r.Run.PrivilegeLevel)),
		htmlText(r.Run.Duration.Round(time.Millisecond).String()))
	b.WriteString("</header>\n")
}

// writeVerdict prints the one sentence this whole run exists to produce.
func (h HTML) writeVerdict(b *strings.Builder, r report.Report) {
	fmt.Fprintf(b, "<section class=\"verdict %s\">\n", statusClass(r.Verdict.Status))
	fmt.Fprintf(b, "<p class=\"word\">%s %s</p>\n",
		htmlText(markerOf(r.Verdict.Status)), htmlText(Label(r.Verdict.Status)))
	fmt.Fprintf(b, "<p class=\"sentence\">%s</p>\n", htmlText(r.Verdict.Sentence))
	fmt.Fprintf(b, "<p class=\"exit\">exit %d %s</p>\n",
		r.Verdict.ExitCode.Int(), htmlText(r.Verdict.ExitCode.Name()))
	b.WriteString("</section>\n")
}

// writeLayers prints the overview, one row per layer, in the report's order.
//
// THE IDENTIFIER BECOMES A LINK ONLY WHERE THERE IS SOMEWHERE TO GO. A layer
// with no findings has no section below it, and a link to an anchor that does
// not exist is the quiet kind of wrong: the browser stays where it is and the
// reader concludes the page is broken rather than that the layer found nothing.
// So the cell holds the same text either way and only sometimes wraps it.
//
// NO COLUMN IS MEASURED, unlike the terminal's, and for the reason markdown
// gives: the width belongs to whoever draws this, not to whoever wrote it.
func (h HTML) writeLayers(b *strings.Builder, r report.Report) {
	b.WriteString("<section class=\"layers\">\n<h2>Layers</h2>\n<table>\n")
	b.WriteString("<thead><tr><th>Layer</th><th></th><th>Status</th><th>Reason</th><th>Detail</th></tr></thead>\n<tbody>\n")

	for _, row := range r.Layers {
		identifier := htmlText(row.ID.String())
		if len(row.Findings) > 0 {
			// THE ANCHOR NAME IS BUILT FROM THE LAYER IDENTIFIER AND NOTHING
			// ELSE. It is the one string on this page that reaches an attribute,
			// and it may: it comes from our own closed registry, never from the
			// machine being diagnosed. That rule has a test of its own.
			identifier = fmt.Sprintf("<a href=\"#%s\">%s</a>", anchorFor(row), identifier)
		}
		fmt.Fprintf(b, "<tr class=\"%s\"><td class=\"lid\">%s</td><td>%s</td>"+
			"<td class=\"status\">%s %s</td><td>%s</td><td>%s</td></tr>\n",
			statusClass(row.Status),
			identifier,
			htmlText(row.ID.Name()),
			htmlText(markerOf(row.Status)),
			htmlText(Label(row.Status)),
			htmlText(string(row.Reason)),
			htmlText(row.Detail))
	}

	b.WriteString("</tbody>\n</table>\n</section>\n")
}

// writeFindings prints one section per layer that has any.
//
// A LAYER WITH NOTHING TO SHOW GETS NO SECTION, the same choice markdown makes
// and for the same reason: the overview above already carries its status, its
// reason and its sentence, and a heading followed by one line saying nothing was
// found is noise on a page somebody scrolls. The terminal prints that line
// because its overview and its findings are the same list.
func (h HTML) writeFindings(b *strings.Builder, r report.Report) {
	for _, row := range r.Layers {
		if len(row.Findings) == 0 {
			continue
		}
		fmt.Fprintf(b, "<section class=\"findings\" id=\"%s\">\n", anchorFor(row))
		fmt.Fprintf(b, "<h2>%s - %s</h2>\n", htmlText(row.ID.String()), htmlText(row.ID.Name()))
		for _, finding := range row.Findings {
			h.writeFinding(b, finding)
		}
		b.WriteString("</section>\n")
	}
}

// writeFinding prints one finding and everything hanging off it.
//
// THE ORDER IS THE ORDER THE OTHER TWO SURFACES USE. They need not match - the
// parity test asks about presence rather than sequence - but two people
// comparing a forwarded page against a console should not have to work out
// whether they are looking at the same run.
func (h HTML) writeFinding(b *strings.Builder, finding report.Finding) {
	b.WriteString("<article class=\"finding\">\n<p class=\"summary\">")
	b.WriteString(htmlText(finding.Summary))
	if value := findingValue(finding); value != "" {
		fmt.Fprintf(b, " <code>%s</code>", htmlText(value))
	}
	fmt.Fprintf(b, " <span class=\"source\">%s</span></p>\n", htmlText(finding.Source.String()))

	h.writeChain(b, finding)

	var detail strings.Builder
	h.writeFix(&detail, finding)
	h.writeAuthority(&detail, finding)
	h.writeCaveats(&detail, finding)
	h.writeAsked(&detail, finding)
	if detail.Len() > 0 {
		fmt.Fprintf(b, "<ul class=\"detail\">\n%s</ul>\n", detail.String())
	}

	b.WriteString("</article>\n")
}

// writeChain prints the certificates one server presented.
//
// IT IS THE ONE BLOCK ON THIS PAGE THAT COLLAPSES, and the choice is about what
// a chain IS to the person reading. It is evidence: it has to be present, whole
// and quotable, and it is also four certificates' worth of fields that nobody
// reads until they need exactly one of them. A details element is the only
// affordance here that needs neither script nor a second page.
//
// IT IS OPEN WHEN THERE IS ONE CERTIFICATE AND CLOSED WHEN THERE ARE MORE. One
// certificate is a fact, and hiding a fact behind a click is hiding it; four are
// a table of contents for a search that has not started yet.
//
// THE FINGERPRINT IS PRINTED WHOLE, for the reason both other surfaces give:
// shortening it is the quiet truncation the evidence contract forbids, and half
// a fingerprint cannot be compared against anything.
func (h HTML) writeChain(b *strings.Builder, finding report.Finding) {
	if finding.TLSHandshake == nil || len(finding.TLSHandshake.Chain) == 0 {
		return
	}
	chain := finding.TLSHandshake.Chain

	open := ""
	if len(chain) == 1 {
		open = " open"
	}
	fmt.Fprintf(b, "<details class=\"chain\"%s>\n", open)
	fmt.Fprintf(b, "<summary>certificate chain (%d)</summary>\n<ol>\n", len(chain))

	for _, certificate := range chain {
		subject := subjectLine(certificate)
		if certificate.IsCA {
			subject += " (CA)"
		}
		fmt.Fprintf(b, "<li>\n<p class=\"subject\">%s</p>\n<dl>\n", htmlText(subject))
		if names := namesLine(certificate); names != "" {
			writeField(b, "names", names)
		}
		writeField(b, "issued by", certificate.Issuer)
		writeField(b, "sha256", certificate.FingerprintSHA256)
		writeField(b, "valid",
			certificate.NotBefore.UTC().Format(time.RFC3339)+" to "+
				certificate.NotAfter.UTC().Format(time.RFC3339))
		b.WriteString("</dl>\n</li>\n")
	}

	b.WriteString("</ol>\n</details>\n")
}

// writeFix prints the only line this program ever asks somebody to run.
//
// THE BLOCK SELECTS ITSELF IN ONE CLICK AND IS NOT A BUTTON. CSS user-select
// takes the whole command on a single click, which is the nearest inert
// equivalent of copying it - see writeOpening for why the scripted version was
// refused. The command was quoted for a named platform before it got here, so
// nothing on this page may re-split or re-wrap it: it goes into a pre element,
// where the browser preserves it exactly.
func (h HTML) writeFix(b *strings.Builder, finding report.Finding) {
	if finding.TrustStore == nil || finding.TrustStore.Fix == nil {
		return
	}
	fix := finding.TrustStore.Fix
	if fix.RequiresElevation {
		fmt.Fprintf(b, "<li class=\"elevation\">needs elevated rights: %s</li>\n", htmlText(fix.Elevation))
	}
	fmt.Fprintf(b, "<li>run:<pre class=\"cmd\">%s</pre></li>\n", htmlText(fix.Command))
	if len(fix.Placeholders) > 0 {
		fmt.Fprintf(b, "<li>replace first: <code>%s</code></li>\n",
			htmlText(strings.Join(fix.Placeholders, ", ")))
	}
	if fix.Caveat != "" {
		fmt.Fprintf(b, "<li>note: %s</li>\n", htmlText(fix.Caveat))
	}
}

// writeAuthority prints who signed the chain and how widely this machine holds
// that signer.
func (h HTML) writeAuthority(b *strings.Builder, finding report.Finding) {
	if finding.SigningAuthority == nil {
		return
	}
	authority := finding.SigningAuthority
	fmt.Fprintf(b, "<li>signed by: <code>%s</code></li>\n", htmlText(authority.Issuer))
	fmt.Fprintf(b, "<li>evidence: leaf fingerprint <code>%s</code></li>\n", htmlText(authority.LeafFingerprint))
	fmt.Fprintf(b, "<li>how widely this machine holds it: %s</li>\n", htmlText(string(authority.HeldBy)))
	if len(authority.TrustingStores) > 0 {
		fmt.Fprintf(b, "<li>held by: <code>%s</code></li>\n",
			htmlText(strings.Join(authority.TrustingStores, ", ")))
	}
	if len(authority.RefusingStores) > 0 {
		fmt.Fprintf(b, "<li>not held by: <code>%s</code></li>\n",
			htmlText(strings.Join(authority.RefusingStores, ", ")))
	}
	if inspection := authority.Inspection; inspection != nil {
		fmt.Fprintf(b, "<li>inspection product: %s, named in the issuer's %s</li>\n",
			htmlText(inspection.Product), htmlText(inspection.MatchedAttribute))
	}
	// PRINTED LAST AND ALWAYS, the discipline inviolable rule 21 asks for: a
	// heuristic names itself as one wherever it is shown. A page is the surface
	// where that matters most, because a coloured block reads as a stronger
	// claim than the same sentence in a line of console text.
	if authority.Caveat != "" {
		fmt.Fprintf(b, "<li class=\"caveat\">note: %s</li>\n", htmlText(authority.Caveat))
	}
}

// writeCaveats prints our own sentences about what a row does not settle.
//
// THEY REACH THIS SURFACE FROM THE DAY IT EXISTS, which is the lesson OBS133 and
// OBS135 left behind: for one slice these lists reached the machine readable
// document alone, and two different states of a PAC evaluation were therefore
// indistinguishable to a person. A new surface is exactly where that happens
// again if nobody looks.
func (h HTML) writeCaveats(b *strings.Builder, finding report.Finding) {
	for _, caveat := range caveatsOf(finding) {
		fmt.Fprintf(b, "<li class=\"caveat\">note: %s</li>\n", htmlText(caveat))
	}
}

// writeAsked prints the names a PAC file sent to a resolver.
//
// IT IS ON THIS PAGE FOR THE REASON IT IS ON THE OTHER TWO: somebody else's file
// chooses these, the allowed set is a list of PLACES and the resolver is on it,
// so no guard in this program can see that channel. Printing what was asked is
// the whole of the honest answer, and a surface that dropped it would be the one
// place the channel goes unwatched.
func (h HTML) writeAsked(b *strings.Builder, finding report.Finding) {
	if finding.PACScript == nil || len(finding.PACScript.Asked) == 0 {
		return
	}
	fmt.Fprintf(b, "<li>asked a resolver about %d name(s):\n<ul class=\"asked\">\n",
		len(finding.PACScript.Asked))
	for _, name := range finding.PACScript.Asked {
		fmt.Fprintf(b, "<li><code>%s</code></li>\n", htmlText(name))
	}
	b.WriteString("</ul>\n</li>\n")
}

// writeNotes prints what this run did not do, and never omits the section.
//
// AN EMPTY SECTION IS PRINTED RATHER THAN SKIPPED, unlike an empty layer above,
// and the difference is inviolable rule 1. A layer with no findings has already
// said everything it has to say in the overview. A report with no notes is
// making a claim - that nothing was skipped - and a claim made by silence cannot
// be told from a section somebody forgot to write.
func (h HTML) writeNotes(b *strings.Builder, r report.Report) {
	b.WriteString("<section class=\"notes\">\n<h2>Notes</h2>\n")
	if len(r.Notes) == 0 {
		b.WriteString("<p>nothing was skipped and nothing was left undetermined</p>\n</section>\n")
		return
	}
	b.WriteString("<ul>\n")
	for _, note := range r.Notes {
		b.WriteString("<li>")
		if note.Layer != "" {
			fmt.Fprintf(b, "%s ", htmlText(string(note.Layer)))
		}
		if note.Field != "" {
			fmt.Fprintf(b, "%s ", htmlText(note.Field))
		}
		fmt.Fprintf(b, "[%s] %s</li>\n", htmlText(string(note.Kind)), htmlText(note.Detail))
	}
	b.WriteString("</ul>\n</section>\n")
}

// writeField prints one labelled value inside a certificate.
func writeField(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "<dt>%s</dt><dd><code>%s</code></dd>\n", htmlText(label), htmlText(value))
}

// anchorFor is the name of the place a layer's findings live.
//
// IT IS PREFIXED RATHER THAN BEING THE BARE IDENTIFIER, because an element
// identifier becomes a fragment in the address bar and a bare "L3" is a name
// somebody else's page may also use once this one is embedded or concatenated.
// The prefix costs nothing and the collision is silent.
func anchorFor(row report.LayerResult) string { return "layer-" + row.ID.String() }

// statusClass maps a status onto the class this page paints from.
//
// IT READS THE COLOUR NAME OUT OF THE APPEARANCE DICTIONARY RATHER THAN CHOOSING
// ONE, which is what that dictionary says it exists for: "Color is a concept,
// not a value ... so that the report formats can map the same name onto
// something that is not an escape sequence at all". This is that surface, and
// inviolable rule 20 is met by reuse rather than by a second table.
//
// A STATUS OUTSIDE THE VOCABULARY YIELDS A CLASS NOTHING PAINTS, which is the
// same degradation Paint performs: the text arrives unpainted and the marker and
// the word carry the verdict on their own. Colour never carries meaning alone
// here either, so nothing is lost but the tint.
func statusClass(s status.Status) string { return "st-" + string(Of(s).Color) }

// markerOf is the glyph beside a status word.
//
// IT IS ALWAYS THE UNICODE ONE, and that is the one appearance question this
// surface may answer differently from the terminal. The ASCII substitute exists
// because a console may be on a code page that renders the glyph as garbage;
// this document declares its own encoding in its own head, so the case cannot
// arise. Terminal has to ask its environment, and this page has no environment
// to ask - the same reason markdown takes no options.
func markerOf(s status.Status) string { return Of(s).Marker(GlyphUnicode) }

// htmlText makes text from the machine being diagnosed safe to put in this
// document, and it is applied to every such piece unconditionally.
//
// IT IS THE HTML COUSIN OF mdText AND THE SECOND HALF MATTERS MORE HERE. visible
// runs first, for the reason it runs everywhere: this file is read with cat and
// grep as often as it is opened, so control bytes are as dangerous here as on a
// console. The escaping on top is what stops somebody else's host name from
// BECOMING the page - a value carrying a tag would otherwise be markup rather
// than text, and on this surface markup is behaviour.
//
// IT ESCAPES THE QUOTES TOO, EVEN THOUGH NO DIAGNOSED VALUE EVER REACHES AN
// ATTRIBUTE. Those two facts are a belt and a pair of braces on purpose: the
// rule that keeps values out of attributes is a rule about where calls are
// written, and a rule like that is one careless line from being broken. Escaping
// the quote as well means the break would be ugly rather than exploitable.
// html.EscapeString covers &, <, >, the double quote and the single quote.
func htmlText(s string) string { return html.EscapeString(visible(s)) }

// stylesheet is the whole appearance of the page.
//
// IT IS DELIBERATELY SMALL AND HAS NO IMAGES, NO FONTS AND NO SCRIPT. Everything
// it needs is a system font stack, four status colours and enough spacing to
// read - a page that fetched anything would be a report announcing itself to a
// third party the moment it was opened (see writeOpening).
//
// IT ANSWERS BOTH COLOUR SCHEMES, because the reader's is not knowable from here
// and a report that is unreadable on half the machines that open it is a report
// that gets pasted somewhere else instead. The four colours are darkened for the
// light scheme and lightened for the dark one rather than shared, which is the
// only way to keep either of them legible.
//
// COLOUR IS NEVER THE ONLY CARRIER - inviolable rule 20 and WCAG 1.4.1. Every
// place a colour appears, the status glyph and the status word are beside it, so
// a reader who cannot separate the hues loses nothing but the tint. That is a
// property of what the renderer WRITES, not of this stylesheet, and it is the
// reason none of these rules hides text or replaces it with a shape.
//
// LONG VALUES WRAP RATHER THAN OVERFLOW. A fingerprint, a Windows store path and
// a remediation command are all longer than a phone screen, and a page whose
// evidence runs off the side is a page where the evidence is missing.
const stylesheet = `:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0 auto; padding: 1.5rem 1rem 3rem; max-width: 64rem; line-height: 1.5;
  font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  background: #fff; color: #1a1a1a; }
h1 { font-size: 1.5rem; margin: 0; }
h2 { font-size: 1.15rem; margin: 2rem 0 .5rem; }
header .target { font-size: 1.05rem; margin: .25rem 0; word-break: break-all; }
header .meta, .source { color: #5a5f66; font-size: .875rem; }
.verdict { margin-top: 1.5rem; padding: .75rem 1rem; border: 1px solid #d0d4da;
  border-left-width: .4rem; border-radius: .25rem; background: #f7f8fa; }
.verdict p { margin: .25rem 0; }
.verdict .word { font-weight: 700; letter-spacing: .04em; }
.verdict .sentence { font-size: 1.05rem; }
.verdict .exit { color: #5a5f66; font-size: .875rem; }
table { border-collapse: collapse; width: 100%; font-size: .9375rem; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #e3e6ea;
  vertical-align: top; }
th { font-weight: 600; color: #5a5f66; }
td.lid { font-variant-numeric: tabular-nums; white-space: nowrap; }
td.status { white-space: nowrap; font-weight: 600; }
.finding { border-top: 1px solid #e3e6ea; padding: .6rem 0; }
.finding:first-of-type { border-top: 0; }
.summary { margin: 0 0 .35rem; }
.detail { margin: .25rem 0 0; padding-left: 1.25rem; }
.detail li { margin: .15rem 0; }
.caveat { color: #5a5f66; }
.elevation { font-weight: 600; }
code { font-family: ui-monospace, SFMono-Regular, Consolas, Menlo, monospace;
  font-size: .875em; word-break: break-all; }
.chain { margin: .35rem 0; }
.chain summary { cursor: pointer; color: #5a5f66; font-size: .9375rem; }
.chain ol { margin: .5rem 0; padding-left: 1.5rem; }
.chain .subject { margin: .5rem 0 .25rem; font-weight: 600; }
.chain dl { display: grid; grid-template-columns: max-content 1fr; gap: .1rem .75rem;
  margin: 0 0 .5rem; }
.chain dt { color: #5a5f66; font-size: .875rem; }
.chain dd { margin: 0; }
/* ONE CLICK TAKES THE WHOLE COMMAND. This is the inert stand-in for a copy
   button: no script, and nothing on the page can re-split a line that was
   already quoted for a named platform. */
pre.cmd { user-select: all; -webkit-user-select: all; margin: .35rem 0;
  padding: .6rem .75rem; border: 1px solid #d0d4da; border-radius: .25rem;
  background: #f4f5f7; white-space: pre-wrap; word-break: break-all;
  font-family: ui-monospace, SFMono-Regular, Consolas, Menlo, monospace;
  font-size: .875rem; }
a { color: #0b5cad; }
footer { margin-top: 2.5rem; padding-top: .75rem; border-top: 1px solid #e3e6ea;
  color: #5a5f66; font-size: .875rem; }
.st-red    { color: #a4001a; }
.st-yellow { color: #7a5500; }
.st-blue   { color: #0b5cad; }
.st-green  { color: #08602d; }
tr.st-red td.status    { color: #a4001a; }
tr.st-yellow td.status { color: #7a5500; }
tr.st-blue td.status   { color: #0b5cad; }
tr.st-green td.status  { color: #08602d; }
.verdict.st-red    { border-left-color: #a4001a; }
.verdict.st-yellow { border-left-color: #7a5500; }
.verdict.st-blue   { border-left-color: #0b5cad; }
.verdict.st-green  { border-left-color: #08602d; }
@media (prefers-color-scheme: dark) {
  body { background: #16181c; color: #e6e8ea; }
  header .meta, .source, th, .caveat, .chain summary, .chain dt, footer { color: #a0a6ad; }
  .verdict { background: #1e2126; border-color: #343941; }
  .verdict .exit { color: #a0a6ad; }
  th, td { border-bottom-color: #262a30; }
  .finding { border-top-color: #262a30; }
  footer { border-top-color: #262a30; }
  pre.cmd { background: #1e2126; border-color: #343941; }
  a { color: #7cb7ff; }
  .st-red    { color: #ff8d8d; }
  .st-yellow { color: #e3b341; }
  .st-blue   { color: #7cb7ff; }
  .st-green  { color: #56d364; }
  tr.st-red td.status    { color: #ff8d8d; }
  tr.st-yellow td.status { color: #e3b341; }
  tr.st-blue td.status   { color: #7cb7ff; }
  tr.st-green td.status  { color: #56d364; }
  .verdict.st-red    { border-left-color: #ff8d8d; }
  .verdict.st-yellow { border-left-color: #e3b341; }
  .verdict.st-blue   { border-left-color: #7cb7ff; }
  .verdict.st-green  { border-left-color: #56d364; }
}
`
