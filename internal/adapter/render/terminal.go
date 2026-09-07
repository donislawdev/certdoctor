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
	fmt.Fprintf(b, "%s %s   %s\n", visible(r.Tool.Name), visible(r.Tool.Version), visible(r.Run.Target))
	fmt.Fprintf(b, "%s   %s   privilege: %s   took %s\n",
		r.Run.StartedAt.UTC().Format(time.RFC3339),
		visible(r.Run.Platform.OS+"/"+r.Run.Platform.Arch),
		visible(string(r.Run.PrivilegeLevel)),
		r.Run.Duration.Round(time.Millisecond))
}

func (t Terminal) writeVerdict(b *strings.Builder, r report.Report) {
	fmt.Fprintf(b, "\n%s %s\n", t.badge(r.Verdict.Status), Paint(r.Verdict.Status, t.Color, visible(r.Verdict.Sentence)))
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
			fmt.Fprintf(&line, "  %s", visible(string(row.Reason)))
		}
		if row.Detail != "" {
			fmt.Fprintf(&line, "  %s", visible(row.Detail))
		}
		writeTrimmed(b, line.String())
		t.writeFindings(b, row)
	}
}

// visible turns every byte a terminal would ACT ON into something it merely
// shows. It is applied to every piece of text that came from the machine being
// diagnosed, unconditionally.
//
// WHY UNCONDITIONALLY, AND WHY --no-color DOES NOT COVER THIS. That switch turns
// off the escape sequences THIS PROGRAM ADDS. It does nothing about sequences the
// program merely PASSES THROUGH out of somebody's environment - measured on
// 2026-08-06: HTTPS_PROXY carrying an escape sequence rendered the report in
// colour, with --no-color asked for. The appearance guard is blind to it by
// construction: it reads OUR source for literal sequences, and these bytes are
// not in our source, they are in the data.
//
// WHAT IT WOULD COST IF LEFT. Not decoration. A value can repaint a row, hide
// text, or move the cursor - so a FAIL row can be made to read as a pass. That
// exact failure is on record in the rule set this project follows: a field from
// somebody else's file rendered a refusal as a green approval.
//
// IT ESCAPES RATHER THAN DELETES, and that is the whole design. Dropping the
// bytes would quietly show a value that is not the value on the machine - the
// silence this tool exists to prevent, committed by the tool itself. A reader
// sees \x1b and knows something odd is in their environment, which is a finding.
//
// WHAT IT COVERS: C0 controls, DEL, the C1 range, the bidirectional overrides
// that reorder a line visually, and bytes that are not valid UTF-8 at all.
//
// WHAT IT DOES NOT COVER, written here rather than discovered later: characters
// that are legitimate text and merely look like other text - a Cyrillic letter
// shaped like a Latin one. Those cannot be escaped without mangling every
// ordinary non-English value, and no amount of escaping makes two identical
// shapes distinguishable on a terminal.
func visible(s string) string {
	if !hasUnsafe(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Not valid UTF-8. The byte is shown as itself rather than replaced
			// with a substitution character, so the report says what is really
			// there instead of what a decoder made of it.
			b.WriteString(notText(s[i]))
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// notText is HOW THIS PROGRAM SPELLS A BYTE THAT IS NOT TEXT, and it lives once
// because two surfaces have to say the same thing about the same byte.
//
// Both renderers meet this case and until 2026-09-04 they answered it
// differently: the terminal wrote the byte as itself, and encoding/json quietly
// swapped it for U+FFFD - so one run produced two documents disagreeing about a
// value, and --json was the one that invented. A second spelling of this would
// bring that back by a slower route.
func notText(b byte) string { return fmt.Sprintf(`\x%02x`, b) }

// decodable rewrites the bytes of s that are not valid UTF-8, and leaves
// everything else exactly as it is.
//
// IT IS DELIBERATELY NARROWER THAN visible, AND THE DIFFERENCE IS THE WHOLE
// POINT. A terminal INTERPRETS an escape sequence or a bidirectional override,
// so those have to be defanged before they reach one. A JSON consumer does not:
// it decodes an escaped override back into the character and gets the value
// that was really there, which is what a machine readable document is for. The one thing JSON
// cannot carry is a byte that is not text at all, and there encoding/json
// substitutes without saying so - the single case where the document stops being
// a record of the machine and becomes a record of a decoder.
func decodable(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString(notText(s[i]))
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// hasUnsafe is the fast path. Almost every value in almost every report is
// ordinary text, and rebuilding those rune by rune would cost the common case to
// pay for the rare one.
func hasUnsafe(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unsafeRune(r) {
			return true
		}
	}
	return false
}

// unsafeRune reports whether a terminal would treat r as an instruction rather
// than as a character.
//
// The bidirectional set is the least obvious entry and it is here on a measured
// case: an invisible override reorders the rest of the line, so a value can be
// made to read as a different value - including in the editor of whoever opens
// the report to look into it.
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
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

	// Widths are measured on the ESCAPED text, not on the raw. A value carrying
	// control bytes gets longer when they become visible, and measuring before
	// escaping would set every column too narrow for the row that needed it most.
	summaryWidth, sourceWidth := 0, 0
	for _, finding := range row.Findings {
		summaryWidth = max(summaryWidth, widthOf(visible(finding.Summary)))
		sourceWidth = max(sourceWidth, widthOf(visible(finding.Source.String())))
	}

	for _, finding := range row.Findings {
		var line strings.Builder
		fmt.Fprintf(&line, "      %s  %s",
			pad(visible(finding.Summary), summaryWidth),
			pad(visible(finding.Source.String()), sourceWidth))
		if value := visible(findingValue(finding)); value != "" {
			fmt.Fprintf(&line, "  %s", value)
		}
		writeTrimmed(b, line.String())
		writeChain(b, finding)
		writeFix(b, finding)
		writeAuthority(b, finding)
		writeCaveats(b, finding)
		writeAsked(b, finding)
	}
}

// writeCaveats prints what a row does not settle, under the row.
//
// IT EXISTS BECAUSE THREE BODIES CARRIED THESE AND THIS PAGE SHOWED NONE OF
// THEM. proxy_stack, pac_script and proxy_challenge each assemble a list of our
// own sentences about the limits of what they measured, every one of them
// reached the machine readable document, and a person at a terminal saw none.
// Found by running the binary: a PAC row printed an answer, the layer refused to
// rest a verdict on it because the file had spent its resolver allowance, and
// the only place saying so was the JSON. That is OBS129's shape - a field no
// surface renders is a field that does not exist - and it is worse here than
// where OBS129 found it, because these sentences are the REASON a verdict came
// out the way it did.
//
// THE PREFIX IS THE ONE ALREADY IN USE. writeAuthority and writeFix have printed
// their single caveat as "note:" since they existed, so a reader who has seen
// one of those recognises this without learning a second convention.
//
// EVERY CAVEAT IS OURS, NOT THE MACHINE'S - the three bodies say so where they
// declare the field - so nothing here is somebody else's text. It still goes
// through visible, because the rule on this page is that borrowed strings are
// escaped and deciding case by case is how one gets missed.
func writeCaveats(b *strings.Builder, finding report.Finding) {
	var caveats []string
	switch {
	case finding.PACScript != nil:
		caveats = finding.PACScript.Caveats
	case finding.ProxyStack != nil:
		caveats = finding.ProxyStack.Caveats
	case finding.ProxyChallenge != nil:
		caveats = finding.ProxyChallenge.Caveats
	}
	for _, caveat := range caveats {
		writeTrimmed(b, fmt.Sprintf("        note: %s", visible(caveat)))
	}
}

// writeAsked prints the names a PAC file sent to a resolver, underneath the row
// for that script.
//
// IT IS ON THIS PAGE AND NOT ONLY IN THE MACHINE READABLE DOCUMENT, which is the
// opposite of the decision proxyStackValue records about an exception list three
// hundred lines down - and the difference is what the two fields are FOR. An
// exception list is configuration the reader can go and look at; these names are
// evidence of something they cannot see any other way. The allowed set is a list
// of PLACES and a resolver is on it, so every query somebody else's file provokes
// is permitted by construction and no guard in this program reports it. If this
// page does not say what was asked, the person running certdoctor on their own
// machine never learns their PAC file sent names out of it.
//
// IT IS BOUNDED BY CONSTRUCTION RATHER THAN BY A LIMIT HERE. The sandbox allows
// one evaluation a fixed number of DISTINCT names, so this block cannot become
// the wall of host names that argument was about.
//
// NOTHING IS PRINTED WHEN NOTHING WAS ASKED, and that includes a script that ran
// and asked about nothing. The distinction between that and a script that never
// ran is real and is kept - it is in the document a program reads, where null and
// an empty array can say it. On a page for a person, a heading over no names
// would be a line asking to be interpreted.
//
// EVERY NAME GOES THROUGH visible: it comes out of somebody else's file, which
// makes it the last string that should reach a terminal unescaped.
func writeAsked(b *strings.Builder, finding report.Finding) {
	if finding.PACScript == nil || len(finding.PACScript.Asked) == 0 {
		return
	}
	writeTrimmed(b, fmt.Sprintf("        asked a resolver about %d name(s):", len(finding.PACScript.Asked)))
	for _, name := range finding.PACScript.Asked {
		writeTrimmed(b, fmt.Sprintf("          %s", visible(name)))
	}
}

// writeAuthority prints who signed the chain, which stores hold that signer and
// what the answer does not settle, underneath the row that carries it.
//
// IT IS THE THIRD PLACE THIS RENDERER GOES TWO LEVELS DEEP, and it earns it the
// same way the chain and the command do: this is the product rather than a
// detail of it. The row above states the measurement in one line, and the reason
// the rest is not up there with it is arithmetic - every summary in a layer is
// padded to the longest, so a paragraph in this one would push the source column
// of every trust row on the machine off the side of the window.
//
// THE CAVEAT IS PRINTED LAST AND ALWAYS. Inviolable rule 21 asks for the
// heuristic to be named as a heuristic, and a hedge shown only when the answer
// is uncomfortable teaches a reader that prose here means bad news - which is
// the accusation reintroduced by layout.
//
// EVERYTHING BORROWED GOES THROUGH visible. An issuer is text out of somebody
// else's certificate and an instance is a path off this machine, and either can
// carry an escape sequence into the terminal of the person deciding whether they
// are being watched.
func writeAuthority(b *strings.Builder, finding report.Finding) {
	if finding.SigningAuthority == nil {
		return
	}
	authority := finding.SigningAuthority
	writeTrimmed(b, fmt.Sprintf("        evidence: leaf fingerprint %s", visible(authority.LeafFingerprint)))
	if len(authority.TrustingStores) > 0 {
		writeTrimmed(b, fmt.Sprintf("        held by: %s", visible(strings.Join(authority.TrustingStores, ", "))))
	}
	if len(authority.RefusingStores) > 0 {
		writeTrimmed(b, fmt.Sprintf("        not held by: %s", visible(strings.Join(authority.RefusingStores, ", "))))
	}
	// WHERE THE NAME CAME FROM, ON THE SURFACE WHERE SOMEBODY DECIDES WHETHER TO
	// BE ALARMED. The summary already says the product; this line says which part
	// of the issuer carried it, which is what a reader would go and check. The
	// product name is ours and needs no escaping, and the attribute is one of two
	// literals this program chose - but both go through visible anyway, because
	// the day one of them stops being ours is not a day anybody will remember
	// this line.
	if authority.Inspection != nil {
		writeTrimmed(b, fmt.Sprintf("        inspection product: %s, named in the issuer's %s",
			visible(authority.Inspection.Product), visible(authority.Inspection.MatchedAttribute)))
	}
	writeTrimmed(b, fmt.Sprintf("        note: %s", visible(authority.Caveat)))
}

// writeFix prints the command that would repair one row, underneath it.
//
// IT IS THE SECOND PLACE THIS RENDERER GOES TWO LEVELS DEEP, and for the same
// reason as the chain: this is the product rather than a detail of it. A command
// squeezed into the value column would be wrapped by the terminal at whatever
// width the window happens to be, and a wrapped command is one somebody pastes
// in two pieces.
//
// THE ELEVATION LINE COMES BEFORE THE COMMAND, and that order is the whole of
// docs/20 rule 5. A warning underneath is a warning read after the command has
// been copied.
//
// EVERYTHING GOES THROUGH visible BECAUSE THE PATH IN IT IS SOMEBODY ELSE'S.
// A store path is read off this machine, and a directory named with an escape
// sequence in it would otherwise rewrite the line a person is about to run.
func writeFix(b *strings.Builder, finding report.Finding) {
	if finding.TrustStore == nil || finding.TrustStore.Fix == nil {
		return
	}
	fix := finding.TrustStore.Fix
	if fix.RequiresElevation {
		writeTrimmed(b, fmt.Sprintf("        needs elevated rights: %s", visible(fix.Elevation)))
	}
	writeTrimmed(b, fmt.Sprintf("        run: %s", visible(fix.Command)))
	if len(fix.Placeholders) > 0 {
		// NAMED RATHER THAN COUNTED. "Two things to replace" makes somebody hunt;
		// the words themselves can be searched for in the line above.
		writeTrimmed(b, fmt.Sprintf("        replace first: %s", visible(strings.Join(fix.Placeholders, ", "))))
	}
	if fix.Caveat != "" {
		writeTrimmed(b, fmt.Sprintf("        note: %s", visible(fix.Caveat)))
	}
}

// writeChain prints the certificates one server presented, underneath the row
// that carries them.
//
// IT IS THE ONE PLACE THIS RENDERER GOES TWO LEVELS DEEP, and the reason is that
// a chain is the product rather than a detail of it. Everything else a finding
// carries fits in the value column beside its summary; four certificates with
// their issuers and their fingerprints do not, and squeezing them in would mean
// dropping the fingerprints - which is the evidence somebody came here for.
//
// ONE BLOCK PER RUN, NOT ONE PER ADDRESS - ADR45. The rows for the other
// addresses say in their summary whether they presented the same certificate,
// and that sentence is all they need: the chains were measured to be identical
// on a healthy network, and a difference is visible from the fingerprint alone.
//
// THE FINGERPRINT IS PRINTED WHOLE. Shortening it would be the quiet kind of
// truncation docs/19 section 4 forbids, and a half fingerprint cannot be
// compared against anything.
//
// EVERY VALUE GOES THROUGH visible BECAUSE ALL OF IT IS SOMEBODY ELSE'S. A
// subject arrives from the network and is exactly where an escape sequence would
// be planted to make one distinguished name read as another.
func writeChain(b *strings.Builder, finding report.Finding) {
	if finding.TLSHandshake == nil || len(finding.TLSHandshake.Chain) == 0 {
		return
	}
	chain := finding.TLSHandshake.Chain
	indexWidth := widthOf(fmt.Sprintf("%d", len(chain)))
	blank := pad("", indexWidth)

	for i, certificate := range chain {
		subject := subjectLine(certificate)
		if certificate.IsCA {
			// The basic constraint as presented, said in the row rather than in a
			// column of its own: a chain is normally one leaf and some
			// authorities, so the exception is what is worth marking.
			subject += "  (CA)"
		}
		writeTrimmed(b, fmt.Sprintf("        %s  %s", pad(fmt.Sprintf("%d", i+1), indexWidth), subject))
		if names := namesLine(certificate); names != "" {
			writeTrimmed(b, fmt.Sprintf("        %s  names      %s", blank, names))
		}
		writeTrimmed(b, fmt.Sprintf("        %s  issued by  %s", blank, visible(certificate.Issuer)))
		writeTrimmed(b, fmt.Sprintf("        %s  sha256     %s", blank, visible(certificate.FingerprintSHA256)))
		// Reported, never judged - the dates are shown and nothing here decides
		// what they mean, because that depends on a clock this program does not
		// own.
		writeTrimmed(b, fmt.Sprintf("        %s  valid      %s to %s", blank,
			certificate.NotBefore.UTC().Format(time.RFC3339),
			certificate.NotAfter.UTC().Format(time.RFC3339)))
	}
}

// subjectLine is what to print where the subject goes, INCLUDING when there is
// no subject.
//
// AN EMPTY SUBJECT IS LEGAL AND A BLANK LINE WOULD READ AS A DEFECT IN THIS TOOL
// - ADR47. RFC 5280 requires an empty subject when the identity lives only in a
// critical subjectAltName, so the page has to say which of the two situations it
// is looking at rather than leaving a gap the reader has to interpret.
func subjectLine(certificate report.Certificate) string {
	switch {
	case certificate.Subject != "":
		return visible(certificate.Subject)
	case len(certificate.DNSNames) > 0:
		return "(no subject - identified by the names below, which RFC 5280 requires)"
	}
	return "(no subject and no names - this certificate does not say what it is for)"
}

// namesLine is what the certificate says it is FOR, or the empty string when
// there is nothing worth a line.
//
// THIS IS THE FIELD A MODERN CLIENT MATCHES ON - RFC 6125 section 6.4.4 forbids
// matching on the common name when these are present - so a page showing only
// the subject was showing the deprecated half of the answer.
//
// AN AUTHORITY WITH NO NAMES GETS NO LINE, and a leaf with none gets one saying
// so. A certification authority is not issued for a host name, so silence there
// is the ordinary state; on a leaf it is the whole reason a client might refuse
// the server, and a missing line would hide it.
func namesLine(certificate report.Certificate) string {
	if len(certificate.DNSNames) == 0 {
		if certificate.IsCA {
			return ""
		}
		return "none presented"
	}
	shown := make([]string, 0, len(certificate.DNSNames))
	for _, name := range certificate.DNSNames {
		shown = append(shown, visible(name))
	}
	return strings.Join(shown, ", ")
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
	case finding.TCPConnect != nil:
		return connectValue(*finding.TCPConnect)
	case finding.TLSHandshake != nil:
		return handshakeValue(*finding.TLSHandshake)
	case finding.ProxyStack != nil:
		return proxyStackValue(*finding.ProxyStack)
	case finding.PACScript != nil:
		return pacScriptValue(*finding.PACScript)
	case finding.ProxyChallenge != nil:
		return proxyChallengeValue(*finding.ProxyChallenge)
	}
	return ""
}

// proxyChallengeValue is what a person needs from a challenge row beyond its
// summary: which proxy answered, and how it offered to be told who is asking.
//
// THE ENDPOINT IS HERE AND NOT IN THE SUMMARY, the masking rule the core states
// at summaryOfChallenge: a summary is masked by a rule that cannot recognise a
// bare "host:port" as a machine, and this body is masked by one that can.
//
// THE REALM IS NOT PRINTED. It is in the machine readable document, where it is
// withheld under --redact; on this page it would be a line of somebody else's
// prose, free to be a company name and free to be in a language this page is
// not. The scheme is the part that says what to do next, and it is a registered
// token rather than free text.
//
// THE STATUS CODE IS NOT PRINTED EITHER WHEN IT IS THE ONE THAT MATTERS. A 407
// already has a sentence of its own in the summary, and repeating the number
// beside it would say one thing twice; every other code has no sentence, so
// there the number IS the answer and the summary carries it.
func proxyChallengeValue(challenge report.ProxyChallenge) string {
	if !challenge.Asked {
		return challenge.Endpoint
	}
	parts := []string{challenge.Endpoint}
	for _, scheme := range challenge.Schemes {
		parts = append(parts, scheme.Scheme)
	}
	return strings.Join(parts, ", ")
}

// pacScriptValue is what a person needs from a script row beyond its summary:
// where the script sends THIS URL.
//
// THE ENDPOINT IS HERE AND NOT IN THE SUMMARY, for the reason proxyStackValue
// gives one function down: a summary is masked by a rule that cannot recognise
// a bare "host:port" as a machine, and this body is masked by one that can, so
// printing it from here prints the MASKED value.
//
// THE VERBATIM ANSWER IS NOT PRINTED. It is in the machine readable document,
// where a reader who wants the file's own words can find them; on this page it
// would be a second spelling of the line below, free to disagree with it under
// --redact, where one is withheld and the other pseudonymised.
//
// A SCRIPT NOBODY COULD FETCH PRINTS NOTHING HERE and says so in its summary,
// which is the line every surface renders without knowing the kind.
func pacScriptValue(script report.PACScript) string {
	if script.Selected == nil {
		return ""
	}
	if script.Selected.Endpoint == "" {
		return script.Selected.Kind
	}
	return script.Selected.Kind + " " + script.Selected.Endpoint
}

// proxyStackValue is what a person needs from a proxy row beyond its summary:
// whether this target skips the proxy, and under whose reading.
//
// THE ADDRESS IS HERE AND NOT IN THE SUMMARY, and that is the masking rule the
// core states at summaryOf rather than a layout choice: a summary is masked by a
// rule that cannot recognise a bare "host:port" as a machine, and this body is
// masked by one that can. Printing it from here prints the MASKED value.
//
// THE READINGS ARE HERE TOO, because they are the fact somebody opened this tool
// to find: ONE exception list gives DIFFERENT answers to different programs on
// one machine, and no single line of prose can carry that.
//
// THE EXCEPTION LIST ITSELF IS NOT PRINTED. It is in the machine readable
// document, where a reader who wants the entries can find them; on this page it
// would be a column of somebody's internal host names, wide enough to push the
// answer off the line.
//
// A CLASS OF DIVERGENCE IS NOT HERE EITHER, and that is not an omission: it is
// a row of its own with a summary of its own, so printing it again beside every
// stack would say one thing several times and let the copies disagree.
func proxyStackValue(stack report.ProxyStack) string {
	var parts []string
	if stack.Selected != nil {
		parts = append(parts, stack.Selected.Address)
	}
	for _, rule := range stack.BypassRules {
		parts = append(parts, fmt.Sprintf("%s: %s", rule.Rule, bypassWord(rule.Bypasses)))
	}
	return strings.Join(parts, ", ")
}

// bypassWord says which way the answer went, in words rather than as a boolean.
//
// "true" IN A COLUMN OF A REPORT IS AMBIGUOUS about which question it answers,
// and this one is easy to read backwards: a list of exceptions matching means
// the proxy is NOT used.
func bypassWord(bypasses bool) string {
	if bypasses {
		return "direct"
	}
	return "via proxy"
}

// handshakeValue is what was negotiated, for a row where anything was.
//
// THE REASON A HANDSHAKE FAILED IS DELIBERATELY NOT HERE, for the same reason
// the outcome is missing from connectValue one function up: it belongs in the
// summary, the line every surface renders without knowing the kind. A row that
// showed why it failed only in a column this renderer happens to print would go
// silent the day a markdown renderer exists.
//
// THE CIPHER IS SHOWN BY NAME AND THAT IS NOT A CONTRADICTION OF RULE 19. This
// is the surface a person reads; the number is in the document a program reads,
// beside the name, and the contract says which of the two to branch on.
func handshakeValue(shake report.TLSHandshake) string {
	if !shake.Completed {
		return ""
	}
	// Assembled by skipping what is absent rather than by joining and trimming.
	// A protocol nobody agreed on is a real state, and an empty entry in this
	// list would render as a stray comma that reads like a missing value.
	said := make([]string, 0, 3)
	for _, part := range []string{shake.Version, shake.CipherSuiteName, shake.ALPN} {
		if part != "" {
			said = append(said, part)
		}
	}
	return strings.Join(said, ", ")
}

// connectValue is the port and how long the attempt took.
//
// THE OUTCOME IS DELIBERATELY NOT HERE, for the same reason the response code is
// not in the resolution value one function down: it belongs in the summary, the
// line every surface renders without knowing the kind. An outcome visible only
// in a column this renderer happens to print would vanish the day a markdown
// renderer exists.
//
// The address is not repeated either - it is the row's name, printed beside it.
func connectValue(attempt report.TCPConnect) string {
	if !attempt.Outcome.Reached() {
		// Nothing was attempted, so there is no time to show. Saying "0 ms" here
		// would be a measurement of something that did not happen.
		return fmt.Sprintf("port %d", attempt.Port)
	}
	return fmt.Sprintf("port %d, %d ms", attempt.Port, attempt.DurationMS)
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
			fmt.Fprintf(b, "%s ", visible(string(note.Layer)))
		}
		if note.Field != "" {
			fmt.Fprintf(b, "%s ", visible(note.Field))
		}
		fmt.Fprintf(b, "[%s] %s\n", visible(string(note.Kind)), visible(note.Detail))
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
