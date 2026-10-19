package render

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// escapeSequence matches an SGR colour run. It is written out in full here
// because a test is the one place allowed to name the thing it is checking for -
// the appearance guard skips test files precisely so that this can exist.
var escapeSequence = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestAColumnWidthIsCountedInRunesAndNotInBytes pins the unit the table is laid
// out in.
//
// It counted bytes, which is the same number only while every value in the
// column is ASCII. Everything is today - layer identifiers, status words, the
// names in the registry - so nothing was misaligned and nothing would have been
// until the trust matrix put a path from somebody else's machine into a column,
// with an account name that may well be in Cyrillic or CJK. The misalignment
// would then have looked like a defect in that layer rather than here.
//
// The string is built from code points rather than pasted in, so this file
// carries no character its reader cannot see.
func TestAColumnWidthIsCountedInRunesAndNotInBytes(t *testing.T) {
	// Latin small a with ogonek and z with dot above: three runes, five bytes.
	word := string([]rune{'a', 0x0105, 0x017c})

	if len(word) == widthOf(word) {
		t.Fatal("this fixture no longer tells the two units apart")
	}
	if got := widthOf(word); got != 3 {
		t.Errorf("width of a three rune word is %d, want 3", got)
	}
	if got := widthOf(pad(word, 6)); got != 6 {
		t.Errorf("padding to six left a column %d wide", got)
	}
}

// everyStatusReport is the screen showing all four statuses at once.
//
// The interface rules ask for one run that prints every status in every output
// mode, so that drift shows up on a single page instead of being discovered
// after five screens. This is that page, and the golden files beside it are what
// make looking at it something other than a habit somebody eventually skips.
//
// It also carries the awkward cases from the same rules: a very long detail
// line, a row with nothing but a status, and a note attached to a layer.
func everyStatusReport() report.Report {
	cycle := []status.Status{status.Fail, status.Warn, status.Unknown, status.Pass}
	reasons := map[status.Status]status.Reason{
		status.Fail:    status.ReasonUnparseable,
		status.Warn:    status.ReasonAccessDenied,
		status.Unknown: status.ReasonProbeError,
	}
	details := map[status.Status]string{
		status.Fail:    "the presented chain does not reach any trust anchor this runtime knows about, and the issuer is local to this machine",
		status.Warn:    "one of the configured resolvers could not be read",
		status.Unknown: "not implemented",
	}

	rows := make([]report.LayerResult, 0, len(layer.All))
	for i, id := range layer.All {
		s := cycle[i%len(cycle)]
		rows = append(rows, report.LayerResult{
			ID:     id,
			Status: s,
			Reason: reasons[s],
			Detail: details[s],
		})
	}

	// ALL THREE STATES OF A FINDINGS LIST ON ONE PAGE, for the same reason every
	// status is on it: a difference between "nobody looked" and "we looked and
	// there was nothing" is invisible one screen at a time. The first layer found
	// something, the fourth looked and found nothing, and the rest never looked.
	rows[0].Findings = []report.Finding{
		{
			Kind:    report.FindingEnvironmentVariable,
			Summary: "HTTPS_PROXY is set and carries credentials",
			Source:  report.SourceDetected,
			EnvironmentVariable: &report.EnvironmentVariable{
				Name: "HTTPS_PROXY",
				// Already masked, because this is what a rendered value looks
				// like by the time it reaches a renderer.
				Value:              "http://[redacted]@proxy.corp:8080",
				Set:                true,
				CarriedCredentials: true,
			},
		},
		{
			Kind:                report.FindingEnvironmentVariable,
			Summary:             "SSL_CERT_FILE is not set",
			Source:              report.SourceDefault,
			EnvironmentVariable: &report.EnvironmentVariable{Name: "SSL_CERT_FILE"},
		},
	}
	rows[3].Findings = []report.Finding{}

	return report.Report{
		Tool: report.Tool{Name: "certdoctor", Version: "0.0.0-test"},
		Run: report.Run{
			StartedAt:      time.Unix(1_770_000_000, 0).UTC(),
			Duration:       4820 * time.Millisecond,
			Target:         "https://api.example.com",
			PrivilegeLevel: report.PrivilegeUser,
			Platform:       report.Platform{OS: "testos", Arch: "testarch"},
		},
		Verdict: report.Verdict{
			Status:   status.Fail,
			Sentence: "Failures in 2 of 6 diagnostic layers.",
			ExitCode: exitcode.Diagnosis,
		},
		Layers: rows,
		Notes: []report.Note{
			{Kind: report.NoteNotImplemented, Detail: "no diagnostic layer is implemented yet"},
			{Kind: report.NoteSkipped, Layer: layer.TrustMatrix, Reason: status.ReasonSkippedBudget,
				Detail: "the run exceeded its overall time budget and did not walk this layer"},
			{Kind: report.NoteUndetermined, Field: "run.platform.container",
				Detail: "certdoctor does not detect containers yet"},
		},
	}
}

// screenPlainASCII is the page as it looks with nothing switched on: the safe
// mode, the one a redirected report and a CI log both get.
//
// It is written out here rather than kept in a file beside the test, and that
// is a deliberate trade. A golden file needs a way to regenerate it, and the
// only honest way to build that here would be a test that writes into the
// source tree - which is the one thing the write guard exists to refuse. Held
// as text it is also readable in a review, which is what this page is for.
//
// The other three modes are NOT pinned as separate pages. They are checked as
// transformations of this one, further down: colour has to be removable without
// changing anything else, and the marker set has to differ only in the markers.
// Pinning them separately would say the same thing four times and let three of
// the copies drift.
const screenPlainASCII = `certdoctor 0.0.0-test   https://api.example.com
2026-02-02T02:40:00Z   testos/testarch   privilege: user   took 4.82s

x Failures in 2 of 6 diagnostic layers.
exit 4 DIAGNOSIS

LAYERS
  x FAIL     L0  Context          unrecognized_output  the presented chain does not reach any trust anchor this runtime knows about, and the issuer is local to this machine
      HTTPS_PROXY is set and carries credentials  detected  http://[redacted]@proxy.corp:8080
      SSL_CERT_FILE is not set                    default
  ! WARN     L1  Name resolution  access_denied  one of the configured resolvers could not be read
  ? UNKNOWN  L2  Proxy            probe_error  not implemented
  + PASS     L3  TCP
      nothing was found
  x FAIL     L4  TLS              unrecognized_output  the presented chain does not reach any trust anchor this runtime knows about, and the issuer is local to this machine
  ! WARN     L5  Trust matrix     access_denied  one of the configured resolvers could not be read

NOTES
  - [not_implemented] no diagnostic layer is implemented yet
  - L5 [skipped] the run exceeded its overall time budget and did not walk this layer
  - run.platform.container [undetermined] certdoctor does not detect containers yet

This report contains internal names and paths. Read it before pasting it anywhere.
`

// TestTheScreenWithEveryStatusLooksLikeThis pins the layout of the one page
// this project has.
//
// The interface rules ask for a single run showing every status at once,
// because drift is invisible one screen at a time and obvious on one page. This
// is that page, and pinning it is what turns looking at it from a habit into a
// check.
func TestTheScreenWithEveryStatusLooksLikeThis(t *testing.T) {
	var rendered bytes.Buffer
	if err := (Terminal{}).Render(&rendered, everyStatusReport()); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if got := rendered.String(); got != screenPlainASCII {
		t.Errorf("the page changed.\n--- got ---\n%s\n--- want ---\n%s", got, screenPlainASCII)
	}
}

// TestTheMarkerSetIsTheOnlyDifferenceBetweenGlyphModes is the second mode
// checked as a property rather than as another copy of the page.
//
// It matters because the substitution is automatic: a Windows console on
// another code page renders the glyph as rubbish, and the fallback is what keeps
// the status column readable. A fallback that also changed the layout would fix
// one problem by introducing another.
func TestTheMarkerSetIsTheOnlyDifferenceBetweenGlyphModes(t *testing.T) {
	var unicode bytes.Buffer
	if err := (Terminal{Glyph: GlyphUnicode}).Render(&unicode, everyStatusReport()); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}

	folded := unicode.String()
	for _, s := range status.All {
		appearance := Of(s)
		if appearance.Glyph == appearance.ASCII {
			continue
		}
		if !strings.Contains(folded, appearance.Glyph) {
			t.Errorf("status %s renders no glyph in unicode mode", s)
		}
		folded = strings.ReplaceAll(folded, appearance.Glyph, appearance.ASCII)
	}
	if folded != screenPlainASCII {
		t.Errorf("the two marker sets differ by more than their markers.\n--- folded ---\n%s", folded)
	}
}

// TestColourNeverCarriesMeaningOnItsOwn is the accessibility rule as a test.
// Strip the colour and the page has to say the same thing, because a reader
// with NO_COLOR set, a reader who cannot distinguish the hues and a reader
// scrolling a CI log all get the plain version.
func TestColourNeverCarriesMeaningOnItsOwn(t *testing.T) {
	var coloured, plain bytes.Buffer
	report := everyStatusReport()

	if err := (Terminal{Color: ColorOn, Glyph: GlyphASCII}).Render(&coloured, report); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if err := (Terminal{Color: ColorOff, Glyph: GlyphASCII}).Render(&plain, report); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}

	stripped := escapeSequence.ReplaceAllString(coloured.String(), "")
	if stripped != plain.String() {
		t.Error("removing the colour changed more than the colour")
	}
	for _, s := range status.All {
		if !strings.Contains(plain.String(), Label(s)) {
			t.Errorf("status %s is not named in the uncoloured page", s)
		}
	}
}

// TestARedirectedReportCarriesNoEscapeSequences is the same promise from the
// direction that reaches a person. A report pasted into a ticket with escape
// codes in it looks broken, and a reader who thinks the tool is broken stops
// reading the verdict.
func TestARedirectedReportCarriesNoEscapeSequences(t *testing.T) {
	var plain bytes.Buffer
	if err := (Terminal{}).Render(&plain, everyStatusReport()); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if escapeSequence.MatchString(plain.String()) {
		t.Error("the zero value of Terminal produced escape sequences")
	}
	for _, r := range plain.String() {
		if r > 0x7f {
			t.Errorf("the zero value of Terminal produced the non-ASCII character %q", r)
			break
		}
	}
}

// TestEveryLayerAndEveryNoteReachesThePage is the ban on silence at the
// rendering layer. A row dropped here is a layer the reader never learns about,
// and the report would look complete without it.
func TestEveryLayerAndEveryNoteReachesThePage(t *testing.T) {
	source := everyStatusReport()
	var page bytes.Buffer
	if err := (Terminal{}).Render(&page, source); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}

	for _, row := range source.Layers {
		if !strings.Contains(page.String(), row.ID.String()) {
			t.Errorf("layer %s is in the report and not on the page", row.ID)
		}
		if !strings.Contains(page.String(), row.ID.Name()) {
			t.Errorf("layer %s has no display name on the page", row.ID)
		}
	}
	for _, note := range source.Notes {
		if !strings.Contains(page.String(), note.Detail) {
			t.Errorf("a note saying %q never reached the page", note.Detail)
		}
	}
	if !strings.Contains(page.String(), source.Verdict.Sentence) {
		t.Error("the verdict sentence never reached the page")
	}
	if !strings.Contains(page.String(), footer) {
		t.Error("the page does not warn that the report carries internal data")
	}
}

// TestEveryFindingReachesThePageWithItsValue is the parity rule at the surface a
// person actually reads.
//
// A finding present in the machine readable document has to be present here too,
// and for an environment variable the VALUE is the finding - a page showing that
// HTTPS_PROXY is set without showing what it is set to answers none of the
// questions it was pasted in to answer. The summary alone would have passed a
// weaker version of this test.
func TestEveryFindingReachesThePageWithItsValue(t *testing.T) {
	source := everyStatusReport()
	var page bytes.Buffer
	if err := (Terminal{}).Render(&page, source); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}

	for _, row := range source.Layers {
		for _, finding := range row.Findings {
			if !strings.Contains(page.String(), finding.Summary) {
				t.Errorf("layer %s carries a finding summarised %q that never reached the page", row.ID, finding.Summary)
			}
			if !strings.Contains(page.String(), finding.Source.String()) {
				t.Errorf("a finding on %s does not say how strongly it is known", row.ID)
			}
			variable := finding.EnvironmentVariable
			if variable == nil || !variable.Set || variable.Value == "" {
				continue
			}
			if !strings.Contains(page.String(), variable.Value) {
				t.Errorf("the value of %s is in the report and not on the page", variable.Name)
			}
		}
	}
}

// TestALayerThatLookedAndFoundNothingSaysSoAndOneThatNeverLookedDoesNot keeps
// the two apart on the page, the same way the document keeps null apart from an
// empty array.
//
// It is the ban on silence pointed at its own answer: printing nothing for both
// would let a layer nobody has written read as a clean bill of health, and
// printing "nothing was found" for both would state a result nobody produced.
func TestALayerThatLookedAndFoundNothingSaysSoAndOneThatNeverLookedDoesNot(t *testing.T) {
	looked := everyStatusReport()
	var withEmpty bytes.Buffer
	if err := (Terminal{}).Render(&withEmpty, looked); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if got := strings.Count(withEmpty.String(), "nothing was found"); got != 1 {
		t.Errorf("the page says nothing was found %d times, and exactly one layer looked and found nothing", got)
	}

	neverLooked := everyStatusReport()
	for i := range neverLooked.Layers {
		neverLooked.Layers[i].Findings = nil
	}
	var withNil bytes.Buffer
	if err := (Terminal{}).Render(&withNil, neverLooked); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if strings.Contains(withNil.String(), "nothing was found") {
		t.Error("a report in which no layer ever looked still claims that nothing was found")
	}
}

// These three use the pageWith helper remediation_test.go already declares -
// one report, one layer's findings replaced, rendered. A second copy of it here
// is the shape OBS50 has measured six times in this tree.

// TestThePageSaysWhichNamesAScriptSentToAResolver is OBS129's rule applied to the
// field that exists because of it. The allowed set is a list of PLACES and a
// resolver is on it, so a query somebody else's PAC file provokes is permitted by
// construction and no guard reports it - printing the names is the only way the
// person running this on their own machine learns their script sent names out.
func TestThePageSaysWhichNamesAScriptSentToAResolver(t *testing.T) {
	page := pageWith(t, report.Finding{
		Kind:      report.FindingPACScript,
		Summary:   "the PAC script at http://wpad.corp/proxy.pac answered",
		Source:    report.SourceDetected,
		PACScript: &report.PACScript{URL: "http://wpad.corp/proxy.pac", Fetched: true, Asked: []string{"one.corp", "two.corp"}},
	})

	if !strings.Contains(page, "asked a resolver about 2 name(s)") {
		t.Errorf("the page does not say how many names left this machine:\n%s", page)
	}
	for _, name := range []string{"one.corp", "two.corp"} {
		if !strings.Contains(page, name) {
			t.Errorf("the page does not name %q, so the channel is invisible here:\n%s", name, page)
		}
	}
}

// TestAScriptThatAskedNothingGetsNoBlockAtAll keeps a heading over an empty list
// off the page. The difference between a script that ran and asked nothing and
// one that never ran is real and is kept - in the document a program reads, where
// null and an empty array can say it. On a page for a person, a heading with
// nothing under it is a line asking to be interpreted.
func TestAScriptThatAskedNothingGetsNoBlockAtAll(t *testing.T) {
	for _, asked := range [][]string{nil, {}} {
		page := pageWith(t, report.Finding{
			Kind:      report.FindingPACScript,
			Summary:   "the PAC script at http://wpad.corp/proxy.pac answered",
			Source:    report.SourceDetected,
			PACScript: &report.PACScript{URL: "http://wpad.corp/proxy.pac", Fetched: true, Asked: asked},
		})
		if strings.Contains(page, "asked a resolver about") {
			t.Errorf("a script that asked about nothing still got a heading:\n%s", page)
		}
	}
}

// TestThePageSaysWhatARowDoesNotSettle is the gap running the binary found: three
// bodies assemble our own sentences about the limits of what they measured, every
// one reached the machine readable document, and a person at a terminal saw none.
// A row that prints an answer while the layer refuses to rest a verdict on it has
// to say why, or the verdict looks arbitrary.
func TestThePageSaysWhatARowDoesNotSettle(t *testing.T) {
	const caveat = "this script asked about more distinct names than one evaluation may resolve"

	for _, one := range []struct {
		name    string
		finding report.Finding
	}{
		{"pac script", report.Finding{
			Kind: report.FindingPACScript, Summary: "a script answered", Source: report.SourceDetected,
			PACScript: &report.PACScript{URL: "http://wpad.corp/p.pac", Fetched: true, Caveats: []string{caveat}},
		}},
		{"proxy stack", report.Finding{
			Kind: report.FindingProxyStack, Summary: "a stack names a proxy", Source: report.SourceDetected,
			ProxyStack: &report.ProxyStack{Caveats: []string{caveat}},
		}},
		{"proxy challenge", report.Finding{
			Kind: report.FindingProxyChallenge, Summary: "a proxy was asked", Source: report.SourceDetected,
			ProxyChallenge: &report.ProxyChallenge{Caveats: []string{caveat}},
		}},
	} {
		t.Run(one.name, func(t *testing.T) {
			if page := pageWith(t, one.finding); !strings.Contains(page, caveat) {
				t.Errorf("the page drops what this row does not settle:\n%s", page)
			}
		})
	}
}

// TestAReportWithNoNotesStillSaysSo covers the degenerate input. An empty
// section that simply disappears reads as a question nobody asked, and "nothing
// was skipped" is a claim worth seeing.
func TestAReportWithNoNotesStillSaysSo(t *testing.T) {
	source := everyStatusReport()
	source.Notes = nil

	var page bytes.Buffer
	if err := (Terminal{}).Render(&page, source); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if !strings.Contains(page.String(), "NOTES") {
		t.Error("a report with no notes dropped the section entirely")
	}
	if !strings.Contains(page.String(), "nothing was skipped") {
		t.Error("a report with no notes does not say that nothing was skipped")
	}
}

// TestColumnsAreMeasuredRatherThanChosen guards against hard geometry. A width
// picked by hand looks right on the author's machine and truncates the first
// name longer than the ones they happened to test with.
func TestColumnsAreMeasuredRatherThanChosen(t *testing.T) {
	source := everyStatusReport()
	long := strings.Repeat("x", 120)
	source.Layers[0].Detail = long

	var page bytes.Buffer
	if err := (Terminal{}).Render(&page, source); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if !strings.Contains(page.String(), long) {
		t.Error("a long detail line was truncated")
	}
}

// TestTheTerminalRendersTheSecondKindOfFinding covers the surface parity rule at
// the moment the union grew a second member.
//
// INVIOLABLE RULE 12: every finding has to be expressible in the terminal, in
// md/html and in --json. The renderer degrades gracefully for a kind it does not
// know - it prints the summary and no value column - so a second kind that
// nobody taught it about would LOOK FINE while quietly losing the addresses.
// That is why this asserts on the value column and not only on the summary.
// hostileText is put into every text field a report has. It carries one of each
// class visible refuses: an escape that starts a colour sequence, a NUL, a
// carriage return that would rewrite the line, a C1 byte, and a bidirectional
// override that reorders whatever follows it.
const hostileText = "ok\x1b[32m\x00\rok\u202eok"

// TestNoControlByteFromTheMachineReachesTheTerminal is the guard for OBS47, and
// it is written as a PROPERTY over the whole page rather than as a list of
// fields.
//
// THAT SHAPE IS THE POINT. A test naming today's fields would pass forever while
// a field added next year went out raw - which is exactly how this hole appeared:
// the appearance guard reads OUR SOURCE for literal escape sequences and is blind
// by construction to bytes that arrive in the data. Colour is switched off here,
// so the page has no legitimate escape at all and the assertion can be total.
//
// The measured case behind it: HTTPS_PROXY carrying an escape sequence rendered
// the report in colour with --no-color asked for. A value that can repaint a row
// can make a FAIL read as a pass.
func TestNoControlByteFromTheMachineReachesTheTerminal(t *testing.T) {
	r := reportWithHostileTextEverywhere()

	var b strings.Builder
	if err := (Terminal{}).Render(&b, r); err != nil {
		t.Fatalf("the report could not be rendered: %v", err)
	}

	for i, line := range strings.Split(b.String(), "\n") {
		for _, symbol := range line {
			if symbol == '\n' {
				continue
			}
			if forbiddenOnAPage(symbol) {
				t.Fatalf("line %d carries U+%04X, which a terminal acts on: %q", i+1, symbol, line)
			}
		}
	}
	// The other side. A guard that stripped everything would pass the loop above
	// and produce a page saying nothing, so the escaped form has to be there.
	if !strings.Contains(b.String(), `\u001b`) {
		t.Error("the escape sequence was deleted rather than made visible - the report now shows a value that is not the value on the machine")
	}
	requireFindingColumnsLineUp(t, b.String())
}

// forbiddenOnAPage is the test's OWN list of what a terminal acts on, written
// out separately from unsafeRune on purpose.
//
// THE FIRST VERSION ASKED unsafeRune AND THE MUTATION REGISTER CAUGHT IT. A test
// whose oracle is the function under test agrees with that function whatever it
// does: deleting the bidirectional range from unsafeRune made the renderer stop
// escaping those runes AND made this loop stop looking for them, so the mutant
// survived while the page carried an invisible override. Two readings of one rule
// by the same hand are one witness, not two.
func forbiddenOnAPage(r rune) bool {
	if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
		return true
	}
	for _, bidi := range []rune{
		0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
		0x2066, 0x2067, 0x2068, 0x2069,
	} {
		if r == bidi {
			return true
		}
	}
	return false
}

// requireFindingColumnsLineUp checks that two findings whose escaped summaries
// differ in length still put their value column in the same place.
//
// COLUMNS ARE MEASURED ON THE ESCAPED TEXT and the golden page cannot see it:
// nothing on that page carries a control byte, so measuring before or after
// escaping gives identical widths there. The mutation register found the gap.
func requireFindingColumnsLineUp(t *testing.T, page string) {
	t.Helper()
	var starts []int
	for _, line := range strings.Split(page, "\n") {
		at := strings.Index(line, "  detected")
		if strings.HasPrefix(line, "      ") && at > 0 {
			starts = append(starts, at)
		}
	}
	if len(starts) < 2 {
		t.Fatalf("the fixture no longer produces two finding rows, so this check proves nothing: %d found", len(starts))
	}
	for _, at := range starts[1:] {
		if at != starts[0] {
			t.Errorf("finding columns do not line up: source column starts at %d and at %d", starts[0], at)
		}
	}
}

// TestOnlyOurOwnAppearanceEscapesSurviveWithColourOn is the second half. With
// colour on the page legitimately carries escape sequences, so the test above
// cannot be total - this one says the only ones present are the dictionary's.
func TestOnlyOurOwnAppearanceEscapesSurviveWithColourOn(t *testing.T) {
	r := reportWithHostileTextEverywhere()

	var b strings.Builder
	if err := (Terminal{Color: ColorOn}).Render(&b, r); err != nil {
		t.Fatalf("the report could not be rendered: %v", err)
	}

	// Every escape our own painting emits is followed by a bracket and ends at
	// an m. Anything else came from the data.
	rest := b.String()
	for {
		at := strings.IndexRune(rest, 0x1b)
		if at < 0 {
			return
		}
		tail := rest[at:]
		end := strings.IndexRune(tail, 'm')
		if end < 0 || !strings.HasPrefix(tail, "\x1b[") {
			t.Fatalf("an escape sequence that is not ours reached the page: %q", tail[:min(20, len(tail))])
		}
		if strings.ContainsAny(tail[:end], "\x00\r") {
			t.Fatalf("an escape sequence carries control bytes from the data: %q", tail[:end])
		}
		rest = tail[end+1:]
	}
}

// reportWithHostileTextEverywhere fills every string a report carries, so the
// property test above covers fields nobody thought to name.
func reportWithHostileTextEverywhere() report.Report {
	r := everyStatusReport()
	r.Tool.Name = hostileText
	r.Tool.Version = hostileText
	r.Run.Target = hostileText
	r.Run.Platform.OS = hostileText
	r.Run.Platform.Arch = hostileText
	r.Verdict.Sentence = hostileText
	// TWO FINDINGS OF THE SAME RAW LENGTH AND DIFFERENT ESCAPED LENGTH, and that
	// is what makes the alignment check able to fail at all. Measured before
	// escaping the two summaries look identical, so the column is set too narrow
	// for the one that grew - measured after, the plain row is padded to match.
	// A fixture whose two rows escape to the same length would pass either way,
	// which is the shape OBS43 records.
	plain := strings.Repeat("p", len([]rune(hostileText)))
	for i := range r.Layers {
		r.Layers[i].Detail = hostileText
		r.Layers[i].Findings = []report.Finding{
			{
				Kind:    report.FindingEnvironmentVariable,
				Summary: hostileText,
				Source:  report.SourceDetected,
				EnvironmentVariable: &report.EnvironmentVariable{
					Name: hostileText, Value: hostileText, Set: true,
				},
			},
			{
				Kind:    report.FindingEnvironmentVariable,
				Summary: plain,
				Source:  report.SourceDetected,
				EnvironmentVariable: &report.EnvironmentVariable{
					Name: plain, Value: plain, Set: true,
				},
			},
		}
	}
	r.Notes = []report.Note{{
		Kind:   report.NoteDegraded,
		Field:  hostileText,
		Detail: hostileText,
	}}
	return r
}

func TestTheTerminalRendersTheSecondKindOfFinding(t *testing.T) {
	r := everyStatusReport()
	for i := range r.Layers {
		if r.Layers[i].ID != layer.Resolution {
			continue
		}
		r.Layers[i].Findings = []report.Finding{
			{
				Kind:    report.FindingNameResolution,
				Summary: "this system resolves example.com to 2 addresses",
				Source:  report.SourceDetected,
				NameResolution: &report.NameResolution{
					Name:       "example.com",
					View:       report.ViewSystem,
					Addresses:  []string{"192.0.2.10", "2001:db8::10"},
					DurationMS: 27,
				},
			},
			{
				Kind:    report.FindingNameResolution,
				Summary: "192.0.2.53 answered NODATA for example.com AAAA",
				Source:  report.SourceDetected,
				NameResolution: &report.NameResolution{
					Name:         "example.com",
					View:         report.ViewDirect,
					Resolver:     "192.0.2.53",
					QueryType:    "AAAA",
					ResponseCode: "NODATA",
					DurationMS:   4,
				},
			},
		}
	}

	var page strings.Builder
	if err := (Terminal{}).Render(&page, r); err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	out := page.String()

	for _, want := range []string{
		"this system resolves example.com to 2 addresses",
		"192.0.2.10",
		"2001:db8::10",
		"27 ms",
		// The response code lives in the summary, which is the line every surface
		// renders without knowing the kind. A code visible only in a column this
		// renderer happens to print would vanish in markdown.
		"192.0.2.53 answered NODATA for example.com AAAA",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the page does not carry %q:\n%s", want, out)
		}
	}
}
