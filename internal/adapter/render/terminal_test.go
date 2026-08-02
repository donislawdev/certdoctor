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
			Sentence: "Failures in 2 of 8 diagnostic layers.",
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

x Failures in 2 of 8 diagnostic layers.
exit 4 DIAGNOSIS

LAYERS
  x FAIL     L0  Context          unrecognized_output  the presented chain does not reach any trust anchor this runtime knows about, and the issuer is local to this machine
  ! WARN     L1  Name resolution  access_denied  one of the configured resolvers could not be read
  ? UNKNOWN  L2  Proxy            probe_error  not implemented
  + PASS     L3  TCP
  x FAIL     L4  TLS              unrecognized_output  the presented chain does not reach any trust anchor this runtime knows about, and the issuer is local to this machine
  ! WARN     L5  Trust matrix     access_denied  one of the configured resolvers could not be read
  ? UNKNOWN  L6  Containers       probe_error  not implemented
  + PASS     L7  Report

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
