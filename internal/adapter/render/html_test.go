package render

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// renderHTML is the whole renderer, run.
func renderHTML(t *testing.T, r report.Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := (HTML{}).Render(&b, r); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	return b.String()
}

// hostile is a value shaped like every way somebody else's string could stop
// being text on this surface.
//
// IT IS ONE CONSTANT USED BY SEVERAL TESTS ON PURPOSE. Each of them asks a
// different question about the same input, and a second spelling of it would let
// one of those questions be answered about a weaker string than the others.
const hostile = `<script>alert(1)</script>" onload="boom" ` +
	`<img src=x onerror=y> & ' [link](http://elsewhere)`

// poison marks a value as having come from the machine being diagnosed.
//
// It is deliberately free of characters with a meaning in HTML, so that a test
// looking for it inside an attribute is asking WHERE THE VALUE WENT rather than
// whether it was escaped on the way. Those are two different defences and this
// file checks them separately.
const poison = "zzpoisonzz"

// TestThePageCarriesNoScriptAndFetchesNothing is the security property that
// decided the shape of this renderer.
//
// A REPORT IS FORWARDED, AND FORWARDING IS THE THREAT. This page ends up in a
// ticket, in a mail to a security team, on a shared drive. If it fetched a font
// or a stylesheet it would announce every one of those openings to a third
// party - from a program whose inviolable rule 16 says the set of destinations
// is finite and named. If it carried script it would be executable content
// arriving in the inbox of exactly the people who must not receive any.
//
// THE ASSERTION IS ABOUT ABSENCE, so it deliberately does not go through
// containsEscaped: this is the one question where being generous would make the
// test useless.
//
// IT ASKS AN ORDINARY REPORT, AND THE FIRST DRAFT ASKED A HOSTILE ONE AND WAS
// WRONG. A page correctly showing the text "<img src=x onerror=y>" as escaped
// characters contains the letters "onerror=" and "src=" - so a substring ban run
// over that page fails on the renderer doing its job perfectly, and the obvious
// way to make it pass is to stop printing the value. The two questions are split
// on purpose: this one asks what the renderer EMITS, and the hostile-value test
// below asks what somebody else's string can BECOME.
func TestThePageCarriesNoScriptAndFetchesNothing(t *testing.T) {
	page := renderHTML(t, everyStatusReport())

	for _, forbidden := range []string{
		"<script", "</script", "<iframe", "<object", "<embed", "<link ",
		"javascript:", "srcdoc", "onerror=", "onload=", "onclick=",
	} {
		if strings.Contains(strings.ToLower(page), forbidden) {
			t.Errorf("the page carries %q, which either executes or fetches", forbidden)
		}
	}

	// EVERY ADDRESS ON THE PAGE IS A FRAGMENT. A src attribute cannot appear at
	// all, and the only href this renderer writes points inside the document.
	if strings.Contains(page, "src=") {
		t.Error("the page carries a src attribute, so it loads something from somewhere")
	}
	for _, href := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(page, -1) {
		if !strings.HasPrefix(href[1], "#") {
			t.Errorf("the page links to %q, which is not a place inside itself", href[1])
		}
	}
}

// TestNothingFromTheDiagnosedMachineReachesAnAttribute is the rule that makes
// the escaping a second line of defence rather than the only one.
//
// ESCAPING IS A PROPERTY OF A FUNCTION, AND THIS IS A PROPERTY OF THE CALLS. A
// renderer where somebody else's text never reaches an attribute cannot be
// broken by one forgotten htmlText, because there is nowhere for an unescaped
// value to do damage that is worse than showing up as visible text. The class
// names, the anchors and the open marker on a details element all come from our
// own closed registries, and this test is what keeps that true.
//
// IT LOOKS FOR THE VALUE, NOT FOR A BROKEN QUOTE. A test that only asked whether
// the page still parses would pass on a renderer that puts a host name in a
// title attribute and escapes it correctly - which is safe today and is one
// refactor away from not being.
func TestNothingFromTheDiagnosedMachineReachesAnAttribute(t *testing.T) {
	page := renderHTML(t, poisonedReport())

	if !strings.Contains(page, poison) {
		t.Fatal("the marker is nowhere on the page, so this test is asking about nothing")
	}

	// Attribute values are always double quoted by this renderer, and an escaped
	// value can never contain a raw double quote, so this pattern cannot be
	// fooled by a value that ran past its own delimiter.
	for _, attribute := range regexp.MustCompile(`[a-zA-Z-]+="([^"]*)"`).FindAllStringSubmatch(page, -1) {
		if strings.Contains(attribute[1], poison) {
			t.Errorf("a value from the diagnosed machine reached an attribute: %q", attribute[0])
		}
	}
}

// TestAHostileValueArrivesAsTextRatherThanAsMarkup covers the other defence.
func TestAHostileValueArrivesAsTextRatherThanAsMarkup(t *testing.T) {
	page := renderHTML(t, hostileReport())

	// The tag the value asked for must not exist, and the text of it must.
	if strings.Contains(page, "<img") {
		t.Error("a value from the diagnosed machine became an element")
	}
	if !strings.Contains(page, "&lt;img src=x onerror=y&gt;") {
		t.Error("the hostile value is not on the page as escaped text either, so it was dropped")
	}
	for _, entity := range []string{"&lt;", "&gt;", "&amp;", "&#34;", "&#39;"} {
		if !strings.Contains(page, entity) {
			t.Errorf("no %s anywhere, so one of the five characters is not being escaped", entity)
		}
	}
}

// TestControlBytesAreMadeVisibleBeforeEscaping says the two defences are applied
// in the right order.
//
// visible RUNS FIRST AND ESCAPING RUNS ON ITS RESULT. This file is read with cat
// and grep at least as often as it is opened in a browser, so a control byte is
// as dangerous here as on a console - and escaping alone would carry it through
// untouched, because an escape sequence contains no character HTML cares about.
func TestControlBytesAreMadeVisibleBeforeEscaping(t *testing.T) {
	document := everyStatusReport()
	document.Run.Target = "https://example.com/\x1b[31mred\x07"

	page := renderHTML(t, document)

	if strings.ContainsRune(page, '\x1b') || strings.ContainsRune(page, '\x07') {
		t.Error("a control byte reached the page")
	}
	// visible spells a control character as \uXXXX, and the point is that
	// the reader is TOLD one was there rather than having it removed.
	if !strings.Contains(page, `\u001b`) || !strings.Contains(page, `\u0007`) {
		t.Error("a control byte was dropped instead of being shown, so the report hides a finding")
	}
}

// TestTheChainIsOpenAloneAndFoldedInCompany checks the one affordance on this
// page that has a rule behind it rather than a default.
//
// ONE CERTIFICATE IS A FACT AND FOUR ARE A SEARCH. Hiding a single certificate
// behind a click hides evidence; showing four in full puts the thing somebody
// came for below a screen of fields they did not ask about.
func TestTheChainIsOpenAloneAndFoldedInCompany(t *testing.T) {
	one := renderHTML(t, chainReport(1))
	if !strings.Contains(one, "<details class=\"chain\" open>") {
		t.Error("a chain of one is folded away, so a single certificate needs a click")
	}

	several := renderHTML(t, chainReport(3))
	if !strings.Contains(several, "<details class=\"chain\">") {
		t.Error("a chain of three is not folded")
	}
	if !strings.Contains(several, "certificate chain (3)") {
		t.Error("the folded chain does not say how many certificates are inside it")
	}
}

// TestALayerIsLinkedOnlyWhenThereIsSomewhereToGo keeps the overview honest.
//
// A DEAD ANCHOR IS THE QUIET KIND OF WRONG: the browser stays where it is, and
// the reader concludes the page is broken rather than that the layer found
// nothing. Every layer keeps its identifier either way, so nothing is hidden -
// only the link is conditional.
func TestALayerIsLinkedOnlyWhenThereIsSomewhereToGo(t *testing.T) {
	page := renderHTML(t, everyStatusReport())

	targets := map[string]bool{}
	for _, id := range regexp.MustCompile(`id="(layer-[^"]*)"`).FindAllStringSubmatch(page, -1) {
		targets[id[1]] = true
	}
	if len(targets) == 0 {
		t.Fatal("no findings section has an anchor, so this test is asking about nothing")
	}
	for _, href := range regexp.MustCompile(`href="#([^"]*)"`).FindAllStringSubmatch(page, -1) {
		if !targets[href[1]] {
			t.Errorf("the overview links to #%s and no section has that anchor", href[1])
		}
	}

	// Every declared layer is still listed, linked or not. A row missing from
	// the overview is a silence, and silence reads as "nothing was found".
	for _, id := range layer.All {
		if got := strings.Count(page, ">"+id.String()+"<"); got != 1 {
			t.Errorf("the overview carries %d cells for %s, want exactly 1", got, id)
		}
	}
}

// TestTheNotesSectionIsPrintedWhenThereIsNothingToSay is inviolable rule 1 on
// this surface.
//
// A REPORT WITH NO NOTES IS MAKING A CLAIM - that nothing was skipped - and a
// claim made by silence cannot be told from a section somebody forgot to write.
func TestTheNotesSectionIsPrintedWhenThereIsNothingToSay(t *testing.T) {
	document := everyStatusReport()
	document.Notes = nil

	page := renderHTML(t, document)
	if !strings.Contains(page, "<h2>Notes</h2>") {
		t.Error("a report with no notes has no notes section, so the claim is made by silence")
	}
	if !strings.Contains(page, "nothing was skipped and nothing was left undetermined") {
		t.Error("the empty notes section does not say what it means")
	}
}

// TestTheStatusColourIsNeverTheOnlyCarrier is inviolable rule 20 and WCAG 1.4.1
// asked on the one surface where colour is ours to choose.
//
// ON A TERMINAL COLOUR CAN BE TURNED OFF AND THE REPORT STILL READS. Here it
// cannot be turned off by the reader at all, which makes the question sharper
// rather than softer: the glyph and the status word have to be beside every
// tint, so that a reader who cannot separate the hues loses nothing but colour.
func TestTheStatusColourIsNeverTheOnlyCarrier(t *testing.T) {
	page := renderHTML(t, everyStatusReport())

	for _, s := range status.All {
		class := statusClass(s)
		if !strings.Contains(page, class) {
			continue
		}
		if !strings.Contains(page, Label(s)) {
			t.Errorf("%s is painted with %s and its word is nowhere on the page", s, class)
		}
		if !strings.Contains(page, Of(s).Glyph) {
			t.Errorf("%s is painted with %s and its glyph is nowhere on the page", s, class)
		}
	}
}

// TestTheDocumentIsWellFormedEnoughToOpen is a shallow structural check, and it
// says so about itself.
//
// IT IS NOT A PARSER AND MUST NOT GROW INTO ONE. What it covers is the class of
// defect that a string-comparison test cannot see and a browser answers by
// drawing something wrong rather than by refusing: a tag opened and not closed.
// Counting is enough for that, and anything more would be writing a second
// implementation of the renderer inside its test.
func TestTheDocumentIsWellFormedEnoughToOpen(t *testing.T) {
	page := renderHTML(t, everyStatusReport())

	if !strings.HasPrefix(page, "<!DOCTYPE html>") {
		t.Error("the page does not begin with a doctype, so a browser will guess at it")
	}
	if !strings.HasSuffix(page, "</html>\n") {
		t.Error("the page does not end with a closed root element")
	}
	for _, element := range []string{"html", "head", "body", "table", "tbody", "section", "article", "ul", "ol", "details"} {
		open := strings.Count(page, "<"+element+" ") + strings.Count(page, "<"+element+">")
		closed := strings.Count(page, "</"+element+">")
		if open != closed {
			t.Errorf("%d <%s> opened and %d closed", open, element, closed)
		}
	}
}

// hostileReport puts a string shaped like an attack into every field of the
// report a renderer prints as text.
func hostileReport() report.Report {
	document := everyStatusReport()
	document.Run.Target = hostile
	document.Verdict.Sentence = hostile
	document.Layers[0].Detail = hostile
	document.Layers[0].Findings = []report.Finding{{
		Kind:    report.FindingEnvironmentVariable,
		Summary: hostile,
		Source:  report.SourceDetected,
		EnvironmentVariable: &report.EnvironmentVariable{
			Name: "HTTPS_PROXY", Value: hostile, Set: true,
		},
	}}
	document.Notes = []report.Note{{Kind: report.NoteSkipped, Layer: layer.Report, Detail: hostile}}
	return document
}

// poisonedReport marks every diagnosed value so a test can follow where it went.
func poisonedReport() report.Report {
	document := everyStatusReport()
	document.Tool.Name = poison
	document.Tool.Version = poison
	document.Run.Target = poison
	document.Run.Platform = report.Platform{OS: poison, Arch: poison}
	document.Verdict.Sentence = poison
	document.Layers[0].Detail = poison
	document.Layers[0].Findings = []report.Finding{{
		Kind:    report.FindingEnvironmentVariable,
		Summary: poison,
		Source:  report.SourceDetected,
		EnvironmentVariable: &report.EnvironmentVariable{
			Name: poison, Value: poison, Set: true,
		},
	}}
	document.Notes = []report.Note{{Kind: report.NoteSkipped, Layer: layer.Report, Detail: poison}}
	return document
}

// chainReport is one handshake finding carrying n certificates.
func chainReport(n int) report.Report {
	document := everyStatusReport()

	chain := make([]report.Certificate, 0, n)
	for i := 0; i < n; i++ {
		certificate := bodyFixtures[report.FindingTLSHandshake].TLSHandshake.Chain[0]
		certificate.IsCA = i > 0
		chain = append(chain, certificate)
	}

	handshake := *bodyFixtures[report.FindingTLSHandshake].TLSHandshake
	handshake.Chain = chain
	document.Layers[0].Findings = []report.Finding{{
		Kind:         report.FindingTLSHandshake,
		Summary:      "the server presented a chain",
		Source:       report.SourceDetected,
		TLSHandshake: &handshake,
	}}
	return document
}
