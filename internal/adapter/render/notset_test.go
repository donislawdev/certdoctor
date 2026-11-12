package render

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// absent is an L0 finding for a variable nobody set, built the way L0 builds it.
func absent(name string) report.Finding {
	return report.Finding{
		Kind:                report.FindingEnvironmentVariable,
		Summary:             report.NotSetSummary(name),
		Source:              report.SourceDefault,
		EnvironmentVariable: &report.EnvironmentVariable{Name: name},
	}
}

// present is an L0 finding for a variable that is set, possibly to nothing.
func present(name, value string) report.Finding {
	summary := name + " is set"
	if value == "" {
		summary = name + " is set to nothing"
	}
	return report.Finding{
		Kind:                report.FindingEnvironmentVariable,
		Summary:             summary,
		Source:              report.SourceDetected,
		EnvironmentVariable: &report.EnvironmentVariable{Name: name, Value: value, Set: true},
	}
}

// withContext is the page with every status, its L0 carrying these findings.
func withContext(findings ...report.Finding) report.Report {
	r := everyStatusReport()
	r.Layers[0].Findings = findings
	return r
}

// pagesFor renders the three pages meant for people.
func pagesFor(t *testing.T, r report.Report) (terminal, markdown, page string) {
	t.Helper()
	var term, md bytes.Buffer
	if err := (Terminal{}).Render(&term, r); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	if err := (Markdown{}).Render(&md, r); err != nil {
		t.Fatalf("markdown: %v", err)
	}
	return term.String(), md.String(), renderHTML(t, r)
}

// notSetNamesOn reads the "not set" paragraph back off a terminal page the way a
// person reads it: every word after the label, up to the first one that does not
// end in a comma.
func notSetNamesOn(page string) map[string]bool {
	names := map[string]bool{}
	_, after, found := strings.Cut(page, "not set (default):")
	if !found {
		return names
	}
	for _, word := range strings.Fields(after) {
		name, more := strings.CutSuffix(word, ",")
		names[name] = true
		if !more {
			break
		}
	}
	return names
}

// TestAVariableNobodySetIsANameInOneParagraph is ADR137 on all three pages.
//
// THE SET VARIABLES KEEP THEIR ROWS AND COME FIRST, the absent ones are one
// paragraph of names after them, and the machine readable document still has
// one entry per variable with its own sentence - nothing a program counts on
// moved.
func TestAVariableNobodySetIsANameInOneParagraph(t *testing.T) {
	r := withContext(
		absent("HTTP_PROXY"),
		present("HTTPS_PROXY", "http://proxy.example:8080"),
		absent("NO_PROXY"),
		present("no_proxy", ""),
	)
	terminal, markdown, page := pagesFor(t, r)

	if !strings.Contains(terminal, "\n      not set (default): HTTP_PROXY, NO_PROXY\n") {
		t.Errorf("the terminal does not list the two absent variables in one paragraph:\n%s", terminal)
	}
	if !containsEscaped(markdown, "\n- not set *(default)*: HTTP_PROXY, NO_PROXY\n") {
		t.Errorf("the markdown page does not list the two absent variables in one bullet:\n%s", markdown)
	}
	if !containsEscaped(page, `<p class="summary">not set <span class="source">default</span>: HTTP_PROXY, NO_PROXY</p>`) {
		t.Errorf("the HTML page does not list the two absent variables in one paragraph:\n%s", page)
	}

	for surface, text := range map[string]string{"terminal": terminal, "markdown": markdown, "html": page} {
		for _, gone := range []string{"HTTP_PROXY is not set", "NO_PROXY is not set"} {
			if strings.Contains(text, gone) {
				t.Errorf("the %s page still prints %q as a row of its own", surface, gone)
			}
		}
		for _, kept := range []string{"HTTPS_PROXY is set", "proxy.example:8080", "no_proxy is set to nothing"} {
			if !containsEscaped(text, kept) {
				t.Errorf("the %s page lost %q, which is a variable that is set", surface, kept)
			}
		}
		if strings.Index(text, "no_proxy is set to nothing") > strings.Index(text, "not set") {
			t.Errorf("on the %s page the absent variables come before the set ones", surface)
		}
	}

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	for _, sentence := range []string{`"summary": "HTTP_PROXY is not set"`, `"summary": "NO_PROXY is not set"`} {
		if !strings.Contains(string(document), sentence) {
			t.Errorf("the machine readable document lost %s - it keeps one entry per variable", sentence)
		}
	}
}

// TestOnlyASentenceSayingNothingButNotSetBecomesAName keeps every other finding
// a row.
//
// THE PARAGRAPH PRINTS NAMES. A finding that says anything else - a longer
// sentence, a source other than the default, a variable set to nothing - would
// lose what it says by going into it, so each of these must come out as a row
// with its sentence whole, and the paragraph must not appear at all.
func TestOnlyASentenceSayingNothingButNotSetBecomesAName(t *testing.T) {
	longer := absent("http_proxy")
	longer.Summary = "http_proxy is not set, and curl reads only this spelling"
	detected := absent("ALL_PROXY")
	detected.Source = report.SourceDetected

	for name, finding := range map[string]report.Finding{
		"a longer sentence":         longer,
		"a source other than ours":  detected,
		"a variable set to nothing": present("NO_PROXY", ""),
	} {
		terminal, markdown, page := pagesFor(t, withContext(finding))
		for surface, text := range map[string]string{"terminal": terminal, "markdown": markdown, "html": page} {
			if !containsEscaped(text, finding.Summary) {
				t.Errorf("%s: the %s page dropped the sentence %q", name, surface, finding.Summary)
			}
		}
		if strings.Contains(terminal, "not set (default):") ||
			strings.Contains(markdown, "not set *(default)*:") ||
			strings.Contains(page, "default</span>:") {
			t.Errorf("%s: a finding that says more than its name went into the paragraph", name)
		}
	}
}

// TestTheParagraphDoesNotWidenTheRowsAboveIt is the reason the columns are
// measured after the split. A long absent name measured with the rows would
// pad every set variable out to its length.
func TestTheParagraphDoesNotWidenTheRowsAboveIt(t *testing.T) {
	terminal, _, _ := pagesFor(t, withContext(present("A", "1"), absent("NODE_TLS_REJECT_UNAUTHORIZED")))

	if !strings.Contains(terminal, "\n      A is set  detected  1\n") {
		t.Errorf("the row of a set variable is padded for a name that is no longer among the rows:\n%s", terminal)
	}
}

// TestTheParagraphBreaksBetweenNamesAndLinesUpAfterItsLabel is the page width
// rule of ADR109 applied to the new paragraph: a name is data, so the list
// breaks between names, every line fits the page, and every continuation starts
// where the first name did.
func TestTheParagraphBreaksBetweenNamesAndLinesUpAfterItsLabel(t *testing.T) {
	var findings []report.Finding
	var names []string
	for i := range 30 {
		name := fmt.Sprintf("SOME_%s_VARIABLE_%02d", strings.Repeat("LONG_", i%4), i)
		names = append(names, name)
		findings = append(findings, absent(name))
	}
	terminal, _, _ := pagesFor(t, withContext(findings...))

	const lead = "      not set (default): "
	start := strings.Index(terminal, lead)
	if start < 0 {
		t.Fatalf("no paragraph on the page:\n%s", terminal)
	}
	var paragraph []string
	for i, line := range strings.Split(terminal[start:], "\n") {
		if i > 0 && !strings.HasPrefix(line, strings.Repeat(" ", len(lead))) {
			break
		}
		paragraph = append(paragraph, line)
	}
	if len(paragraph) < 2 {
		t.Fatalf("thirty names fit on one line, so this check proves nothing:\n%s", terminal)
	}

	var read []string
	for i, line := range paragraph {
		if widthOf(line) > pageWidth {
			t.Errorf("line %d of the paragraph is %d wide, past the page: %q", i+1, widthOf(line), line)
		}
		if i > 0 && (len(line) <= len(lead) || line[len(lead)] == ' ') {
			t.Errorf("line %d of the paragraph does not start where the first name did: %q", i+1, line)
		}
		for _, word := range strings.Fields(strings.TrimPrefix(line, lead)) {
			read = append(read, strings.TrimSuffix(word, ","))
		}
	}
	if strings.Join(read, " ") != strings.Join(names, " ") {
		t.Errorf("the paragraph does not read back as the names in their order:\n got %v\nwant %v", read, names)
	}
}

// TestANameInTheParagraphIsEscapedOnEveryPage keeps the paragraph inside the
// rule every other piece of text on these pages follows: what came from the
// machine is shown, never acted on.
func TestANameInTheParagraphIsEscapedOnEveryPage(t *testing.T) {
	name := "BAD\x1b[31m<b>"
	terminal, markdown, page := pagesFor(t, withContext(absent(name)))

	// Built in two halves so no editor turns the escape back into the byte.
	shown := "BAD" + `\` + "u001b"
	for surface, text := range map[string]string{"terminal": terminal, "markdown": markdown, "html": page} {
		if strings.ContainsRune(text, 0x1b) {
			t.Errorf("the %s page carries the escape byte from a name", surface)
		}
		// Through containsEscaped, because markdown escapes the backslash of the
		// escaped spelling once more, and that is correct.
		if !containsEscaped(text, shown) {
			t.Errorf("the %s page dropped the name instead of showing it escaped:\n%s", surface, text)
		}
	}
	if strings.Contains(page, "<b>") || !strings.Contains(page, "&lt;b&gt;") {
		t.Errorf("a name in the paragraph became markup on the HTML page:\n%s", page)
	}
	if strings.Contains(markdown, "[31m<b>") {
		t.Errorf("a name in the paragraph reached the markdown page unescaped:\n%s", markdown)
	}
}
