package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// markdownOf renders one finding and hands back the page.
func markdownOf(t *testing.T, finding report.Finding) string {
	t.Helper()
	document := everyStatusReport()
	document.Layers = []report.LayerResult{{
		ID:       layer.TCP,
		Status:   status.Pass,
		Detail:   "one layer carrying one finding",
		Findings: []report.Finding{finding},
	}}

	var b bytes.Buffer
	if err := (Markdown{}).Render(&b, document); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	return b.String()
}

// TestSomebodyElsesTextCannotBecomeMarkup is the reason this renderer escapes at
// all, and it is a security property rather than a cosmetic one.
//
// THE DIFFERENCE FROM THE TERMINAL IS WHERE THE HARM LANDS. There, an escape
// sequence makes a console DO something. Here the document is turned into HTML
// by whatever the reader pastes it into - a code host, a ticket tracker - so a
// host name spelled as a link becomes a LINK, pointing wherever the machine
// being diagnosed said. That machine is the thing under suspicion.
//
// EVERY VALUE BELOW IS A PLAUSIBLE ONE. A certificate subject is free text from
// somebody else's certificate authority, an environment variable holds whatever
// was exported, and a PAC file names hosts of its own choosing. None of this
// needs an attacker to be exotic.
func TestSomebodyElsesTextCannotBecomeMarkup(t *testing.T) {
	for _, c := range []struct {
		name    string
		summary string
		escaped []string
	}{
		{
			name:    "a link",
			summary: "the issuer is [click here](http://elsewhere.example) and nothing else",
			escaped: []string{"\\[click here\\]"},
		},
		{
			name:    "raw markup",
			summary: "the issuer is <img src=x onerror=alert(1)> and nothing else",
			escaped: []string{"\\<img src=x onerror=alert(1)\\>"},
		},
		{
			name:    "a table row of its own",
			summary: "the issuer is a|b|c and nothing else",
			escaped: []string{"a\\|b\\|c"},
		},
		{
			name:    "a code fence",
			summary: "the issuer is ``` and nothing else",
			escaped: []string{"\\`\\`\\`"},
		},
	} {
		page := markdownOf(t, report.Finding{
			Kind:       report.FindingTCPConnect,
			Summary:    c.summary,
			Source:     report.SourceDetected,
			TCPConnect: &report.TCPConnect{Address: "192.0.2.10", Port: 443, Outcome: report.OutcomeConnected},
		})
		// ASSERTED AS THE ESCAPED FORM RATHER THAN AS THE ABSENCE OF THE RAW
		// ONE, and the first draft of this test got that wrong in a way worth
		// keeping: a backslash placed BEFORE a character leaves the raw string
		// intact as a substring, so "does the page contain <img" is true of a
		// page that escaped it correctly. Asking for the escaped spelling is the
		// only form of this question that can fail for the right reason.
		for _, want := range c.escaped {
			if !strings.Contains(page, want) {
				t.Errorf("%s: the page does not carry %q, so somebody else's text was not neutralised",
					c.name, want)
			}
		}
		// AND IT IS STILL THERE TO READ. Escaping that dropped the value would
		// pass the check above and lose the evidence, which is the failure this
		// project calls quiet truncation - the same reason visible() escapes
		// rather than deletes.
		if !strings.Contains(page, "and nothing else") {
			t.Errorf("%s: the value was not escaped but removed", c.name)
		}
	}
}

// TestAValueHoldingBackticksStaysInsideItsCodeSpan pins the one escape a code
// span cannot ignore.
//
// A code span is safe from everything except the backtick that ends it, so a
// value carrying one has to be fenced by a longer run. Without this a host name
// with a backtick in it would close its span and the rest of the line would be
// markup again - the same hole the escaping above closes, arriving through the
// mechanism meant to make escaping unnecessary.
func TestAValueHoldingBackticksStaysInsideItsCodeSpan(t *testing.T) {
	for _, value := range []string{"a`b", "a``b", "`leading", "trailing`", "```"} {
		span := mdCode(value)
		fence := span[:strings.IndexFunc(span, func(r rune) bool { return r != '`' })]
		if fence == "" {
			t.Fatalf("%q produced no fence: %q", value, span)
		}
		if strings.Contains(strings.TrimSuffix(strings.TrimPrefix(span, fence), fence), fence) {
			t.Errorf("%q: the value contains its own fence %q, so the span ends early: %q", value, fence, span)
		}
	}
}

// TestARemediationCommandSurvivesItsOwnBackticks is the same rule for the one
// line this program asks somebody to run.
//
// IT MATTERS MORE HERE THAN ANYWHERE ELSE ON THE PAGE. A command whose block
// closed early would not merely render badly - the remainder would be read as
// markup, and what a person copied would be a truncated command they then run
// with elevated rights.
func TestARemediationCommandSurvivesItsOwnBackticks(t *testing.T) {
	block := fencedBlock("keytool -import -file ```odd```.crt")
	lines := strings.Split(strings.TrimSuffix(block, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("a one line command produced %d line(s): %q", len(lines), block)
	}
	if lines[0] != lines[2] {
		t.Errorf("the block opens with %q and closes with %q", lines[0], lines[2])
	}
	if strings.Contains(lines[1], lines[0]) {
		t.Errorf("the command contains its own fence %q, so the block ends early: %q", lines[0], lines[1])
	}
}

// TestAnEnvironmentVariableIsNotDisfiguredByEscaping is the other half of the
// escaping decision, and it is a test because the first draft got it wrong.
//
// Escaping the underscore turned HTTP_PROXY into HTTP\_PROXY on twenty-three
// consecutive lines of a real run. Markdown does not emphasise an underscore
// inside a word, so that was a page made harder to read in exchange for
// nothing - and a report people stop reading is a report that settles nothing.
func TestAnEnvironmentVariableIsNotDisfiguredByEscaping(t *testing.T) {
	page := markdownOf(t, report.Finding{
		Kind:                report.FindingEnvironmentVariable,
		Summary:             "NODE_TLS_REJECT_UNAUTHORIZED is set",
		Source:              report.SourceDetected,
		EnvironmentVariable: &report.EnvironmentVariable{Name: "NODE_TLS_REJECT_UNAUTHORIZED", Value: "0", Set: true},
	})
	if !strings.Contains(page, "NODE_TLS_REJECT_UNAUTHORIZED is set") {
		t.Errorf("the variable name is not readable on the page:\n%s", page)
	}
}
