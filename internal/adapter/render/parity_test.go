package render

import (
	"bytes"
	"html"
	"strconv"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// THIS FILE IS THE PRODUCT OF THE SLICE THAT ADDED THE SECOND DOCUMENT SURFACE,
// AND THE RENDERER IS THE CHEAPER HALF.
//
// Inviolable rule 12 says every finding can be expressed on the terminal, in the
// markdown report and in the machine readable document. Until this file existed
// that rule was PROSE: three surfaces walked the same report independently, and
// nothing anywhere asked whether they still said the same things. A rule nobody
// checks is a rule that is true until the first person in a hurry.
//
// IT ASKS ABOUT PRESENCE, NOT ABOUT BYTES. The three surfaces are for different
// readers and are meant to differ - the terminal measures columns and paints
// them, the document carries nanoseconds a person cannot use, markdown fences a
// command so it can be copied in one gesture. What must not differ is WHAT IS
// THERE: a fact a reader acts on cannot be on two surfaces and missing from the
// third, because whoever reads the third would then be reading a report that
// quietly settled less than it measured.

// surface is one way of turning a report into bytes somebody reads.
//
// THE LIST IS COMPLETE AS OF THE SLICE THAT ADDED HTML. It was two entries and
// a test saying the third was declared and not built; that test has been removed
// because it did its job - somebody flipping the built bit was told there was a
// list here waiting for them. A fourth surface would need the same treatment,
// and the shape to copy is the one that just retired.
type surface struct {
	name   string
	render func(report.Report) (string, error)
}

func surfaces() []surface {
	return []surface{
		{"terminal", func(r report.Report) (string, error) {
			var b bytes.Buffer
			err := Terminal{}.Render(&b, r)
			return b.String(), err
		}},
		{"markdown", func(r report.Report) (string, error) {
			var b bytes.Buffer
			err := Markdown{}.Render(&b, r)
			return b.String(), err
		}},
		{"html", func(r report.Report) (string, error) {
			var b bytes.Buffer
			err := HTML{}.Render(&b, r)
			return b.String(), err
		}},
		{"json", func(r report.Report) (string, error) {
			document, err := Encode(r)
			return string(document), err
		}},
	}
}

// TestEveryFindingKindReachesEverySurface is the guard rule 12 asks for.
//
// IT BUILDS ITSELF FROM THE REGISTRY. One report is assembled carrying one
// finding of EVERY declared kind, so a kind added later cannot reach a release
// without somebody meeting this test - the same self-building shape the schema
// guard beside it already uses, and the same one the testbed uses for benches
// whose reader does not exist yet.
//
// WHAT IT CHECKS PER KIND is the value that kind exists to carry: the address
// for a connection, the fingerprint for a certificate, the endpoint for a
// challenge. A kind whose distinguishing value appears on two surfaces and not
// the third is a finding a reader cannot act on wherever they happen to be
// looking - which is the whole failure rule 12 describes.
func TestEveryFindingKindReachesEverySurface(t *testing.T) {
	// THE VALUE PER KIND IS NAMED HERE RATHER THAN DERIVED, and the difference
	// matters: derived from the body it would pass by construction, because both
	// sides would be reading the same field. Written down, it is a claim about
	// what this kind is FOR, and a renderer that stops carrying it fails.
	wanted := map[report.FindingKind][]string{
		report.FindingEnvironmentVariable: {"HTTPS_PROXY", "proxy.example:8080"},
		report.FindingNameResolution:      {"example.com", "192.0.2.10"},
		report.FindingTCPConnect:          {"192.0.2.10"},
		// THE FINGERPRINT IS HERE BECAUSE THE MUTATION REGISTER SAID IT WAS NOT.
		// With only the protocol version named, deleting the whole chain block
		// from a renderer left this test green - and the chain is the evidence
		// somebody came to the report for.
		report.FindingTLSHandshake: {"TLS 1.3", leafFingerprint},
		// THE FINGERPRINT AND THE STORES ARE THE EVIDENCE HALF, and this row is
		// the one place in the report where a wrong answer is an accusation -
		// inviolable rule 21. A surface that showed "this looks like
		// interception" without showing which stores hold the signer and which
		// refuse it would be making that accusation without its evidence.
		report.FindingSigningAuthority: {
			"Example Root CA", leafFingerprint, "curl /usr/bin/curl", "java jdk-25",
		},
		report.FindingProxyStack: {"proxy.example:8080"},
		// THE ASKED NAMES ARE THE CHANNEL NO GUARD IN THIS PROGRAM CAN SEE. The
		// allowed set answers "may this run connect there" and the resolver is
		// on it, so a hostile PAC file chooses not a destination but a QUESTION.
		// Printing what it asked is the whole of the answer, so a surface that
		// stopped printing it would be the one place that channel goes unwatched.
		report.FindingPACScript: {"wpad.example", "socks.example:1080", "intranet.example"},
		// THE CAVEAT, for the reason the terminal grew one: these sentences are
		// WHY a verdict came out as it did, and a surface without them shows a
		// verdict that looks arbitrary.
		report.FindingProxyChallenge: {"proxy.example:8080", "Basic", "cut off"},

		// THESE TWO ARE ASKED ABOUT THEIR SUMMARY AND NOT THEIR BODY, AND
		// THAT IS A MEASUREMENT THIS TEST MADE RATHER THAN A CONVENIENCE.
		//
		// findingValue - the function both human surfaces call to put a body
		// beside a summary - has a case for seven kinds and NOT for these two.
		// So everything a trust store row carries beyond its summary (the store
		// path, the anchor count, what selected it) and everything a divergence
		// row carries (the class token, the stacks compared) reaches a person
		// ONLY through the sentence the core wrote.
		//
		// It is not a rule 12 violation: on a real run those sentences carry the
		// facts - measured, "java C:\...\jdk-25 trusts the presented chain (110
		// anchors)". It is a COUPLING, and the fixtures here are what make it
		// visible, because their summaries are shorter than the real ones. The
		// day somebody shortens a summary in the core, the terminal quietly
		// stops carrying a path and nothing anywhere goes red. OBS138.
		report.FindingTrustStore:      {"OpenJDK 25"},
		report.FindingStackDivergence: {"one stack names a proxy and another names none"},
	}

	if len(wanted) != len(report.AllFindingKinds) {
		t.Fatalf("this test knows %d kind(s) and the registry declares %d - a kind was added "+
			"without anybody saying what a reader takes from it", len(wanted), len(report.AllFindingKinds))
	}

	for _, kind := range report.AllFindingKinds {
		values, known := wanted[kind]
		if !known {
			t.Errorf("%s: the registry declares this kind and this test does not know what it carries", kind)
			continue
		}
		fixture, present := bodyFixtures[kind]
		if !present {
			t.Errorf("%s: no fixture, so no surface can be asked about it", kind)
			continue
		}

		document := parityReport(fixture)
		for _, one := range surfaces() {
			rendered, err := one.render(document)
			if err != nil {
				t.Errorf("%s: the %s surface refused to render it: %v", kind, one.name, err)
				continue
			}
			for _, value := range values {
				if !containsEscaped(rendered, value) {
					t.Errorf("%s: the %s surface does not carry %q, so a reader on that surface "+
						"cannot act on this finding", kind, one.name, value)
				}
			}
		}
	}
}

// TestEverySurfaceCarriesWhatTheRunItselfSays covers the parts of a report that
// belong to no finding, and it is a separate test because it fails for a
// different reason.
//
// A finding lost from one surface is a fact about the diagnosed machine going
// missing. THESE are the run saying what it is and what it concluded, and a
// surface without them is not a shorter report - it is an anonymous one. The
// verdict sentence in particular is the product: everything else on the page
// exists to support the one line at the top.
func TestEverySurfaceCarriesWhatTheRunItselfSays(t *testing.T) {
	document := parityReport(bodyFixtures[report.FindingTCPConnect])

	for _, one := range surfaces() {
		rendered, err := one.render(document)
		if err != nil {
			t.Fatalf("the %s surface refused to render: %v", one.name, err)
		}
		for _, value := range []string{
			document.Tool.Name,
			document.Tool.Version,
			document.Run.Target,
			document.Verdict.Sentence,
			// THE NUMBER AND NOT THE NAME, and the difference is a decision.
			// The machine readable document carries exit_code as an integer
			// only; the two human surfaces print the word beside it. That is a
			// rendering of the number rather than a second fact - a consumer
			// maps 5 to whatever it calls inconclusive - so requiring the word
			// everywhere would be requiring a label, not a measurement.
			strconv.Itoa(document.Verdict.ExitCode.Int()),
			// The layer identifier and its status word. A page that showed
			// findings without saying which layer reached which verdict would
			// leave a reader to guess the one thing the report is organised by.
			"L3",
			"PASS",
			// What the run did NOT do. Inviolable rule 1: a claim made by
			// silence cannot be told from a section somebody forgot to write.
			"a note this run wrote about itself",
		} {
			if !containsEscaped(rendered, value) {
				t.Errorf("the %s surface does not carry %q", one.name, value)
			}
		}
	}
}

// TestNoSurfaceInventsAVerdictWord keeps the four statuses closed across all of
// them - inviolable rule 20.
//
// IT IS HERE RATHER THAN BESIDE ONE RENDERER because the risk it covers only
// exists once there is more than one: a second surface is exactly where somebody
// writes "OK" because it fits the column better, and the report then has five
// words for four states depending on where it is read.
func TestNoSurfaceInventsAVerdictWord(t *testing.T) {
	document := parityReport(bodyFixtures[report.FindingTCPConnect])

	for _, one := range surfaces() {
		rendered, err := one.render(document)
		if err != nil {
			t.Fatalf("the %s surface refused to render: %v", one.name, err)
		}
		for _, forbidden := range []string{"OK", "GOOD", "ERROR", "FAILED", "SUCCESS", "SKIPPED"} {
			if strings.Contains(rendered, forbidden) {
				t.Errorf("the %s surface uses the word %q, which is not one of the four statuses",
					one.name, forbidden)
			}
		}
	}
}

// containsEscaped asks whether a surface carries a value, allowing for the
// escaping each one does on its way out.
//
// IT CANNOT BE strings.Contains ALONE, and working out why is most of what
// this file is for. Every surface escapes text that came from the diagnosed
// machine, and each escapes differently: the machine readable document turns a
// quote into \" because JSON says so, and markdown puts a backslash before a
// bracket because a bracket would otherwise make a link. A test comparing raw
// substrings would therefore report a value as MISSING when it is present and
// correctly escaped - and somebody would then "fix" a renderer by removing its
// escaping, which is the one change here that is a security defect rather than
// a cosmetic one.
//
// So the comparison drops backslashes from both sides before looking, and
// resolves HTML entities on the way in. That is blunt, and it is blunt in the
// safe direction: it can only ever make this test more willing to say a value is
// present, and every other assertion in this file is about presence rather than
// absence. The one test that asserts ABSENCE - the closed status vocabulary -
// deliberately does not use it.
//
// THE ENTITY HALF ARRIVED WITH THE THIRD SURFACE AND IS NOT YET LOAD-BEARING.
// None of the values below contains an ampersand or an angle bracket today, so
// dropping it would change no result this afternoon - which is exactly the
// argument for putting it in now rather than the argument against. The day
// somebody adds a fixture holding a "&", the failure without this would be a
// renderer reported as LOSING a value it escaped correctly, and the obvious fix
// for that reading is to remove the escaping.
func containsEscaped(surface, value string) bool {
	strip := func(s string) string {
		return strings.ReplaceAll(html.UnescapeString(s), `\`, "")
	}
	return strings.Contains(strip(surface), strip(value))
}

// parityReport is one report carrying one finding, and everything else a report
// always has.
//
// THE LAYER IS L3 FOR EVERY KIND ON PURPOSE. Which layer produces which finding
// is the orchestrator's business and is checked where that lives; this file asks
// only whether a finding placed in a report comes out the other side, and
// varying the layer would add a second reason for a failure without adding a
// second thing tested.
func parityReport(finding report.Finding) report.Report {
	document := everyStatusReport()
	document.Layers = []report.LayerResult{{
		ID:       layer.TCP,
		Status:   status.Pass,
		Detail:   "one layer carrying one finding",
		Findings: []report.Finding{finding},
	}}
	document.Notes = []report.Note{{
		Kind:   report.NoteSkipped,
		Layer:  layer.Report,
		Detail: "a note this run wrote about itself",
	}}
	return document
}
