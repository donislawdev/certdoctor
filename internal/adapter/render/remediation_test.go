package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// The remediation command on both surfaces.
//
// IT GETS ITS OWN FILE BECAUSE IT IS THE ONE THING THIS PROGRAM PRINTS THAT
// SOMEBODY RUNS. Everything else here is a description, wrong at worst; a
// command is wrong AND executed.

// refusingRow is a store that refused the chain for want of a signer, with the
// command that would repair it. The account name is invented, as the guard in
// internal/guard requires of any path in this repository.
func refusingRow() report.Finding {
	no := false
	return report.Finding{
		Kind:    report.FindingTrustStore,
		Summary: "java jdk-25 does NOT trust the presented chain (158 anchors)",
		Source:  report.SourceDetected,
		TrustStore: &report.TrustStore{
			Runtime:              "java",
			Instance:             `C:\Users\jdoe\OpenJDK\jdk-25`,
			Variant:              "jdk",
			Architecture:         "x64",
			StorePath:            `C:\Users\jdoe\OpenJDK\jdk-25\lib\security\cacerts`,
			StoreForm:            report.StoreFile,
			TrustAnchorCount:     158,
			TrustsPresentedChain: &no,
			TrustFailure:         report.UnknownAuthority,
			SelectedBy:           []string{"JAVA_HOME"},
			Fix: &report.Fix{
				Command: `"C:\Users\jdoe\OpenJDK\jdk-25\bin\keytool" -importcert -trustcacerts ` +
					`-keystore "C:\Users\jdoe\OpenJDK\jdk-25\lib\security\cacerts" -storepass changeit ` +
					`-alias <alias> -file <certificate.pem>`,
				Placeholders:      []string{"<alias>", "<certificate.pem>"},
				RequiresElevation: true,
				Elevation:         "this store is outside this account's own files",
				Caveat:            "installing a newer build of this runtime brings its own store",
			},
		},
	}
}

func pageWith(t *testing.T, findings ...report.Finding) string {
	t.Helper()
	r := everyStatusReport()
	for i := range r.Layers {
		if r.Layers[i].ID == layer.TrustMatrix {
			r.Layers[i].Findings = findings
		}
	}
	var page strings.Builder
	if err := (Terminal{}).Render(&page, r); err != nil {
		t.Fatalf("the terminal renderer failed: %v", err)
	}
	return page.String()
}

// TestTheWarningComesBeforeTheCommand is the whole of docs/20 rule 5, and the
// ORDER is the rule rather than the presence.
//
// A warning printed underneath is a warning read after the command has been
// copied. Somebody scanning a report takes the line beginning "run:" and stops.
func TestTheWarningComesBeforeTheCommand(t *testing.T) {
	page := pageWith(t, refusingRow())

	warning := strings.Index(page, "needs elevated rights")
	command := strings.Index(page, "run: ")
	if warning < 0 {
		t.Fatal("a command that edits a shared store printed no warning at all")
	}
	if command < 0 {
		t.Fatal("the command never reached the page")
	}
	if warning > command {
		t.Error("the warning about elevated rights is printed AFTER the command it applies to")
	}
}

// TestTheCommandReachesTheTerminalWhole - a command cut to fit a column is a
// command somebody pastes in two pieces.
func TestTheCommandReachesTheTerminalWhole(t *testing.T) {
	finding := refusingRow()
	page := pageWith(t, finding)

	if !strings.Contains(page, finding.TrustStore.Fix.Command) {
		t.Error("the command does not appear in the page in one piece")
	}
	// NAMED RATHER THAN COUNTED. "Two things to replace" makes somebody hunt for
	// them; the words themselves can be searched for in the line above.
	for _, placeholder := range finding.TrustStore.Fix.Placeholders {
		if !strings.Contains(page, placeholder) {
			t.Errorf("the placeholder %q is never named on the page", placeholder)
		}
	}
	if !strings.Contains(page, finding.TrustStore.Fix.Caveat) {
		t.Error("the caveat never reaches the page, so somebody learns it from the certificate disappearing")
	}
}

// THE POSITIVE TWIN, INVERTED - OBS56. Every test above asserts that a command is
// printed, and a renderer that printed one for every row would pass all of them.
// A green matrix is the ordinary case and must stay quiet.
func TestARowWithNothingToFixPrintsNoCommand(t *testing.T) {
	page := pageWith(t, bodyFixtures[report.FindingTrustStore])

	for _, unwanted := range []string{"run: ", "needs elevated rights", "replace first"} {
		if strings.Contains(page, unwanted) {
			t.Errorf("a store that trusts the chain was given a %q line", unwanted)
		}
	}
}

// TestAnEscapeSequenceInAStorePathCannotRewriteTheCommandLine.
//
// The path is read off somebody's machine, and a directory can be named with a
// control byte in it. That byte would otherwise reach the terminal in the ONE
// line a person is about to select and run.
func TestAnEscapeSequenceInAStorePathCannotRewriteTheCommandLine(t *testing.T) {
	finding := refusingRow()
	finding.TrustStore.Fix.Command = "keytool -keystore \"C:\\x\x1b[2Kmalicious\""
	page := pageWith(t, finding)

	if strings.Contains(page, "\x1b[") {
		t.Error("an escape sequence from a path reached the page unescaped")
	}
}

// TestTheCommandSurvivesTheRoundTripThroughJSON checks the machine surface, and
// the two fields a consumer branches on.
func TestTheCommandSurvivesTheRoundTripThroughJSON(t *testing.T) {
	r := everyStatusReport()
	for i := range r.Layers {
		if r.Layers[i].ID == layer.TrustMatrix {
			r.Layers[i].Findings = []report.Finding{refusingRow()}
		}
	}

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if err := ValidateDocument(document); err != nil {
		t.Fatalf("a document carrying a command does not match its own schema: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	body := bodyOfKind(decoded, string(report.FindingTrustStore))
	if body == nil {
		t.Fatal("no trust_store body in the document")
	}
	if got := body["trust_failure"]; got != string(report.UnknownAuthority) {
		t.Errorf("trust_failure is %v, and a consumer branches on it rather than on the sentence", got)
	}
	fix, ok := body["fix"].(map[string]any)
	if !ok {
		t.Fatalf("fix is %v rather than an object", body["fix"])
	}
	if fix["requires_elevation"] != true {
		t.Error("requires_elevation did not survive, and it is the field docs/20 rule 5 turns on")
	}
	// NEVER NULL. An empty array says the command is ready to paste; a null would
	// say nobody worked it out, and a consumer cannot tell those apart.
	placeholders, ok := fix["placeholders"].([]any)
	if !ok || len(placeholders) != 2 {
		t.Errorf("placeholders came out as %v, want two entries in an array", fix["placeholders"])
	}
}

// A green row carries two nulls rather than two absent keys, so a consumer
// reading the document knows the questions were asked.
func TestARowWithNothingToFixCarriesNullsRatherThanNothing(t *testing.T) {
	r := everyStatusReport()
	for i := range r.Layers {
		if r.Layers[i].ID == layer.TrustMatrix {
			r.Layers[i].Findings = []report.Finding{bodyFixtures[report.FindingTrustStore]}
		}
	}

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	body := bodyOfKind(decoded, string(report.FindingTrustStore))
	for _, key := range []string{"fix", "trust_failure"} {
		value, present := body[key]
		if !present {
			t.Errorf("%q is absent from a green row, and an absent key reads as a field nobody has", key)
		}
		if value != nil {
			t.Errorf("%q on a green row is %v, want null", key, value)
		}
	}
}
