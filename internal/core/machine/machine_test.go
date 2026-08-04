package machine

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// fixed builds a lookup over a map, which is what every test here uses instead
// of the real environment.
func fixed(env map[string]string) Lookup {
	return func(name string) (string, bool) {
		value, set := env[name]
		return value, set
	}
}

// findingNamed returns the finding for one variable, failing the test if the
// layer did not report it at all. A missing row is the failure that would
// otherwise read as a passing assertion about nothing.
func findingNamed(t *testing.T, result Result, name string) report.Finding {
	t.Helper()
	for _, finding := range result.Findings {
		if finding.EnvironmentVariable != nil && finding.EnvironmentVariable.Name == name {
			return finding
		}
	}
	t.Fatalf("no finding for %s - the layer did not report it", name)
	return report.Finding{}
}

// TestTheApprovedListIsExactlyTwentyOneDistinctNames pins the list.
//
// The number is approved rather than convenient - D11 raised it from nineteen
// when the two container hints joined - so a variable appearing or vanishing is
// a decision, not an edit. The duplicate half matters just as much and is
// invisible by eye at this length: the same name twice produces two identical
// rows in every report, which reads as the two spellings of a variable rather
// than as a mistake.
func TestTheApprovedListIsExactlyTwentyOneDistinctNames(t *testing.T) {
	if len(variables) != 21 {
		t.Fatalf("the approved list holds twenty-one variables, this one holds %d", len(variables))
	}
	seen := map[string]bool{}
	for _, name := range variables {
		if seen[name] {
			t.Errorf("%s is declared twice, which would render as two rows saying the same thing", name)
		}
		seen[name] = true
	}
}

// TestBothSpellingsAreCarriedSeparately is the guard on the thing this layer is
// most likely to get quietly wrong.
//
// HTTP_PROXY and http_proxy are not two spellings of one thing. curl honours the
// http one in lower case only, so on Linux they are separate variables with
// different effects, while on Windows the environment is case insensitive and
// they are one. Folding them into a single row would produce a sentence that is
// true and misleading at the same time, on both systems.
func TestBothSpellingsAreCarriedSeparately(t *testing.T) {
	for _, pair := range [][2]string{
		{"HTTP_PROXY", "http_proxy"},
		{"HTTPS_PROXY", "https_proxy"},
		{"ALL_PROXY", "all_proxy"},
		{"NO_PROXY", "no_proxy"},
	} {
		upper, lower := pair[0], pair[1]
		result := Read(fixed(map[string]string{upper: "http://upper.example:8080"}))

		if got := findingNamed(t, result, upper).EnvironmentVariable; !got.Set {
			t.Errorf("%s was set and the layer did not report it", upper)
		}
		if got := findingNamed(t, result, lower).EnvironmentVariable; got.Set {
			t.Errorf("%s was not set and the layer reported it as set - the spellings were merged", lower)
		}
	}
}

// TestTheThreeStatesAreToldApart covers the difference the value column cannot
// show.
//
// A renderer prints a value only when there is one, so absent and set-to-nothing
// both print an empty column. Some tools stop proxying on an empty value and
// carry on when it is absent, so the difference decides the diagnosis - and the
// summary is the only place it can survive.
func TestTheThreeStatesAreToldApart(t *testing.T) {
	result := Read(fixed(map[string]string{
		"HTTPS_PROXY": "http://proxy.example:8080",
		"NO_PROXY":    "",
	}))

	cases := []struct {
		name        string
		wantSet     bool
		wantValue   string
		wantSummary string
		wantSource  report.Source
	}{
		{"HTTPS_PROXY", true, "http://proxy.example:8080", "HTTPS_PROXY is set", report.SourceDetected},
		{"NO_PROXY", true, "", "NO_PROXY is set to nothing", report.SourceDetected},
		{"HTTP_PROXY", false, "", "HTTP_PROXY is not set", report.SourceDefault},
	}
	for _, c := range cases {
		finding := findingNamed(t, result, c.name)
		variable := finding.EnvironmentVariable
		switch {
		case variable.Set != c.wantSet:
			t.Errorf("%s: set is %v, want %v", c.name, variable.Set, c.wantSet)
		case variable.Value != c.wantValue:
			t.Errorf("%s: value is %q, want %q", c.name, variable.Value, c.wantValue)
		case finding.Summary != c.wantSummary:
			t.Errorf("%s: summary is %q, want %q", c.name, finding.Summary, c.wantSummary)
		case finding.Source != c.wantSource:
			t.Errorf("%s: source is %q, want %q", c.name, finding.Source, c.wantSource)
		}
	}
}

// TestTheSummariesOfTheThreeStatesAreAllDifferent is the other half of the test
// above, and it is the half that catches a well meant tidy-up.
//
// Two of those three sentences could be made identical without any assertion
// above failing on the state it happens to check, and the report would then show
// two different machines as the same one. The three have to be distinguishable
// from each other, not merely correct one at a time.
func TestTheSummariesOfTheThreeStatesAreAllDifferent(t *testing.T) {
	absent := summaryFor("X", "", false)
	empty := summaryFor("X", "", true)
	filled := summaryFor("X", "value", true)

	if absent == empty {
		t.Errorf("a variable that is absent and one set to nothing read identically: %q", absent)
	}
	if empty == filled {
		t.Errorf("a variable set to nothing and one with a value read identically: %q", empty)
	}
	for _, summary := range []string{absent, empty, filled} {
		if !strings.Contains(summary, "X") {
			t.Errorf("the summary %q does not name the variable, so a row could not be read on its own", summary)
		}
	}
}

// TestTheValueIsHandedOverRaw is ADR18 seen from the layer's side.
//
// The layer does not mask and must not: a Redaction holds unsynchronised maps
// and the fan-out this program is heading for lives inside a layer. Masking is
// the assembly path's job, which means a layer that helpfully cleaned its own
// evidence would be masking it twice and hiding whether the other half works.
//
// The guard on the import is separate and lives in internal/guard. This one says
// the value actually arrives untouched, which no import check can see.
func TestTheValueIsHandedOverRaw(t *testing.T) {
	const raw = "http://someone:a-secret@proxy.example:8080"
	result := Read(fixed(map[string]string{"HTTPS_PROXY": raw}))

	variable := findingNamed(t, result, "HTTPS_PROXY").EnvironmentVariable
	if variable.Value != raw {
		t.Errorf("the layer handed over %q, want the raw value %q", variable.Value, raw)
	}
	if variable.CarriedCredentials {
		t.Error("the layer answered whether credentials were removed - that is filled in where the masking happens, from the same text, so the two cannot disagree")
	}
}

// TestNothingIsReportedAsSetWithoutSomethingSettingIt refuses a port that
// answers two things at once.
//
// The real environment never hands back a value alongside "not set", but a
// stand-in for it can, and the finding built from that answer breaks its own
// contract - which costs the layer its entire row and replaces it with a note
// about a broken contract. The absent half is the half that decides.
func TestNothingIsReportedAsSetWithoutSomethingSettingIt(t *testing.T) {
	confused := func(string) (string, bool) { return "left over", false }

	for _, finding := range Read(confused).Findings {
		if breach := finding.Breach(); breach != "" {
			t.Fatalf("the layer built a finding that %s", breach)
		}
		if variable := finding.EnvironmentVariable; variable.Value != "" {
			t.Errorf("%s is not set and carries the value %q", variable.Name, variable.Value)
		}
	}
}

// TestEveryFindingIsWellFormed asks the contract itself rather than restating it.
//
// Breach is what the orchestrator and the report validator both call, so passing
// it here means these findings survive the two places that can throw them away.
func TestEveryFindingIsWellFormed(t *testing.T) {
	result := Read(fixed(map[string]string{"JAVA_TOOL_OPTIONS": "-Dtrustpassword=hunter2", "container": "podman"}))

	if len(result.Findings) != len(variables) {
		t.Fatalf("the layer reported %d findings for %d variables", len(result.Findings), len(variables))
	}
	for i, finding := range result.Findings {
		if breach := finding.Breach(); breach != "" {
			t.Errorf("the finding at position %d %s", i, breach)
		}
		if finding.Kind != report.FindingEnvironmentVariable {
			t.Errorf("the finding at position %d is of kind %q", i, finding.Kind)
		}
	}
}

// TestTheOrderIsTheDeclaredOrder is property five applied to this layer: the
// same input has to give the same bytes, whatever the map iteration did.
func TestTheOrderIsTheDeclaredOrder(t *testing.T) {
	env := map[string]string{"HTTPS_PROXY": "a", "PIP_CERT": "b", "container": "c", "NO_PROXY": "d"}

	// Repeated, because a single comparison would pass by luck about as often as
	// a map has orderings. Twenty is the same count the orchestrator's own row
	// order test uses.
	for run := 0; run < 20; run++ {
		findings := Read(fixed(env)).Findings
		for i, name := range variables {
			if got := findings[i].EnvironmentVariable.Name; got != name {
				t.Fatalf("run %d, position %d: reported %s, the list declares %s", run, i, got, name)
			}
		}
	}
}

// TestAReadThatLookedReportsAnEmptyListRatherThanNoList is ADR20 from the
// producing side.
//
// Nil and empty encode identically in Go until something asks, and the thing
// that asks is the JSON encoder. Nil renders as null, which says nobody looked;
// an empty array says we looked and there was nothing. This layer always looks,
// so its slice must never be nil - and a declaration that built it with var
// would pass every count based test while flipping that claim.
func TestAReadThatLookedReportsAnEmptyListRatherThanNoList(t *testing.T) {
	result := Read(fixed(nil))
	if result.Findings == nil {
		t.Fatal("the layer looked and reported no list at all, which renders as null and claims nobody looked")
	}
	if result.Status != status.Pass {
		t.Errorf("reading an environment with nothing set is a successful read, got %s", result.Status)
	}
	if result.Reason != "" {
		t.Errorf("a pass carried the reason %q, and only a problem takes one", result.Reason)
	}
}

// TestWithNoWayToLookTheAnswerIsUnknownAndNotPass is rule 15 at this layer.
//
// A run that could not read the environment established nothing about this
// machine's context. Reporting that as a pass would put the product's central
// promise in breach in the very first row of the report, and it would look
// exactly like a clean result.
func TestWithNoWayToLookTheAnswerIsUnknownAndNotPass(t *testing.T) {
	result := Read(nil)

	if result.Status != status.Unknown {
		t.Errorf("with no way to read the environment the status is %s, want %s", result.Status, status.Unknown)
	}
	if result.Reason != status.ReasonProbeError {
		t.Errorf("the reason is %q, want %q", result.Reason, status.ReasonProbeError)
	}
	if result.Detail == "" {
		t.Error("the answer carries no detail line, so the report would say unknown without saying why")
	}
	// Nil rather than empty, and this is the one place in this package where
	// that is the correct answer: nothing was looked at.
	if result.Findings != nil {
		t.Errorf("the layer reported %d findings without a way to look at anything", len(result.Findings))
	}
}

// TestTheDetailCountsRatherThanClaims keeps the sentence and the list from
// drifting apart.
//
// A hand written number here would be right on the day it was typed and wrong on
// the day the approved list changes - and it would be wrong in a sentence that
// reads like a measurement.
func TestTheDetailCountsRatherThanClaims(t *testing.T) {
	detail := Read(fixed(nil)).Detail
	if !strings.Contains(detail, "21") {
		t.Errorf("the detail line %q does not say how many variables were read", detail)
	}
}
