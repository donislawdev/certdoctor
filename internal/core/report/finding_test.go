package report

import (
	"strings"
	"testing"
)

// TestEveryFindingKindIsCompletelyDeclared is the cheapest guard this project
// has and the one it repeats most: a registry entry with a missing half renders
// as a blank heading, which reads as a broken terminal rather than as a gap in
// the code.
func TestEveryFindingKindIsCompletelyDeclared(t *testing.T) {
	if len(AllFindingKinds) != len(findingKindMeanings) {
		t.Fatalf("the list has %d kinds and the registry has %d - one of them was edited alone",
			len(AllFindingKinds), len(findingKindMeanings))
	}
	seen := map[FindingKind]bool{}
	for _, kind := range AllFindingKinds {
		if seen[kind] {
			t.Errorf("%q is listed twice", kind)
		}
		seen[kind] = true
		if !kind.Valid() {
			t.Errorf("%q is listed and not in the registry", kind)
		}
		if kind.Meaning() == "" {
			t.Errorf("%q has no meaning declared", kind)
		}
		if kind.String() == "" {
			t.Errorf("a kind has an empty identifier")
		}
	}
}

// TestEverySourceIsCompletelyDeclared covers the other closed list in this file.
//
// It matters more than it looks. Source is the rule that every claim about
// somebody else's machine carries where it came from, written into the data - it
// says how strong a claim is - so a source outside the four would let a report
// present something worked out as something observed.
func TestEverySourceIsCompletelyDeclared(t *testing.T) {
	if len(AllSources) != len(sourceMeanings) {
		t.Fatalf("the list has %d sources and the registry has %d", len(AllSources), len(sourceMeanings))
	}
	for _, source := range AllSources {
		if !source.Valid() {
			t.Errorf("%q is listed and not in the registry", source)
		}
		if source.Meaning() == "" {
			t.Errorf("%q has no meaning declared", source)
		}
	}
}

// TestEveryFindingKindSaysHowToFindItsBody is the registry test pointed at the
// half of the union that is easy to add without.
//
// A kind declared with no way of telling whether its body is present would make
// the union check walk straight past it: the finding would be accepted with no
// body at all, and a renderer would draw an envelope with nothing inside.
func TestEveryFindingKindSaysHowToFindItsBody(t *testing.T) {
	if len(findingBodies) != len(AllFindingKinds) {
		t.Fatalf("%d kinds are declared and %d of them say where their body is - one list was edited alone",
			len(AllFindingKinds), len(findingBodies))
	}
	for _, kind := range AllFindingKinds {
		if _, declared := findingBodies[kind]; !declared {
			t.Errorf("%q is a declared kind and nothing knows how to find its body", kind)
		}
	}
}

func environmentVariableFinding() Finding {
	return Finding{
		Kind:    FindingEnvironmentVariable,
		Summary: "HTTPS_PROXY is set",
		Source:  SourceDetected,
		EnvironmentVariable: &EnvironmentVariable{
			Name:  "HTTPS_PROXY",
			Value: "http://proxy.corp:8080",
			Set:   true,
		},
	}
}

func TestAWellFormedFindingIsAccepted(t *testing.T) {
	if breach := environmentVariableFinding().Breach(); breach != "" {
		t.Fatalf("a well formed finding was refused: %s", breach)
	}
}

// TestBreachNamesWhatIsWrongWithAFinding walks every way an envelope or a body
// can be wrong.
//
// The last three are the ones worth the space. A variable that is not set cannot
// carry a value and cannot have had a credential taken out of it - both render
// as an ordinary row and read as a fact about somebody's machine, which is the
// quiet failure this whole type exists to prevent.
func TestBreachNamesWhatIsWrongWithAFinding(t *testing.T) {
	cases := []struct {
		name    string
		damage  func(*Finding)
		expects string
	}{
		{"a kind nobody declared", func(f *Finding) { f.Kind = FindingKind("hunch") }, "outside the registry"},
		{"no summary", func(f *Finding) { f.Summary = "" }, "carries no summary"},
		{"a source outside the four", func(f *Finding) { f.Source = Source("guessed") }, "how strongly it is known"},
		{"no body", func(f *Finding) { f.EnvironmentVariable = nil }, "carries no body of that kind"},
		{"a nameless variable", func(f *Finding) { f.EnvironmentVariable.Name = "" }, "with no name"},
		{"a value for a variable that is not set", func(f *Finding) { f.EnvironmentVariable.Set = false }, "carries a value for it anyway"},
		{"a credential taken out of a variable that is not set", func(f *Finding) {
			f.EnvironmentVariable.Set = false
			f.EnvironmentVariable.Value = ""
			f.EnvironmentVariable.CarriedCredentials = true
		}, "took something out of it"},
	}

	for _, c := range cases {
		finding := environmentVariableFinding()
		c.damage(&finding)

		breach := finding.Breach()
		if breach == "" {
			t.Errorf("%s was accepted", c.name)
			continue
		}
		if !strings.Contains(breach, c.expects) {
			t.Errorf("%s was refused for something else: %q, expected a mention of %q", c.name, breach, c.expects)
		}
	}
}

// withExtraKind declares a second finding kind for the length of one test.
//
// WHY A TEST REACHES INTO A REGISTRY. Two branches of the union check cannot be
// executed while exactly one kind exists: a finding cannot carry the body of
// ANOTHER kind when there is no other kind, and no declared kind can be missing
// from the body table when the table holds the only entry. Those two branches
// are the entire reason the check is a table walk rather than one condition, so
// leaving them unexecuted would mean the shape that costs the most is the one
// nothing has proved. The sideways import guard reaches into its own list for
// the same reason.
//
// A body function that always answers "present" is what makes the first branch
// reachable: the real finding carries an environment variable, and this says the
// second kind's body is there as well.
func withExtraKind(t *testing.T, kind FindingKind, body func(Finding) bool) {
	t.Helper()

	kinds, meaning := AllFindingKinds, findingKindMeanings[kind]
	AllFindingKinds = append(append([]FindingKind{}, AllFindingKinds...), kind)
	findingKindMeanings[kind] = "a kind that exists for the length of one test"
	if body != nil {
		findingBodies[kind] = body
	}

	t.Cleanup(func() {
		AllFindingKinds = kinds
		delete(findingBodies, kind)
		if meaning == "" {
			delete(findingKindMeanings, kind)
			return
		}
		findingKindMeanings[kind] = meaning
	})
}

// TestAFindingCarryingTheBodyOfAnotherKindIsRefused is the union rule in the
// direction that a flat struct makes easy to break.
//
// Every body is a field on the same struct, so nothing in the type system stops
// a finding from filling in two of them. One would be rendered and the other
// silently dropped, and which one depends on the renderer.
func TestAFindingCarryingTheBodyOfAnotherKindIsRefused(t *testing.T) {
	withExtraKind(t, FindingKind("certificate"), func(Finding) bool { return true })

	breach := environmentVariableFinding().Breach()
	if breach == "" {
		t.Fatal("a finding carrying two bodies was accepted")
	}
	if !strings.Contains(breach, "as well") {
		t.Errorf("it was refused for something else: %q", breach)
	}
}

// TestAKindWithNoDeclaredBodyIsRefusedRatherThanSkipped covers the failure the
// registry test above is meant to prevent, from inside the check itself.
//
// If the registry test were ever deleted, this is what keeps a kind with no body
// entry from being walked past in silence - it is refused loudly instead, which
// is the direction an unknown has to fail in.
func TestAKindWithNoDeclaredBodyIsRefusedRatherThanSkipped(t *testing.T) {
	withExtraKind(t, FindingKind("certificate"), nil)

	breach := environmentVariableFinding().Breach()
	if breach == "" {
		t.Fatal("a finding was accepted while a declared kind had no body declaration")
	}
	if !strings.Contains(breach, "nothing knows how to find") {
		t.Errorf("it was refused for something else: %q", breach)
	}
}

// TestTheZeroValuesAreNotAcceptedAnswers keeps a forgotten assignment loud.
// Both of these are strings, so the zero value is the empty one, and a finding
// that reached a report with an empty kind would be rendered as a row with no
// heading rather than refused.
func TestTheZeroValuesAreNotAcceptedAnswers(t *testing.T) {
	var kind FindingKind
	if kind.Valid() {
		t.Error("the zero value of a finding kind is accepted")
	}
	var source Source
	if source.Valid() {
		t.Error("the zero value of a source is accepted")
	}
}

// TestEveryResolutionViewIsCompletelyDeclared closes the list at two.
//
// ADR23 decided there are two lenses and that "derived" is not a third one - it
// is how strongly the system view is known, which Source already carries. The
// registry is what stops a third view being added by somebody who has not read
// that decision, because a third view would silently mean the same fact is
// declared in two places.
func TestEveryResolutionViewIsCompletelyDeclared(t *testing.T) {
	if len(AllResolutionViews) != 2 {
		t.Fatalf("%d views are declared - ADR23 says two, and a third is the mistake it exists to prevent",
			len(AllResolutionViews))
	}
	seen := map[ResolutionView]bool{}
	for _, view := range AllResolutionViews {
		if seen[view] {
			t.Errorf("%q appears twice in the list", view)
		}
		seen[view] = true
		if !view.Valid() {
			t.Errorf("%q is listed and does not validate", view)
		}
		if view.Meaning() == "" {
			t.Errorf("%q is listed with no meaning", view)
		}
		if view.String() != string(view) {
			t.Errorf("%q does not print as itself", view)
		}
	}
	if (ResolutionView("derived")).Valid() {
		t.Error("\"derived\" validates as a view - that is the third value ADR23 refused, and it belongs to Source")
	}
	if (ResolutionView("")).Valid() {
		t.Error("the zero value validates, so a forgotten assignment would pass as a lens")
	}
}

func systemViewFinding() Finding {
	return Finding{
		Kind:    FindingNameResolution,
		Summary: "this system resolves example.com to 2 addresses",
		Source:  SourceDetected,
		NameResolution: &NameResolution{
			Name:       "example.com",
			View:       ViewSystem,
			Addresses:  []string{"192.0.2.10", "2001:db8::10"},
			DurationMS: 27,
		},
	}
}

func directViewFinding() Finding {
	return Finding{
		Kind:    FindingNameResolution,
		Summary: "192.0.2.53 answered NOERROR for example.com A",
		Source:  SourceDetected,
		NameResolution: &NameResolution{
			Name:         "example.com",
			View:         ViewDirect,
			Resolver:     "192.0.2.53",
			QueryType:    "A",
			ResponseCode: "NOERROR",
			Addresses:    []string{"192.0.2.10"},
			DurationMS:   4,
		},
	}
}

// TestBothViewsAreAcceptedWhenWellFormed is the other side of the refusals
// below. Rules that refused every resolution finding would satisfy all of them
// and nobody would find out until L1 could not emit a single row.
func TestBothViewsAreAcceptedWhenWellFormed(t *testing.T) {
	if breach := systemViewFinding().Breach(); breach != "" {
		t.Errorf("a well formed system view was refused: %s", breach)
	}
	if breach := directViewFinding().Breach(); breach != "" {
		t.Errorf("a well formed direct view was refused: %s", breach)
	}
	// The system view IS allowed to be derived - that is the container case D3
	// describes, where it has to be rebuilt from resolv.conf rather than measured.
	derived := systemViewFinding()
	derived.Source = SourceDerived
	if breach := derived.Breach(); breach != "" {
		t.Errorf("a derived system view was refused, and that is the whole container case: %s", breach)
	}
}

// TestAResolutionAnswerCannotClaimWhatNobodyEstablished walks every refusal.
//
// THE THREE SYSTEM VIEW RULES ARE WHY THIS BODY HAS A BREACH FUNCTION AT ALL.
// The operating system resolves a name and reports nothing else - not which of
// its resolvers replied, not which record type it asked for, not what response
// code came back. Each of those is the most useful column in the row, so each is
// what a plausible mistake fills in, and a filled in row reads as a measurement.
func TestAResolutionAnswerCannotClaimWhatNobodyEstablished(t *testing.T) {
	cases := []struct {
		name    string
		base    func() Finding
		damage  func(*Finding)
		expects string
	}{
		{"an answer for no name", systemViewFinding,
			func(f *Finding) { f.NameResolution.Name = "" }, "for no name"},
		{"a lens nobody declared", systemViewFinding,
			func(f *Finding) { f.NameResolution.View = ResolutionView("guessed") }, "which of the two lenses"},
		{"a third lens called derived", systemViewFinding,
			func(f *Finding) { f.NameResolution.View = ResolutionView("derived") }, "which of the two lenses"},
		{"time running backwards", systemViewFinding,
			func(f *Finding) { f.NameResolution.DurationMS = -1 }, "took -1 milliseconds"},

		{"the system view naming a resolver", systemViewFinding,
			func(f *Finding) { f.NameResolution.Resolver = "192.0.2.53" }, "does not report"},
		{"the system view carrying a response code", systemViewFinding,
			func(f *Finding) { f.NameResolution.ResponseCode = "NOERROR" }, "does not hand back"},
		{"the system view claiming a record type", systemViewFinding,
			func(f *Finding) { f.NameResolution.QueryType = "AAAA" }, "does not split by"},

		{"our own query called derived", directViewFinding,
			func(f *Finding) { f.Source = SourceDerived }, "derived rather than observed"},
		{"a direct query with no resolver", directViewFinding,
			func(f *Finding) { f.NameResolution.Resolver = "" }, "cannot say which resolver"},
		{"a direct query with no response code", directViewFinding,
			func(f *Finding) { f.NameResolution.ResponseCode = "" }, "this view exists to establish"},
		{"a direct query with no record type", directViewFinding,
			func(f *Finding) { f.NameResolution.QueryType = "" }, "which record type"},

		{"a name that does not exist, with addresses", directViewFinding, func(f *Finding) {
			f.NameResolution.ResponseCode = ResponseNXDomain
		}, "does not exist and lists"},

		{"the kind without the body", systemViewFinding,
			func(f *Finding) { f.NameResolution = nil }, "carries no body of that kind"},
		{"both bodies at once", systemViewFinding, func(f *Finding) {
			f.EnvironmentVariable = &EnvironmentVariable{Name: "HTTPS_PROXY", Set: true, Value: "x"}
		}, "body as well"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			finding := c.base()
			c.damage(&finding)
			breach := finding.Breach()
			if breach == "" {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(breach, c.expects) {
				t.Errorf("the refusal reads %q and does not mention %q", breach, c.expects)
			}
		})
	}
}

// TestADirectAnswerMayReportNothingFound keeps NODATA expressible.
//
// "The name exists and has no AAAA record" is a real answer and half of the
// class of failures L1 is meant to find. A rule requiring addresses would have
// made it unsayable, which is why it is pinned rather than assumed.
func TestADirectAnswerMayReportNothingFound(t *testing.T) {
	finding := directViewFinding()
	finding.NameResolution.QueryType = "AAAA"
	finding.NameResolution.ResponseCode = "NODATA"
	finding.NameResolution.Addresses = nil
	finding.Summary = "192.0.2.53 answered NODATA for example.com AAAA"

	if breach := finding.Breach(); breach != "" {
		t.Errorf("an answer of NODATA was refused, and it is a real one: %s", breach)
	}

	// And NXDOMAIN with no addresses is fine too - it is the contradiction that
	// is refused, not the code.
	finding.NameResolution.ResponseCode = ResponseNXDomain
	if breach := finding.Breach(); breach != "" {
		t.Errorf("NXDOMAIN with no addresses was refused: %s", breach)
	}
}
