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
// It matters more than it looks. Source is rule 18 written into the data - it
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
