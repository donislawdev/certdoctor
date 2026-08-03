package report

import "testing"

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
