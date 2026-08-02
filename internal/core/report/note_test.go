package report

import "testing"

// TestEveryNoteKindIsCompletelyDeclared is the registry test for the one
// vocabulary that exists so a run can admit it did less than it promised. A kind
// without a meaning is a note nobody can act on.
func TestEveryNoteKindIsCompletelyDeclared(t *testing.T) {
	if len(AllNoteKinds) != len(noteKindMeanings) {
		t.Fatalf("AllNoteKinds has %d kinds, the registry has %d - one was added in a single place",
			len(AllNoteKinds), len(noteKindMeanings))
	}

	seen := map[NoteKind]bool{}
	seenMeaning := map[string]bool{}
	for _, k := range AllNoteKinds {
		if seen[k] {
			t.Errorf("kind %q appears twice in AllNoteKinds", k)
		}
		seen[k] = true

		if !k.Valid() {
			t.Errorf("kind %q is listed and the registry does not know it", k)
		}
		meaning := k.Meaning()
		if meaning == "" {
			t.Errorf("kind %q has no meaning", k)
		}
		if seenMeaning[meaning] {
			t.Errorf("meaning %q appears twice - a copied row is a row nobody finished", meaning)
		}
		seenMeaning[meaning] = true

		for _, r := range string(k) {
			if (r < 'a' || r > 'z') && r != '_' {
				t.Errorf("kind %q is not lower case with underscores - it goes out in the machine readable report", k)
				break
			}
		}
	}
}

// TestNoteKindOutsideTheListDescribesItselfAsNothing keeps the same promise as
// every other closed vocabulary here: something we do not recognise reports as
// nothing rather than as an invented answer.
func TestNoteKindOutsideTheListDescribesItselfAsNothing(t *testing.T) {
	for _, k := range []NoteKind{"", "fyi", "NOT_IMPLEMENTED", "warning"} {
		if k.Valid() {
			t.Errorf("Valid() accepted %q, which is not in the registry", k)
		}
		if k.Meaning() != "" {
			t.Errorf("kind %q invented the meaning %q", k, k.Meaning())
		}
	}
}

// TestTheZeroValueOfATristateIsNotAnAnswer is small and carries the whole point
// of the type. A plain bool defaults to "no", which would state a measurement
// nobody took.
func TestTheZeroValueOfATristateIsNotAnAnswer(t *testing.T) {
	var zero Tristate
	if zero != NotDetermined {
		t.Errorf("the zero value of Tristate is %d, want NotDetermined", zero)
	}
	if zero.Determined() {
		t.Error("the zero value of Tristate claims to carry an answer")
	}
	for _, determined := range []Tristate{DeterminedFalse, DeterminedTrue} {
		if !determined.Determined() {
			t.Errorf("Tristate %d does not report itself as determined", determined)
		}
	}
	if DeterminedFalse == DeterminedTrue {
		t.Error("the two determined values are the same value")
	}
}

// TestPrivilegeLevelVocabularyIsClosed pins the third value as a real answer
// rather than a placeholder. Until something detects the level, claiming "user"
// would be a measurement we never took.
func TestPrivilegeLevelVocabularyIsClosed(t *testing.T) {
	for _, p := range []PrivilegeLevel{PrivilegeUnknown, PrivilegeUser, PrivilegeElevated} {
		if !p.Valid() {
			t.Errorf("declared privilege level %q is rejected by Valid()", p)
		}
	}
	for _, p := range []PrivilegeLevel{"", "root", "admin", "USER"} {
		if p.Valid() {
			t.Errorf("Valid() accepted %q, which is not in the set", p)
		}
	}
	if len(privilegeLevels) != 3 {
		t.Errorf("the privilege level set has %d members, want 3", len(privilegeLevels))
	}
}
