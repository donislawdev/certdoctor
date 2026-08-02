package exitcode

import "testing"

// TestExitCodeTableMatchesFrozenContract restates the table on purpose.
//
// Normally repeating a table is how two sources of truth are born. Here it is
// the opposite: this is a contract pin, and its whole job is to be a second
// opinion that has to be edited deliberately. Changing a number in the registry
// without changing it here is precisely the loud failure we want, because the
// number lives in other people's pipelines.
func TestExitCodeTableMatchesFrozenContract(t *testing.T) {
	frozen := []struct {
		code Code
		want int
		name string
	}{
		{OK, 0, "OK"},
		{Runtime, 1, "RUNTIME"},
		{Usage, 2, "USAGE"},
		{Config, 3, "CONFIG"},
		{Diagnosis, 4, "DIAGNOSIS"},
		{Inconclusive, 5, "INCONCLUSIVE"},
		{IO, 6, "IO"},
		{Interrupted, 130, "INTERRUPTED"},
		{Terminated, 143, "TERMINATED"},
	}

	if len(registry) != len(frozen) {
		t.Fatalf("the registry has %d codes, the frozen contract has %d - adding or removing one is a breaking change",
			len(registry), len(frozen))
	}
	for _, f := range frozen {
		if f.code.Int() != f.want {
			t.Errorf("%s is %d, the frozen contract says %d", f.name, f.code.Int(), f.want)
		}
		if got := f.code.Name(); got != f.name {
			t.Errorf("code %d is named %q, the frozen contract says %q", f.code.Int(), got, f.name)
		}
	}
}

// TestEveryEntryIsCompletelyDeclared is the registry test: one pass over the
// table demanding a full set of declarations from every row. It is the cheapest
// guard available and it catches the mistake that gets likelier with every added
// row - the entry filled in halfway.
func TestEveryEntryIsCompletelyDeclared(t *testing.T) {
	if len(All) != len(registry) {
		t.Fatalf("All has %d codes, the registry has %d - an entry was added in one place only", len(All), len(registry))
	}

	seenCode := map[Code]bool{}
	seenName := map[string]bool{}
	for _, e := range registry {
		if seenCode[e.code] {
			t.Errorf("code %d appears twice - two meanings behind one number is a contract nobody can read", e.code.Int())
		}
		seenCode[e.code] = true

		if e.name == "" {
			t.Errorf("code %d has no name", e.code.Int())
		}
		if seenName[e.name] {
			t.Errorf("name %q appears twice", e.name)
		}
		seenName[e.name] = true

		for _, r := range e.name {
			if r < 'A' || r > 'Z' {
				t.Errorf("name %q is not uppercase ASCII - exit code names go into other people's scripts", e.name)
				break
			}
		}
		if e.meaning == "" {
			t.Errorf("code %s has no meaning - --help would show the user an empty sentence", e.name)
		}
		if !e.code.Valid() {
			t.Errorf("code %s is in the registry but Valid() rejects it", e.name)
		}
	}
}

// TestCodeOutsideTheTableDescribesItselfAsNothing guards the same promise as the
// status vocabulary: something we do not recognise is reported as nothing, never
// as an invented answer.
func TestCodeOutsideTheTableDescribesItselfAsNothing(t *testing.T) {
	for _, c := range []Code{7, 8, -1, 255} {
		if c.Valid() {
			t.Errorf("Valid() accepted %d, which is not in the table", c.Int())
		}
		if c.Name() != "" {
			t.Errorf("code %d invented the name %q", c.Int(), c.Name())
		}
		if c.Meaning() != "" {
			t.Errorf("code %d invented the meaning %q", c.Int(), c.Meaning())
		}
	}
}

// TestSuccessIsTheOnlyZero pins the one value a shell interprets on its own.
func TestSuccessIsTheOnlyZero(t *testing.T) {
	if OK.Int() != 0 {
		t.Fatalf("OK is %d - a shell reads anything but 0 as failure", OK.Int())
	}
	for _, e := range registry {
		if e.code.Int() == 0 && e.name != "OK" {
			t.Errorf("%s also maps to 0, so a failure would be reported as success", e.name)
		}
	}
}
