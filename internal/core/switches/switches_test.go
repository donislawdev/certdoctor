package switches

import (
	"strings"
	"testing"
)

// TestEverySpellingIsOneSwitch keeps the surface readable as a table of
// names: no two switches answer to one spelling, every one has a group and a
// sentence for the help, and a numeric switch takes a value, because a number
// with nowhere to be written is a declaration nobody can satisfy.
func TestEverySpellingIsOneSwitch(t *testing.T) {
	seen := map[string]string{}
	for _, s := range All {
		for _, spelling := range append([]string{s.Name}, s.Aliases...) {
			if spelling == "" || strings.HasPrefix(spelling, "-") {
				t.Errorf("--%s has the spelling %q, which is written without its dashes or not at all", s.Name, spelling)
			}
			if owner, taken := seen[spelling]; taken {
				t.Errorf("%q answers for both --%s and --%s", spelling, owner, s.Name)
			}
			seen[spelling] = s.Name
		}
		if s.Group == "" || s.Summary == "" {
			t.Errorf("--%s has no group or no sentence for the help", s.Name)
		}
		if s.Numeric && !s.TakesValue() {
			t.Errorf("--%s is numeric and takes no value", s.Name)
		}
	}
}

// TestNamedFindsEachSwitchAndNothingElse covers the one lookup the surface
// offers, in both directions.
func TestNamedFindsEachSwitchAndNothingElse(t *testing.T) {
	for _, s := range All {
		got, ok := Named(s.Name)
		if !ok || got.Name != s.Name {
			t.Errorf("Named(%q) answered %q, %v", s.Name, got.Name, ok)
		}
	}
	for _, missing := range []string{"", "h", "Timeout", "--timeout", "time"} {
		if got, ok := Named(missing); ok {
			t.Errorf("Named(%q) found --%s", missing, got.Name)
		}
	}
}

// TestTheBudgetSentencesCarryTheDeclaredNumbers ties the help's sentences to
// the constants the parser and the window use, so the page cannot keep a
// number the code has moved away from.
func TestTheBudgetSentencesCarryTheDeclaredNumbers(t *testing.T) {
	for name, want := range map[string]string{"timeout": "Defaults to 60", "probe-timeout": "Defaults to 10"} {
		s, _ := Named(name)
		if !strings.Contains(s.Summary, want) || !strings.Contains(s.Summary, "at least 0.001") {
			t.Errorf("--%s says %q", name, s.Summary)
		}
	}
	format, _ := Named("format")
	if format.Arg != "<"+strings.Join(Formats, "|")+">" {
		t.Errorf("--format shows %q", format.Arg)
	}
}
