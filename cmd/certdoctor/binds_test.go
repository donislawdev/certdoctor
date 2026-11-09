package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/switches"
)

// TestEveryDeclaredSwitchIsBound holds binds to the published surface in both
// directions. A declared switch without an entry is printed by the help and
// then refused as unknown. An entry without a declaration is a switch nobody
// can find, and the window does not offer it either, because the window builds
// its form from the declarations alone (ADR121 point 3).
func TestEveryDeclaredSwitchIsBound(t *testing.T) {
	declared := map[string]bool{}
	for _, s := range switches.All {
		if declared[s.Name] {
			t.Errorf("--%s is declared twice", s.Name)
		}
		declared[s.Name] = true
		if _, ok := binds[s.Name]; !ok {
			t.Errorf("--%s is declared and has no place in options", s.Name)
		}
	}
	for name := range binds {
		if !declared[name] {
			t.Errorf("binds puts --%s somewhere and the surface does not declare it", name)
		}
	}
	if len(declared) == 0 {
		t.Fatal("no switch is declared, so this test checks nothing")
	}
}

// TestADeclaredSwitchWithNoPlaceStopsTheFirstParse - the day somebody declares
// a switch and forgets its entry here, the first parse says which switch, in
// every test that parses, rather than every run refusing a switch its own help
// names.
func TestADeclaredSwitchWithNoPlaceStopsTheFirstParse(t *testing.T) {
	saved := binds["quiet"]
	delete(binds, "quiet")
	t.Cleanup(func() { binds["quiet"] = saved })
	defer func() {
		if said := fmt.Sprint(recover()); !strings.Contains(said, "--quiet") {
			t.Errorf("the parse went on, or stopped without naming the switch: %q", said)
		}
	}()
	newFlagSet()
}

// TestEachSwitchIsRegisteredAsItIsDeclared asks the flag set what each bind
// registered: under the declared name and every alias, and with a value
// exactly when the declaration says there is one. A bind that registered a
// switch under another name, or a flag where a value was declared, would
// otherwise be found by the person typing it.
func TestEachSwitchIsRegisteredAsItIsDeclared(t *testing.T) {
	fs, _ := newFlagSet()
	for _, s := range switches.All {
		for _, name := range append([]string{s.Name}, s.Aliases...) {
			f := fs.Lookup(name)
			if f == nil {
				t.Errorf("-%s is declared and the flag set does not know it", name)
				continue
			}
			if got := takesValue(fs, name); got != s.TakesValue() {
				t.Errorf("-%s takes a value: %v, and the declaration says %v", name, got, s.TakesValue())
			}
		}
	}
	registered := 0
	fs.VisitAll(func(*flag.Flag) { registered++ })
	spellings := 0
	for _, s := range switches.All {
		spellings += 1 + len(s.Aliases)
	}
	if registered != spellings {
		t.Errorf("the flag set holds %d switches and the surface declares %d spellings", registered, spellings)
	}
}

// TestTheDefaultsTheHelpPrintsAreTheOnesParsed - with no switch given, the two
// budgets hold the numbers the help prints and the window shows in an empty
// field, both read from the one declaration.
func TestTheDefaultsTheHelpPrintsAreTheOnesParsed(t *testing.T) {
	fs, o := newFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if o.timeout != switches.DefaultBudgetSeconds || o.probeTimeout != switches.DefaultLayerBudgetSeconds {
		t.Errorf("an empty command line runs with %g and %g seconds, and the help says %d and %d",
			o.timeout, o.probeTimeout, switches.DefaultBudgetSeconds, switches.DefaultLayerBudgetSeconds)
	}
}

// TestTheHelpWritesEachSwitchInItsShape reads the page for the three shapes a
// switch is written in: with the placeholder of its value, alone, and with
// its alias.
func TestTheHelpWritesEachSwitchInItsShape(t *testing.T) {
	page := helpText()
	for _, want := range []string{"  --timeout <seconds>  ", "  --json  ", "  --help, -h  "} {
		if !strings.Contains(page, want) {
			t.Errorf("the help has no %q", want)
		}
	}
}

// TestTheFormatsTheHelpNamesAreTheOnesTheParserTakes keeps the two lists of
// formats in step: the published names in the switch's placeholder, and this
// program's own list, which also says which of them are built.
func TestTheFormatsTheHelpNamesAreTheOnesTheParserTakes(t *testing.T) {
	if got := formatNames(); !slices.Equal(got, switches.Formats) {
		t.Errorf("the parser takes %v and the surface declares %v", got, switches.Formats)
	}
}
