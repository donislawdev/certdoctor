package request

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/switches"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TestEverySwitchIsInTheWindowOrSaysWhyNot is the guard ADR121 point 3 asks
// for, on the pattern of the one over --help: every switch the command line
// declares is offered by the window or left to the command line with a
// reason, never both and never neither, and nothing is offered or excused that
// the command line does not declare.
func TestEverySwitchIsInTheWindowOrSaysWhyNot(t *testing.T) {
	offered := map[string]bool{}
	for _, o := range Offered {
		if offered[o.Switch] {
			t.Errorf("--%s is offered twice", o.Switch)
		}
		offered[o.Switch] = true
		if _, declared := switches.Named(o.Switch); !declared {
			t.Errorf("the window offers --%s and the command line does not declare it", o.Switch)
		}
		if _, excused := NotOffered[o.Switch]; excused {
			t.Errorf("--%s is offered and also left to the command line", o.Switch)
		}
	}
	for name, why := range NotOffered {
		if _, declared := switches.Named(name); !declared {
			t.Errorf("the window leaves out --%s and the command line does not declare it", name)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("--%s is left out with no reason", name)
		}
	}
	for _, s := range switches.All {
		if _, excused := NotOffered[s.Name]; !offered[s.Name] && !excused {
			t.Errorf("--%s is declared and the window neither offers it nor says why not", s.Name)
		}
	}
}

// TestEachOptionHasItsWords - a label, a hint and, for a word, an example,
// each with text in the catalogue. A key with no text would show in angle
// brackets on the form.
func TestEachOptionHasItsWords(t *testing.T) {
	for _, o := range Offered {
		keys := []words.Key{o.Label, o.Hint}
		if o.Control() == Line {
			keys = append(keys, o.Example)
		} else if o.Example != "" {
			t.Errorf("--%s shows an example and is not set by typing a word", o.Switch)
		}
		for _, k := range keys {
			if k == "" || strings.HasPrefix(words.T(k), "<") {
				t.Errorf("--%s has no words for %q", o.Switch, k)
			}
		}
	}
}

// TestEachControlIsWhatItsSwitchTakes reads the three controls off the
// declarations, including the one that takes a word.
func TestEachControlIsWhatItsSwitchTakes(t *testing.T) {
	want := map[string]Control{"pac-url": Line, "timeout": Seconds, "probe-timeout": Seconds, "redact": Tick}
	for _, o := range Offered {
		if got := o.Control(); got != want[o.Switch] {
			t.Errorf("--%s is set with %d, want %d", o.Switch, got, want[o.Switch])
		}
	}
}

// TestTheDefaultShownIsTheOneTheCommandLineUses - an empty Seconds field shows
// a number, and that number is the one the help says the switch defaults to,
// so the form cannot show a limit the run does not keep.
func TestTheDefaultShownIsTheOneTheCommandLineUses(t *testing.T) {
	for _, o := range Offered {
		if o.Control() != Seconds {
			if o.Default != 0 {
				t.Errorf("--%s carries a default and is not a number of seconds", o.Switch)
			}
			continue
		}
		s, _ := switches.Named(o.Switch)
		if o.Default <= 0 || !strings.Contains(s.Summary, fmt.Sprintf("Defaults to %d", o.Default)) {
			t.Errorf("--%s shows %d and the help says %q", o.Switch, o.Default, s.Summary)
		}
	}
}

var argsCases = []struct {
	name string
	r    Request
	want []string
}{
	{"nothing set", Request{Address: "https://example.com"},
		[]string{"--json", "--", "https://example.com"}},
	{"every option, in the order of the form", Request{
		Address: "https://example.com",
		Ticked:  map[string]bool{"redact": true},
		Typed:   map[string]string{"redact": "ignored", "probe-timeout": "5", "timeout": "0", "pac-url": "http://p/x.pac"},
	}, []string{"--json", "--pac-url=http://p/x.pac", "--timeout=0", "--probe-timeout=5", "--redact", "--", "https://example.com"}},
	{"space around values and the address is a shell's, not the person's", Request{
		Address: "  https://example.com \t",
		Typed:   map[string]string{"timeout": " 1,5 ", "pac-url": "   "},
	}, []string{"--json", "--timeout=1,5", "--", "https://example.com"}},
	{"an address that looks like a switch stays an address", Request{Address: "--help"},
		[]string{"--json", "--", "--help"}},
	{"a value beginning with a dash stays the value of its switch", Request{
		Address: "https://example.com",
		Typed:   map[string]string{"pac-url": "-x=y"},
	}, []string{"--json", "--pac-url=-x=y", "--", "https://example.com"}},
	{"an unticked option and a tick on an option that takes a value", Request{
		Address: "https://example.com",
		Ticked:  map[string]bool{"redact": false, "timeout": true},
	}, []string{"--json", "--", "https://example.com"}},
	{"no address is passed on as it is", Request{}, []string{"--json", "--", ""}},
}

// TestTheRequestBecomesTheCommandLineItSays covers Args case by case.
func TestTheRequestBecomesTheCommandLineItSays(t *testing.T) {
	for _, c := range argsCases {
		if got := c.r.Args(); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

// TestTheLimitIsTheTypedNumberOrTheDefault - the time shown against is the
// number typed for the time limit, zero included, and the command line's
// default for anything that is not a number of seconds.
func TestTheLimitIsTheTypedNumberOrTheDefault(t *testing.T) {
	def := float64(switches.DefaultBudgetSeconds)
	for _, c := range []struct {
		typed string
		want  float64
	}{
		{"", def}, {"   ", def}, {"90", 90}, {" 2.5 ", 2.5}, {"0", 0}, {"1,5", def}, {"-3", def},
		{"NaN", def}, {"Inf", def}, {"ten", def}, {"1e2", 100}, {"86400", 86400}, {"86401", def}, {"1e300", def},
	} {
		r := Request{Typed: map[string]string{budgetSwitch: c.typed, "probe-timeout": "7"}}
		if got := r.Limit(); got != c.want {
			t.Errorf("a time limit typed as %q gives %v, want %v", c.typed, got, c.want)
		}
	}
	if got := (Request{}).Limit(); got != def {
		t.Errorf("a request with nothing typed gives %v, want the default %v", got, def)
	}
}

// TestTheLimitIsReadFromTheWholeRunsSwitch - the switch Limit reads is the one
// offered for the whole run's time, with the default the form shows for it.
func TestTheLimitIsReadFromTheWholeRunsSwitch(t *testing.T) {
	for _, o := range Offered {
		if o.Switch == budgetSwitch {
			if o.Control() != Seconds || o.Default != switches.DefaultBudgetSeconds {
				t.Errorf("--%s is offered as %v with the default %d", budgetSwitch, o.Control(), o.Default)
			}
			return
		}
	}
	t.Errorf("--%s, which the time shown is read from, is not offered by the window", budgetSwitch)
}

// TestARequestIsReadyWithAnAddress - spaces are no address.
func TestARequestIsReadyWithAnAddress(t *testing.T) {
	for address, want := range map[string]bool{"": false, " \t ": false, "example.com": true, " https://example.com ": true} {
		if got := (Request{Address: address}).Ready(); got != want {
			t.Errorf("the address %q is ready: %v, want %v", address, got, want)
		}
	}
}
