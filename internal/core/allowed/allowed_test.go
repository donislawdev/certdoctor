package allowed

import (
	"strings"
	"testing"
)

// TestTheZeroValuePermitsNothing is the direction a forgotten assignment has to
// fail in.
//
// A set that permitted everything when nobody filled it would turn rule 16 into
// a rule that holds only when somebody remembered - which is the shape of every
// promise this project refuses to leave in prose.
func TestTheZeroValuePermitsNothing(t *testing.T) {
	var empty Targets

	if _, ok := empty.Permits("example.com:443"); ok {
		t.Error("an unfilled set permitted a connection")
	}
	if empty.Len() != 0 {
		t.Errorf("an unfilled set holds %d targets", empty.Len())
	}
	// And it must still be usable rather than panicking, because the zero value
	// is what a caller gets by declaring the field and not calling New.
	if err := empty.Allow("example.com:443", ReasonTarget); err != nil {
		t.Errorf("the zero value refused to grow: %v", err)
	}
	if _, ok := empty.Permits("example.com:443"); !ok {
		t.Error("the zero value did not keep what was allowed")
	}
}

// TestTheFiveDerivationsAreTheWholeList pins rule 16's enumeration.
//
// The list being closed is what makes the rule enforceable. An open one means
// the next person adds "telemetry" as a sixth derivation and nothing anywhere
// says no.
func TestTheFiveDerivationsAreTheWholeList(t *testing.T) {
	if len(AllReasons) != 5 {
		t.Fatalf("rule 16 permits five derivations, this list holds %d", len(AllReasons))
	}
	seen := map[Reason]bool{}
	for _, r := range AllReasons {
		if seen[r] {
			t.Errorf("%s is declared twice", r)
		}
		seen[r] = true
		if !r.Valid() {
			t.Errorf("%s is in the list and not in the registry", r)
		}
		if r.Meaning() == "" {
			t.Errorf("%s has no meaning, so a refusal could not explain itself", r)
		}
	}
	if Reason("telemetry").Valid() {
		t.Error("a derivation outside the five was accepted as valid")
	}
}

// TestAReasonOutsideTheFiveIsRefusedRatherThanStored is the enforcement half.
//
// Without it the closed list would be a comment: anything could enter the set
// carrying any label, and the set would still answer "permitted".
func TestAReasonOutsideTheFiveIsRefusedRatherThanStored(t *testing.T) {
	set := New()

	err := set.Allow("telemetry.example.com:443", Reason("telemetry"))
	if err == nil {
		t.Fatal("a target entered the set under a derivation rule 16 does not permit")
	}
	if !strings.Contains(err.Error(), "rule 16") {
		t.Errorf("the refusal does not name the rule it is enforcing: %v", err)
	}
	if _, ok := set.Permits("telemetry.example.com:443"); ok {
		t.Error("the refused target is in the set anyway")
	}
	if set.Len() != 0 {
		t.Errorf("the set grew to %d after refusing", set.Len())
	}
}

// TestAnEmptyTargetIsRefused covers the other defect on our side. An empty
// string stored as a key would make Permits("") answer yes, and "" is what a
// forgotten field produces.
func TestAnEmptyTargetIsRefused(t *testing.T) {
	set := New()

	for _, blank := range []string{"", "   ", "\t"} {
		if err := set.Allow(blank, ReasonTarget); err == nil {
			t.Errorf("an empty target %q was allowed", blank)
		}
	}
	if _, ok := set.Permits(""); ok {
		t.Error("the set permits the empty target")
	}
}

// TestTheSetGrowsAndNeverShrinks is the property the whole design rests on.
//
// The addresses are not known before L1 and the proxy not before L2, so the set
// has to grow mid-run. What must never happen is the opposite: a target allowed
// early answering "no" later, which would make "was this permitted" depend on
// when it was asked.
func TestTheSetGrowsAndNeverShrinks(t *testing.T) {
	set := New()
	steps := []struct {
		target string
		reason Reason
	}{
		{"example.com:443", ReasonTarget},
		{"93.184.216.34:443", ReasonResolvedAddress},
		{"192.0.2.53:53", ReasonResolver},
		{"proxy.example.com:8080", ReasonProxy},
		{"wpad.example.com:80", ReasonPACFile},
	}

	for i, step := range steps {
		if err := set.Allow(step.target, step.reason); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		// Everything allowed so far still answers yes.
		for _, earlier := range steps[:i+1] {
			if _, ok := set.Permits(earlier.target); !ok {
				t.Errorf("after step %d, %s stopped being permitted", i, earlier.target)
			}
		}
	}
	if set.Len() != len(steps) {
		t.Errorf("the set holds %d targets after %d additions", set.Len(), len(steps))
	}
}

// TestTheReasonComesBackWithTheAnswer covers the half a boolean would lose.
//
// A refusal has to be able to say what the set did contain, and an audit of a
// run has to trace every connection to something the user asked for. A bare
// yes-or-no cannot do either.
func TestTheReasonComesBackWithTheAnswer(t *testing.T) {
	set := New()
	if err := set.Allow("192.0.2.53:53", ReasonResolver); err != nil {
		t.Fatal(err)
	}

	reason, ok := set.Permits("192.0.2.53:53")
	if !ok {
		t.Fatal("the target is not permitted")
	}
	if reason != ReasonResolver {
		t.Errorf("the set says %q put it there, want %q", reason, ReasonResolver)
	}
	if reason, ok := set.Permits("192.0.2.99:53"); ok || reason != "" {
		t.Errorf("an address nobody allowed came back as %q / %v", reason, ok)
	}
}

// TestTheSameTargetTwiceIsNotAnError covers the case that happens routinely.
//
// A host can resolve to an address that is also a resolver, and both layers
// will allow it. Treating that as a defect would make correct code report
// errors, and the first reason is kept because the set answers "may I connect",
// not "how many ways did we get here".
func TestTheSameTargetTwiceIsNotAnError(t *testing.T) {
	set := New()
	if err := set.Allow("192.0.2.53:53", ReasonResolver); err != nil {
		t.Fatal(err)
	}
	if err := set.Allow("192.0.2.53:53", ReasonResolvedAddress); err != nil {
		t.Errorf("allowing the same target a second time failed: %v", err)
	}

	if set.Len() != 1 {
		t.Errorf("the set holds %d entries for one target", set.Len())
	}
	if reason, _ := set.Permits("192.0.2.53:53"); reason != ReasonResolver {
		t.Errorf("the second reason overwrote the first: %q", reason)
	}
}

// TestHostCaseDoesNotDecideWhetherAConnectionIsAllowed covers the divergence
// that would otherwise refuse a target allowed one line earlier.
//
// Names in DNS are case insensitive, so EXAMPLE.COM and example.com are one
// machine. Storing them as two would mean the layer that allowed it and the
// layer that asks disagree over nothing.
func TestHostCaseDoesNotDecideWhetherAConnectionIsAllowed(t *testing.T) {
	set := New()
	if err := set.Allow("EXAMPLE.COM:443", ReasonTarget); err != nil {
		t.Fatal(err)
	}

	for _, spelling := range []string{"example.com:443", "Example.Com:443", "  example.com:443  "} {
		if _, ok := set.Permits(spelling); !ok {
			t.Errorf("%q was refused although the same host was allowed", spelling)
		}
	}
	if set.Len() != 1 {
		t.Errorf("one host was stored as %d targets", set.Len())
	}
}

// TestTheListIsSortedRatherThanInMapOrder is property five applied here: the
// same set has to render the same bytes, whatever the map iteration did.
func TestTheListIsSortedRatherThanInMapOrder(t *testing.T) {
	set := New()
	for _, target := range []string{"z.example.com:443", "a.example.com:443", "m.example.com:443"} {
		if err := set.Allow(target, ReasonTarget); err != nil {
			t.Fatal(err)
		}
	}

	// Repeated, because a single comparison passes by luck about as often as a
	// map has orderings.
	want := []string{"a.example.com:443", "m.example.com:443", "z.example.com:443"}
	for run := 0; run < 20; run++ {
		got := set.List()
		if len(got) != len(want) {
			t.Fatalf("run %d: %d entries, want %d", run, len(got), len(want))
		}
		for i := range want {
			if got[i].Target != want[i] {
				t.Fatalf("run %d, position %d: %s, want %s", run, i, got[i].Target, want[i])
			}
		}
	}
}
