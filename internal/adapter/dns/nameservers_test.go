package dns

import (
	"net/netip"
	"testing"
)

// TestKnownKeepsTheOnesInUseFirstAndSaysEachOnce covers the fold.
//
// The order matters to a reader scanning the allowed set - the resolvers
// actually in use belong at the front - and the deduplication matters because
// the same address routinely turns up in both lists on Windows, where the
// registry records what GetNetworkParams reports.
func TestKnownKeepsTheOnesInUseFirstAndSaysEachOnce(t *testing.T) {
	got := merged([]string{"1.1.1.1", "8.8.8.8"}, []string{"8.8.8.8", "192.168.1.1", "1.1.1.1"})

	want := []string{"1.1.1.1", "8.8.8.8", "192.168.1.1"}
	if len(got) != len(want) {
		t.Fatalf("the fold produced %v where %v was expected", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d is %q and should be %q - %v", i, got[i], want[i], got)
		}
	}
}

// TestTheFoldDropsEmptyEntriesRatherThanCarryingThem keeps a blank out of the
// allowed set, where it would be a key that matches nothing and reads like a
// resolver nobody can name.
func TestTheFoldDropsEmptyEntriesRatherThanCarryingThem(t *testing.T) {
	for _, address := range merged([]string{"", "1.1.1.1"}, []string{"", ""}) {
		if address == "" {
			t.Error("an empty address reached the list of places this run may connect to")
		}
	}
}

// TestEnumerationAnswersWithAddressesOrWithAReason is a PROPERTY and not a
// fixture, deliberately.
//
// This function reads the real machine - the Windows registry and the IP helper
// API on one platform, /etc/resolv.conf on the others - so a test asserting WHICH
// resolvers it finds would pass here and fail on the next machine, which is
// exactly the failure this project keeps warning about. What has to be true
// everywhere is narrower and more useful: whatever comes back is a list of things
// this program could actually send a query to, or an error that says what went
// wrong. A resolver that is not an address would be a hole in inviolable rule 16,
// because that string goes into the set of places this run may connect to.
func TestEnumerationAnswersWithAddressesOrWithAReason(t *testing.T) {
	found, err := Enumerate(nil)
	if err != nil {
		// A legitimate outcome, and the layer turns it into UNKNOWN with a
		// reason. What is not legitimate is an error saying nothing.
		if err.Error() == "" {
			t.Fatal("the enumeration failed and said nothing about why")
		}
		t.Logf("this machine reported no resolvers: %v", err)
		return
	}

	if len(found.ToAsk) > len(found.Known) {
		t.Errorf("the list to ask has %d entries and the wider list has %d, so it is not wider",
			len(found.ToAsk), len(found.Known))
	}
	if found.From == "" {
		t.Error("the enumeration did not say where the list came from, and that goes into the report")
	}
	for _, list := range [][]string{found.ToAsk, found.Known} {
		for _, resolver := range list {
			if _, err := netip.ParseAddr(resolver); err != nil {
				t.Errorf("%q was reported as a resolver and is not an address: %v", resolver, err)
			}
			if _, err := Target(resolver); err != nil {
				t.Errorf("%q cannot be turned into something to dial: %v", resolver, err)
			}
		}
	}
}

// TestEveryResolverInUseIsAlsoKnown is the invariant the allowed set rests on.
//
// The set is seeded from the wider list and the queries go to the narrower one,
// so a resolver we would ask but never recorded is a query that dial.Guarded
// would refuse - a run that fails on a working machine, for a reason nobody
// reading the report could see.
func TestEveryResolverInUseIsAlsoKnown(t *testing.T) {
	found, err := Enumerate(nil)
	if err != nil {
		t.Skipf("this machine reported no resolvers: %v", err)
	}

	known := make(map[string]bool, len(found.Known))
	for _, resolver := range found.Known {
		known[resolver] = true
	}
	for _, resolver := range found.ToAsk {
		if !known[resolver] {
			t.Errorf("%s would be asked and is not in the list the allowed set is built from", resolver)
		}
	}
}
