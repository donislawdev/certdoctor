package pac

import (
	"errors"
	"testing"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// What these tests are really about.
//
// Probe S16 measured the sandbox stopwatch on 2026-09-07, three runs of three,
// and split one assumption in half. A native call already running is not
// interrupted - ADR78 - but the NEXT one is stopped from starting, so a slow
// resolver overruns the budget by exactly one query. Time is held. Count is not:
// inside one 300 millisecond budget a file got 214 to 222 questions away at a
// millisecond each. Every one of those is a name somebody else chose, sent to a
// resolver the allowed set already permits, so nothing in this program refuses it
// and nothing but these tests says the bound works.

// resolverThatCounts hands back a resolver and a reader for how many times it
// was actually called, which is the only way to tell the cache from a coincidence.
func resolverThatCounts(answer func(host string) ([]string, error)) (func(string) ([]string, error), func() int) {
	calls := 0
	return func(host string) ([]string, error) {
		calls++
		return answer(host)
	}, func() int { return calls }
}

// sandboxResolving is testSandbox with a resolver behind it and an allowance.
func sandboxResolving(resolve func(string) ([]string, error), allowance int) Sandbox {
	s := testSandbox()
	s.Ports.Resolve = resolve
	s.MaxLookups = allowance
	return s
}

func alwaysResolves(string) ([]string, error) { return []string{"10.1.2.3"}, nil }

// TestOneNameIsAskedOnceHoweverOftenTheFileUsesIt is why the allowance counts
// NAMES rather than CALLS. A corporate PAC tests one host against several
// subnets - isInNet again and again about a single name - and an allowance that
// counted calls would refuse such a file for traffic it never generated.
func TestOneNameIsAskedOnceHoweverOftenTheFileUsesIt(t *testing.T) {
	resolve, calls := resolverThatCounts(alwaysResolves)

	result := evaluateSource(sandboxResolving(resolve, 4), `
		isInNet(host, "10.0.0.0", "255.0.0.0");
		isInNet(host, "172.16.0.0", "255.240.0.0");
		isInNet(host, "192.168.0.0", "255.255.0.0");
		isResolvable(host);
		dnsResolve(host);
		return "DIRECT";`)

	if result.Outcome != corepac.OutcomeAnswered {
		t.Fatalf("the file did not answer: %s / %s", result.Outcome, result.Detail)
	}
	if calls() != 1 {
		t.Errorf("one name cost %d queries, so the evaluation is not caching", calls())
	}
	if len(result.Asked) != 1 || result.Asked[0] != "api.example.com" {
		t.Errorf("the run recorded %v as having been asked about, want the one name", result.Asked)
	}
	if result.LookupsExhausted {
		t.Error("one name inside an allowance of four was reported as spending it")
	}
}

// TestTheAllowanceStopsTheQueriesAndSaysSo is the bound itself. Without it a file
// decides how many names leave this machine.
func TestTheAllowanceStopsTheQueriesAndSaysSo(t *testing.T) {
	resolve, calls := resolverThatCounts(alwaysResolves)

	result := evaluateSource(sandboxResolving(resolve, 2), `
		dnsResolve("one.example");
		dnsResolve("two.example");
		dnsResolve("three.example");
		dnsResolve("four.example");
		return "DIRECT";`)

	if result.Outcome != corepac.OutcomeAnswered {
		t.Fatalf("the file did not answer: %s / %s", result.Outcome, result.Detail)
	}
	if calls() != 2 {
		t.Errorf("an allowance of two let %d queries out", calls())
	}
	if len(result.Asked) != 2 {
		t.Errorf("the run recorded %v, want only the names it actually sent", result.Asked)
	}
	if !result.LookupsExhausted {
		t.Error("the allowance ran out and the result does not say so, so the layer would settle on it")
	}
}

// TestANameBeyondTheAllowanceAnswersAsThoughItDidNotResolve pins what the FILE
// sees, which is the half that decides whether a verdict may rest on the answer.
// It is the same known untruth a run with no resolver hands over, which is why
// both stop the answer settling.
func TestANameBeyondTheAllowanceAnswersAsThoughItDidNotResolve(t *testing.T) {
	result := evaluateSource(sandboxResolving(alwaysResolves, 1), `
		dnsResolve("first.example");
		return isResolvable("second.example") ? "PROXY reached:1" : "DIRECT";`)

	if result.Raw != "DIRECT" {
		t.Errorf("a name past the allowance answered %q, want the browser-shaped no", result.Raw)
	}
	if !result.LookupsExhausted {
		t.Error("the file was answered from an allowance it had spent and nothing recorded it")
	}
}

// TestAllowanceZeroRefusesEveryQuery follows the rule Sandbox states about all
// its numbers: a field nobody set makes the sandbox useless rather than
// unbounded. A caller who wires a resolver and forgets the allowance gets a run
// that says it could not ask, never one that asks without limit.
func TestAllowanceZeroRefusesEveryQuery(t *testing.T) {
	resolve, calls := resolverThatCounts(alwaysResolves)

	result := evaluateSource(sandboxResolving(resolve, 0), `dnsResolve(host); return "DIRECT";`)

	if calls() != 0 {
		t.Errorf("an allowance of zero let %d queries out", calls())
	}
	if !result.LookupsExhausted {
		t.Error("an allowance of zero was spent silently")
	}
	if len(result.Unanswered) != 0 {
		t.Errorf("a run WITH a resolver reported %v as having nothing behind it, "+
			"which tells somebody their machine has no resolver when it has one", result.Unanswered)
	}
}

// TestAFailedLookupIsRememberedToo keeps the allowance honest. A name that failed
// is a question that already left this machine, and asking again would send it a
// second time to learn what we know - which would also let one file spend a
// single slot an unbounded number of times.
func TestAFailedLookupIsRememberedToo(t *testing.T) {
	resolve, calls := resolverThatCounts(func(string) ([]string, error) {
		return nil, errors.New("nobody could be asked")
	})

	result := evaluateSource(sandboxResolving(resolve, 4), `
		dnsResolve("gone.example");
		dnsResolve("gone.example");
		dnsResolve("gone.example");
		return "DIRECT";`)

	if calls() != 1 {
		t.Errorf("one failing name cost %d queries", calls())
	}
	if len(result.Asked) != 1 {
		t.Errorf("the run recorded %v, want the failing name once", result.Asked)
	}
}

// TestAnAddressLiteralIsNeverSentToAResolver is pac.Ports.DNSResolve's own rule
// observed from the outside, and it matters twice over: a lookup nobody asked for
// is ADR62 one layer along, and a literal that consumed the allowance would let a
// file exhaust it without a single name leaving the machine.
func TestAnAddressLiteralIsNeverSentToAResolver(t *testing.T) {
	resolve, calls := resolverThatCounts(alwaysResolves)

	result := evaluateSource(sandboxResolving(resolve, 1), `
		dnsResolve("10.0.0.1");
		dnsResolve("2001:db8::1");
		return isResolvable("real.example") ? "PROXY reached:1" : "DIRECT";`)

	if calls() != 1 {
		t.Errorf("two address literals and one name cost %d queries", calls())
	}
	if len(result.Asked) != 1 || result.Asked[0] != "real.example" {
		t.Errorf("the run recorded %v, want only the name that was actually asked about", result.Asked)
	}
	if result.LookupsExhausted {
		t.Error("address literals spent the allowance without asking anybody anything")
	}
	if result.Raw != "PROXY reached:1" {
		t.Errorf("the one real name was answered %q rather than resolved", result.Raw)
	}
}

// TestTheNamesAreRecordedInTheOrderTheyWereFirstAsked pins the order, because the
// determinism guard needs two runs of one binary against one file to produce one
// document - and a map's range order would not.
func TestTheNamesAreRecordedInTheOrderTheyWereFirstAsked(t *testing.T) {
	result := evaluateSource(sandboxResolving(alwaysResolves, 4), `
		dnsResolve("beta.example");
		dnsResolve("alpha.example");
		dnsResolve("beta.example");
		dnsResolve("gamma.example");
		return "DIRECT";`)

	want := []string{"beta.example", "alpha.example", "gamma.example"}
	if len(result.Asked) != len(want) {
		t.Fatalf("the run recorded %v, want %v", result.Asked, want)
	}
	for i, name := range want {
		if result.Asked[i] != name {
			t.Errorf("position %d holds %q, want %q - the order is not first-asked", i, result.Asked[i], name)
		}
	}
}

// TestARunWithNoResolverRecordsNothingAsAsked keeps the two states apart at the
// source. A file that went looking on a run with no resolver is reported through
// Unanswered; Asked is for names that actually left this machine, and one filling
// in for the other would make the report claim a query nobody sent.
func TestARunWithNoResolverRecordsNothingAsAsked(t *testing.T) {
	result := evaluateSource(testSandbox(), `dnsResolve(host); return "DIRECT";`)

	if len(result.Asked) != 0 {
		t.Errorf("a run with no resolver recorded %v as having been asked about", result.Asked)
	}
	if result.LookupsExhausted {
		t.Error("a run with no resolver reported an allowance as spent")
	}
	if len(result.Unanswered) != 1 || result.Unanswered[0] != "dnsResolve" {
		t.Errorf("a run with no resolver recorded %v, want the helper nobody could answer", result.Unanswered)
	}
}
