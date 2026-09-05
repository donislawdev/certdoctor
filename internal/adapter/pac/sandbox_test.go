package pac

import (
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// The bench's PAC files live in the repository, so these tests read the same
// bytes the bench serves rather than a copy - OBS64 and OBS75 both measured what
// happens when two artefacts of one bench come apart.
const benchFiles = "../../../testbed/pac/files"
const benchExpected = "../../../testbed/expected"

func benchPAC(t *testing.T, name string) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(benchFiles, name))
	if err != nil {
		t.Fatalf("the bench file %s could not be read: %v", name, err)
	}
	return string(source)
}

// benchExpectation reads one key from a bench expectation file.
//
// THE EXPECTATIONS WERE WRITTEN BEFORE THIS CODE EXISTED, from the bench's
// configuration, in slice P4c. Reading them here rather than restating them is
// the whole point: a value copied into a test is a value that can drift from the
// bench without anybody noticing.
func benchExpectation(t *testing.T, file, key string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(benchExpected, file))
	if err != nil {
		t.Fatalf("the bench expectation %s could not be read: %v", file, err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if name, value, found := strings.Cut(line, "="); found && name == key {
			return value
		}
	}
	t.Fatalf("%s carries no key %q", file, key)
	return ""
}

// testSandbox is the sandbox these tests use. The budget is generous on purpose:
// a test that fails when a laptop is busy teaches retrying rather than looking.
func testSandbox() Sandbox {
	return Sandbox{
		Ports:     corepac.Ports{Now: func() time.Time { return time.Unix(1767225600, 0).UTC() }},
		Budget:    2 * time.Second,
		Ceiling:   64 << 20,
		MaxSource: 1 << 20,
		MaxStack:  2000,
	}
}

// TestTheSandboxReachesNeitherTheNetworkNorTheFileSystem is the guard docs/24
// makes MANDATORY for this slice, and it is checked with the PAC file that TRIES
// both rather than by reading the code.
//
// hostile.pac probes for require, process, fetch, XMLHttpRequest, setTimeout,
// console, a file reader and a runtime global, and RETURNS A DIRECTIVE NAMING
// whichever it found instead of throwing. So a sandbox that leaks produces a
// visible, named answer that cannot be mistaken for an unrelated fault - and
// this test can say WHICH condition failed rather than only that one did.
func TestTheSandboxReachesNeitherTheNetworkNorTheFileSystem(t *testing.T) {
	result := testSandbox().Evaluate(benchPAC(t, "hostile.pac"), "http://via.proxy.test/", "via.proxy.test")

	want := benchExpectation(t, "pac-hostile.txt", "l2_pac_result")
	if result.Outcome != corepac.OutcomeAnswered {
		t.Fatalf("the hostile PAC did not answer at all: %s %s", result.Outcome, result.Detail)
	}
	if result.Raw != want {
		t.Fatalf("the sandbox leaked: the bench expects %q and this run produced %q", want, result.Raw)
	}

	// The forbidden names, read from the bench rather than restated here. Any
	// one of them in the output is a named leak.
	forbidden := benchExpectation(t, "pac-hostile.txt", "leak_forbidden") + "," +
		benchExpectation(t, "pac-hostile.txt", "leak_forbidden_2")
	for _, leak := range strings.Split(forbidden, ",") {
		if leak = strings.TrimSpace(leak); leak != "" && strings.Contains(result.Raw, leak) {
			t.Errorf("the sandbox exposed something it must not: %s", leak)
		}
	}
}

// TestOnlyTheTwelveHelpersAreExposed is condition 4 of docs/14 section 2.1.
//
// IT COMPARES TWO RUNTIMES RATHER THAN ASKING OUR OWN LIST WHAT IT CONTAINS.
// A fresh goja Runtime is measured for the names it already has, an injected one
// for the names it has, and the difference must be exactly the twelve. The
// twelve are WRITTEN OUT HERE, independently of helperNames in the package, for
// the reason OBS48 measured: an assertion that asks the code under test what to
// expect agrees with it whatever it does.
func TestOnlyTheTwelveHelpersAreExposed(t *testing.T) {
	twelve := []string{
		"dateRange", "dnsDomainIs", "dnsDomainLevels", "dnsResolve",
		"isInNet", "isPlainHostName", "isResolvable", "localHostOrDomainIs",
		"myIpAddress", "shExpMatch", "timeRange", "weekdayRange",
	}

	before := globalNames(t, goja.New())

	injected := goja.New()
	if err := (testSandbox()).inject(injected); err != nil {
		t.Fatalf("the sandbox could not be built: %v", err)
	}
	after := globalNames(t, injected)

	var added []string
	for _, name := range after {
		if !contains(before, name) {
			added = append(added, name)
		}
	}
	sort.Strings(added)

	if strings.Join(added, ",") != strings.Join(twelve, ",") {
		t.Errorf("the sandbox exposes %v, want exactly %v", added, twelve)
	}
}

func globalNames(t *testing.T, vm *goja.Runtime) []string {
	t.Helper()
	value, err := vm.RunString("Object.getOwnPropertyNames(globalThis).join(',')")
	if err != nil {
		t.Fatalf("could not enumerate the global scope: %v", err)
	}
	return strings.Split(value.String(), ",")
}

func contains(haystack []string, needle string) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}
	return false
}

// TestACeilingSetHighMeansLooseRatherThanInstantlyTripped is arithmetic, and it
// is a test rather than a comment because the failure it guards is SILENT and
// INVERTED.
//
// The stopwatch compares the live heap against base + ceiling. That sum wraps,
// so the loosest ceiling anybody can express - the value reached for when the
// intent is "do not limit this" - used to land one BELOW the baseline and stop
// the first evaluation that ticked. Measured 2026-09-03: HeapAlloc 202414760,
// HeapAlloc + MaxUint64 = 202414759, and a PAC file that had done nothing came
// back memory_ceiling in no time at all.
//
// Nothing in this program builds a Sandbox yet - L2 arrives with P8-K3 - so this
// went in before the first caller rather than after. A limit that turns into its
// own opposite is the worst direction for one to fail in, and this one failed
// looking exactly like a real answer.
func TestACeilingSetHighMeansLooseRatherThanInstantlyTripped(t *testing.T) {
	loose := testSandbox()
	loose.Ceiling = math.MaxUint64

	result := loose.Evaluate("function FindProxyForURL(url, host) { return 'DIRECT'; }",
		"https://example.com/", "example.com")

	if result.Outcome == corepac.OutcomeMemoryCeiling {
		t.Fatalf("a PAC file that allocated nothing was stopped for allocating, under the loosest ceiling "+
			"this type can express: %s", result.Detail)
	}
	if result.Outcome != corepac.OutcomeAnswered {
		t.Fatalf("outcome %q where an answer was expected: %s", result.Outcome, result.Detail)
	}
	if result.Raw != "DIRECT" {
		t.Errorf("the file answered %q and should have answered DIRECT", result.Raw)
	}
}

// TestALooseCeilingAlsoHoldsForAFileTheStopwatchGETSTOWATCH is the test above
// made independent of a race, and it exists because the one above turned out to
// be decided by one.
//
// WHAT THE FULL MUTATION REGISTER MEASURED, 2026-09-05. The entry aimed at the
// saturation - replacing "if limit < base.HeapAlloc" with a condition that never
// fires - was caught 3 times out of 3 when run on its own, and SURVIVED in the
// full run of 528 entries. Nothing about the code differed between those runs.
// What differed was the machine: a full run keeps go build and go test busy, and
// under that load the stopwatch goroutine does not get scheduled before a file
// that answers immediately has already answered.
//
// WHY THAT MAKES THE TEST ABOVE INSUFFICIENT ON ITS OWN, and it is not that it
// is wrong. Its sentence - a file that allocated nothing must not be stopped for
// allocating - is true and worth pinning, so it stays untouched. But with the
// saturation removed the limit wraps to base.HeapAlloc-1, so the FIRST heap read
// trips it, and whether that read happens at all depends on the scheduler. A
// guard whose verdict depends on machine load teaches rerunning rather than
// looking - docs/22 section 2 says exactly that about flaky guards.
//
// WHAT THIS ONE CHANGES: the file RUNS for a while, so the stopwatch reads the
// heap dozens of times while it does. Measured tick is one millisecond and the
// budget here is two seconds, so a file taking tens of milliseconds leaves the
// stopwatch about a hundred chances to fire and still finishes with a margin of
// more than an order of magnitude. It is not a proof by construction - that
// would need the arithmetic reachable on its own - but it moves the verdict off
// a coin flip.
func TestALooseCeilingAlsoHoldsForAFileTheStopwatchGetsToWatch(t *testing.T) {
	loose := testSandbox()
	loose.Ceiling = math.MaxUint64

	// THE TIME BUDGET IS RAISED BECAUSE IT IS THE CONFOUNDING LIMIT HERE, not
	// out of caution. This test asks about the MEMORY ceiling, and a file that
	// runs long enough to be watched necessarily spends time doing it - so the
	// two-second budget the other tests share would be a second reason for a
	// verdict, and a failure could mean either. Caught by the race detector on
	// the first run: under -race goja is roughly twelve times slower, the loop
	// overran two seconds, and the outcome came back "time_limit" where the
	// test is not asking about time at all.
	loose.Budget = 20 * time.Second

	// A COUNTING LOOP RATHER THAN AN ALLOCATING ONE, deliberately. With the
	// saturation removed the limit trips on the first read whatever the heap
	// holds, so allocating would add nothing but noise - and a file that
	// allocates could trip a REAL ceiling on some other machine, which is a
	// second reason for a verdict this test does not want.
	//
	// The count is chosen so the file runs for tens of milliseconds unraced and
	// still finishes quickly under -race, which is the range where the stopwatch
	// gets dozens to hundreds of reads either way.
	const source = `function FindProxyForURL(url, host) {
		var n = 0;
		for (var i = 0; i < 300000; i++) { n = n + 1; }
		return n === 300000 ? 'DIRECT' : 'PROXY counted.wrong:1';
	}`

	result := loose.Evaluate(source, "https://example.com/", "example.com")

	if result.Outcome == corepac.OutcomeMemoryCeiling {
		t.Fatalf("a file that only counted was stopped for allocating, under the loosest ceiling "+
			"this type can express: %s", result.Detail)
	}
	if result.Outcome != corepac.OutcomeAnswered {
		t.Fatalf("outcome %q where an answer was expected: %s", result.Outcome, result.Detail)
	}
	if result.Raw != "DIRECT" {
		t.Errorf("the file answered %q and should have answered DIRECT", result.Raw)
	}
}
