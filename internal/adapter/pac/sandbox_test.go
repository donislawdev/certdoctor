package pac

import (
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
