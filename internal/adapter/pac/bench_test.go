package pac

import (
	"strings"
	"testing"
	"time"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// TestTheBenchPACFiles runs every PAC file the bench serves and prints what
// happened to each.
//
// THIS IS THE SLICE'S COMMAND-AND-EFFECT PAIR. Run it with -v and every file in
// testbed/pac/files gets a line saying what the sandbox made of it. Eight files,
// eight named outcomes, and the three that are limits show the time they took -
// which is the difference between "the tests pass" and being able to see that a
// runaway PAC file is stopped in milliseconds rather than never.
//
// THE EXPECTATIONS ARE THE BENCH'S, NOT THIS TEST'S. hostile.pac and broken.pac
// have expectation files written in P4c, before an evaluator existed, and those
// are read rather than restated. The other six had their expectations written
// into the PAC files themselves as comments, in the same slice and for the same
// reason, and they are transcribed here.
func TestTheBenchPACFiles(t *testing.T) {
	for _, c := range []struct {
		file    string
		host    string
		budget  time.Duration
		outcome corepac.Outcome
		raw     string
	}{
		// The main file, one row per branch, further down.
		{"proxy.pac", "via.proxy.test", 2 * time.Second, corepac.OutcomeAnswered, "PROXY 172.28.0.128:3128"},

		// The guard file. Any other answer is a leak with a name attached.
		{"hostile.pac", "via.proxy.test", 2 * time.Second, corepac.OutcomeAnswered, "PROXY none.seen:1"},

		// "UNKNOWN with a reason, never an exception and never PASS" - and
		// never DIRECT, which is what libproxy answers and what our contract
		// forbids.
		{"broken.pac", "via.proxy.test", 2 * time.Second, corepac.OutcomeMalformed, ""},

		// Legal JavaScript, no answer at all. goja exports null as the STRING
		// "null", so this row is what stops a proxy called null reaching a
		// report.
		{"null.pac", "via.proxy.test", 2 * time.Second, corepac.OutcomeNoAnswer, ""},

		// The three limits of sandbox condition 3.
		{"runaway.pac", "via.proxy.test", 300 * time.Millisecond, corepac.OutcomeTimeLimit, ""},
		{"bomb.pac", "via.proxy.test", 5 * time.Second, corepac.OutcomeMemoryCeiling, ""},
		{"recursion.pac", "via.proxy.test", 5 * time.Second, corepac.OutcomeStackLimit, ""},

		// The file that gives the engine choice a witness: otto could not
		// compile this expression, so it would have called a working machine's
		// PAC broken.
		{"lookahead.pac", "app.internal.example", 2 * time.Second, corepac.OutcomeAnswered, "DIRECT"},
		{"lookahead.pac", "build.internal.example", 2 * time.Second, corepac.OutcomeAnswered, "PROXY 172.28.0.128:3128"},
	} {
		sandbox := testSandbox()
		sandbox.Budget = c.budget

		start := time.Now()
		result := sandbox.Evaluate(benchPAC(t, c.file), "http://"+c.host+"/", c.host)
		elapsed := time.Since(start)

		t.Logf("%-14s %-24s -> %-15s %-26q %v",
			c.file, c.host, result.Outcome, result.Raw, elapsed.Round(time.Millisecond))

		if result.Outcome != c.outcome {
			t.Errorf("%s on %s: outcome %s, want %s (%s)", c.file, c.host, result.Outcome, c.outcome, result.Detail)
			continue
		}
		if c.raw != "" && result.Raw != c.raw {
			t.Errorf("%s on %s: answered %q, want %q", c.file, c.host, result.Raw, c.raw)
		}
	}
}

// TestTheBrokenPACNeverAnswersDirect is the bench's loudest expectation, kept as
// a test of its own because it is the one a future session is most likely to
// undo while making something else work.
//
// libproxy answers direct:// here, most software does the same, and doing so
// would make certdoctor agree with the machine's own silence instead of breaking
// it. The expectation file says this in capitals; this is it enforced.
func TestTheBrokenPACNeverAnswersDirect(t *testing.T) {
	mustNotSay := benchExpectation(t, "pac-broken.txt", "l2_must_not_say")

	result := testSandbox().Evaluate(benchPAC(t, "broken.pac"), "http://via.proxy.test/", "via.proxy.test")

	if result.Outcome == corepac.OutcomeAnswered {
		t.Fatalf("a PAC file that does not parse produced an answer: %q", result.Raw)
	}
	if len(result.Directives) != 0 {
		t.Errorf("a PAC file that does not parse produced %d directives", len(result.Directives))
	}
	if strings.Contains(result.Raw, mustNotSay) {
		t.Errorf("the one answer that must never come out of a broken PAC came out: %q", result.Raw)
	}
	if result.Detail == "" {
		t.Error("a refused PAC file must carry a reason, never silence")
	}
}

// TestEveryBranchOfTheBenchPACIsReachable walks the main file's six rules.
//
// A RULE NO NAME CAN REACH IS A RULE NOBODY CHECKS, which is what the bench file
// says about itself. These names come from the bench's own zones, so this test
// also fails if somebody edits the PAC file and leaves a branch stranded.
func TestEveryBranchOfTheBenchPACIsReachable(t *testing.T) {
	source := benchPAC(t, "proxy.pac")

	for _, c := range []struct{ host, want string }{
		// isPlainHostName: a single label never leaves the network.
		{"buildbox", "DIRECT"},
		// shExpMatch on "direct.*": the exception rule, and the reason this
		// product exists - a proxy is configured and this name bypasses it.
		{"direct.proxy.test", "DIRECT"},
		// shExpMatch on "auth.*": the name that must meet a proxy demanding
		// credentials.
		{"auth.proxy.test", "PROXY 172.28.0.128:3129"},
		// dnsDomainIs on the suffix, and the apex spelled out separately
		// because a suffix match cannot reach it.
		{"via.proxy.test", "PROXY 172.28.0.128:3128"},
		{"proxy.test", "PROXY 172.28.0.128:3128"},
		{"partner.test", "PROXY 172.28.0.128:3128"},
		// The fall-through: a name absent from every rule quietly bypasses the
		// proxy, which is the common shape and worth seeing.
		{"unknown.example", "DIRECT"},
	} {
		result := testSandbox().Evaluate(source, "http://"+c.host+"/", c.host)
		if result.Outcome != corepac.OutcomeAnswered || result.Raw != c.want {
			t.Errorf("%s -> %s %q, want an answer of %q", c.host, result.Outcome, result.Raw, c.want)
		}
	}
}
