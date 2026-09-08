package pac

import (
	"strings"
	"testing"
	"time"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// answer runs one inline PAC file through the test sandbox.
func answer(t *testing.T, body string) corepac.Result {
	t.Helper()
	return testSandbox().Evaluate("function "+Entry+"(url, host) {"+body+"}",
		"http://via.proxy.test/path", "via.proxy.test")
}

func TestTheShapesOfAnAnswer(t *testing.T) {
	for _, c := range []struct {
		name    string
		body    string
		outcome corepac.Outcome
		raw     string
	}{
		{"a proxy", `return "PROXY p.test:8080";`, corepac.OutcomeAnswered, "PROXY p.test:8080"},
		{"direct", `return "DIRECT";`, corepac.OutcomeAnswered, "DIRECT"},
		{"a fallback chain", `return "PROXY a.test:1; PROXY b.test:2; DIRECT";`, corepac.OutcomeAnswered, "PROXY a.test:1; PROXY b.test:2; DIRECT"},

		// An object with toString is a string by the time it reaches us -
		// measured by probe S12, and the reason read() does not test the type.
		{"an object with toString", `return { toString: function(){ return "DIRECT"; } };`, corepac.OutcomeAnswered, "DIRECT"},

		// null and undefined are the same state and neither is a directive.
		{"null", `return null;`, corepac.OutcomeNoAnswer, ""},
		{"undefined", `return undefined;`, corepac.OutcomeNoAnswer, ""},
		{"nothing at all", `var x = 1;`, corepac.OutcomeNoAnswer, ""},

		// An answer made only of separators said nothing, and that is not the
		// same as saying something unreadable.
		{"only semicolons", `return " ; ; ";`, corepac.OutcomeNoAnswer, ""},
		{"an empty string", `return "";`, corepac.OutcomeNoAnswer, ""},

		// A number is a string here, and an unreadable one - which is kept
		// rather than dropped, so nothing downstream can read it as DIRECT.
		{"a number", `return 42;`, corepac.OutcomeAnswered, "42"},
	} {
		result := answer(t, c.body)
		if result.Outcome != c.outcome || (c.raw != "" && result.Raw != c.raw) {
			t.Errorf("%s: %s %q, want %s %q (%s)", c.name, result.Outcome, result.Raw, c.outcome, c.raw, result.Detail)
		}
	}
}

func TestAnUnknownKeywordIsKeptRatherThanDropped(t *testing.T) {
	// Inviolable rule 15 in the small: a directive silently discarded would
	// make a report say a client goes direct when the file named something we
	// failed to read.
	result := answer(t, `return "WARP gateway.test:9; DIRECT";`)

	if len(result.Directives) != 2 {
		t.Fatalf("want both directives kept, got %d", len(result.Directives))
	}
	if result.Directives[0].Recognised {
		t.Error("WARP was reported as a keyword this program knows")
	}
	if result.Directives[0].Endpoint != "gateway.test:9" {
		t.Errorf("the endpoint of the unknown directive was lost: %q", result.Directives[0].Endpoint)
	}
	if !result.Directives[1].Recognised {
		t.Error("DIRECT after an unknown keyword stopped being recognised")
	}
}

func TestTheWaysAPACFileCanBeUnusable(t *testing.T) {
	for _, c := range []struct {
		name, source, mustSay string
	}{
		{"no entry point", `var x = 1;`, "defines no " + Entry},
		{"the entry point is not a function", `var ` + Entry + ` = 3;`, "defines no " + Entry},
		{"it does not parse", `function ` + Entry + `( {{{`, "could not be loaded"},
		{"it throws", `function ` + Entry + `(u, h) { throw new Error("no"); }`, "failed while answering"},
		{"it throws at load", `throw new Error("no");`, "could not be loaded"},
	} {
		result := testSandbox().Evaluate(c.source, "http://via.proxy.test/", "via.proxy.test")
		if result.Outcome != corepac.OutcomeMalformed {
			t.Errorf("%s: outcome %s, want %s", c.name, result.Outcome, corepac.OutcomeMalformed)
		}
		if !strings.Contains(result.Detail, c.mustSay) {
			t.Errorf("%s: detail %q does not say %q", c.name, result.Detail, c.mustSay)
		}
		if len(result.Directives) != 0 {
			t.Errorf("%s: an unusable file produced directives", c.name)
		}
	}
}

func TestAFileTooLargeIsRefusedBeforeItIsParsed(t *testing.T) {
	// docs/14 section 2.3: the check is on the bytes, not on the parsed result,
	// because after parsing it is already too late. The source below WOULD
	// parse, so an outcome of malformed here would mean the size check never
	// ran.
	sandbox := testSandbox()
	sandbox.MaxSource = 32

	result := sandbox.Evaluate("function "+Entry+"(u, h) { return \"DIRECT\"; }", "http://x.test/", "x.test")

	if result.Outcome != corepac.OutcomeTooLarge {
		t.Fatalf("outcome %s, want %s - a file that parses must still be refused on size", result.Outcome, corepac.OutcomeTooLarge)
	}
	if !strings.Contains(result.Detail, "before it was parsed") {
		t.Errorf("the reason does not say the file was refused before parsing: %q", result.Detail)
	}
}

func TestAFormWeCannotReadBlamesUsRatherThanTheFile(t *testing.T) {
	// dateRange has seven documented shapes. A file using one this program does
	// not cover must not quietly take the false branch - that is an unknown
	// answered as a no. It throws, and the message says the gap is ours.
	result := answer(t, `if (dateRange(1, 2, 3)) { return "DIRECT"; } return "PROXY p.test:1";`)

	if result.Outcome != corepac.OutcomeMalformed {
		t.Fatalf("outcome %s, want the run to say it could not read the file", result.Outcome)
	}
	if !strings.Contains(result.Detail, "certdoctor does not understand") {
		t.Errorf("the reason does not name us as the limitation: %q", result.Detail)
	}
}

func TestTheHelpersThatNeedTheWorldAnswerWithoutIt(t *testing.T) {
	// In P8-K1 nothing is wired behind the ports, and the sandbox has no
	// network BY CONSTRUCTION rather than by promise. These are the answers a
	// PAC file gets in that state, and each is the specification's own answer
	// for "could not be established" rather than an invention of ours.
	for _, c := range []struct{ name, body, want string }{
		{"dnsResolve", `return "PROXY " + (dnsResolve("a.test") === null ? "null.seen" : "resolved") + ":1";`, "PROXY null.seen:1"},
		{"myIpAddress", `return "PROXY " + myIpAddress() + ":1";`, "PROXY " + corepac.LoopbackFallback + ":1"},
		{"isResolvable", `return "PROXY " + (isResolvable("a.test") ? "yes" : "no") + ":1";`, "PROXY no:1"},
		{"isInNet", `return "PROXY " + (isInNet("a.test", "192.0.2.0", "255.255.255.0") ? "yes" : "no") + ":1";`, "PROXY no:1"},
	} {
		result := answer(t, c.body)
		if result.Outcome != corepac.OutcomeAnswered || result.Raw != c.want {
			t.Errorf("%s: %s %q, want %q", c.name, result.Outcome, result.Raw, c.want)
		}
	}
}

func TestTheClockInsideThePACFileIsOurs(t *testing.T) {
	// Measured 2026-09-02: goja exposes SetTimeSource, so Date inside a PAC file
	// reads THIS run's clock. That is what makes timeRange and dateRange answer
	// about the moment the user is asking about, and what makes two runs of one
	// binary agree.
	sandbox := testSandbox()
	moment := time.Date(2026, time.September, 2, 14, 30, 0, 0, time.UTC)
	sandbox.Ports.Now = func() time.Time { return moment }

	result := sandbox.Evaluate("function "+Entry+`(u, h) { return "PROXY t" + new Date().getTime() + ":1"; }`,
		"http://x.test/", "x.test")

	want := "PROXY t1788359400000:1"
	if result.Raw != want {
		t.Errorf("the PAC file saw %q, want %q - Date must come from this run's clock", result.Raw, want)
	}
}

func TestRandomnessIsPinnedAndReported(t *testing.T) {
	// The sandbox pins Math.random so a report is reproducible. A file that
	// used it took ONE of the branches a browser could take, so the result says
	// so rather than leaving the caveat in a comment nobody reads.
	steady := answer(t, `return "PROXY p" + Math.floor(Math.random() * 1000) + ".test:1";`)
	again := answer(t, `return "PROXY p" + Math.floor(Math.random() * 1000) + ".test:1";`)

	if steady.Raw != again.Raw {
		t.Errorf("two runs of one file disagreed: %q then %q", steady.Raw, again.Raw)
	}
	if !steady.UsedRandomness {
		t.Error("a file that called Math.random was not reported as having done so")
	}
	if plain := answer(t, `return "DIRECT";`); plain.UsedRandomness {
		t.Error("a file that never called Math.random was reported as having done so")
	}
}

func TestEachEvaluationGetsItsOwnRuntime(t *testing.T) {
	// THE STOPWATCH RESTS ON THIS. It is not waited for, so it can outlive an
	// evaluation by one tick; that is only safe because a late interrupt lands
	// on a Runtime nobody will use again. A file that leaves a global behind
	// must therefore not be able to see it on the next evaluation.
	sandbox := testSandbox()
	first := sandbox.Evaluate("function "+Entry+`(u, h) { globalThis.left = "behind"; return "DIRECT"; }`,
		"http://x.test/", "x.test")
	if first.Outcome != corepac.OutcomeAnswered {
		t.Fatalf("the first evaluation failed: %s", first.Detail)
	}

	second := sandbox.Evaluate("function "+Entry+
		`(u, h) { return "PROXY " + (typeof globalThis.left === "undefined" ? "clean" : "dirty") + ":1"; }`,
		"http://x.test/", "x.test")
	if second.Raw != "PROXY clean:1" {
		t.Errorf("state survived from one evaluation to the next: %q", second.Raw)
	}
}

func TestARunawayFileDoesNotPoisonTheNextOne(t *testing.T) {
	// The other half of the same promise: after a file is interrupted, the next
	// one must get a full budget rather than an engine still carrying the
	// interrupt. Probe S12 measured that a Runtime keeps working after
	// ClearInterrupt; building a fresh one sidesteps the question entirely, and
	// this is the test that says so.
	sandbox := testSandbox()
	sandbox.Budget = 200 * time.Millisecond

	stopped := sandbox.Evaluate(benchPAC(t, "runaway.pac"), "http://x.test/", "x.test")
	if stopped.Outcome != corepac.OutcomeTimeLimit {
		t.Fatalf("the runaway file was not stopped: %s %s", stopped.Outcome, stopped.Detail)
	}

	after := sandbox.Evaluate("function "+Entry+`(u, h) { return "DIRECT"; }`, "http://x.test/", "x.test")
	if after.Outcome != corepac.OutcomeAnswered || after.Raw != "DIRECT" {
		t.Errorf("the evaluation after an interrupted one gave %s %q, want an ordinary answer (%s)",
			after.Outcome, after.Raw, after.Detail)
	}
}

func TestAZeroSandboxRefusesRatherThanRunsUnbounded(t *testing.T) {
	// A value nobody set must fail towards refusing. A zero MaxSource refuses
	// every file that is not empty, which is the safe direction.
	var unset Sandbox
	result := unset.Evaluate("function "+Entry+`(u, h) { return "DIRECT"; }`, "http://x.test/", "x.test")
	if result.Outcome != corepac.OutcomeTooLarge {
		t.Errorf("an unconfigured sandbox gave %s, want it to refuse", result.Outcome)
	}
}

func TestTheSandboxRefusesToBuildWithAHelperMissing(t *testing.T) {
	// helperNames and the map that builds them are two lists on purpose, so a
	// disagreement is visible. If they ever come apart, refusing to build is the
	// only safe direction: a PAC file calling a name that quietly went missing
	// would fail as though the FILE were wrong.
	helperNames = append(helperNames, "notAHelper")
	defer func() { helperNames = helperNames[:len(helperNames)-1] }()

	result := testSandbox().Evaluate("function "+Entry+`(u, h) { return "DIRECT"; }`, "http://x.test/", "x.test")
	if result.Outcome != corepac.OutcomeMalformed {
		t.Fatalf("outcome %s, want the sandbox to refuse to build", result.Outcome)
	}
	if !strings.Contains(result.Detail, "sandbox could not be built") {
		t.Errorf("the reason does not say the sandbox failed to build: %q", result.Detail)
	}
}

func TestTheThreeTimeHelpersAnswerRatherThanAccusingTheFile(t *testing.T) {
	// Until 2026-09-08 Ports.Now was nil in production while every test wired
	// it, so this package measured a rule the shipped binary did not follow.
	// Measured against the binary on a file whose only sin was
	// weekdayRange("MON","FRI"): OutcomeMalformed, L2 UNKNOWN
	// unrecognized_output, and a sentence saying the PAC file failed - the
	// vocabulary this product keeps for a file that will not parse, spent on a
	// legal one.
	//
	// EACH RANGE BELOW IS TRUE ON EVERY DAY AND AT EVERY HOUR on purpose, so
	// this test asserts that the helper ANSWERED rather than what the answer
	// was. A range that depended on the calendar would be a test that fails one
	// day a week.
	for _, c := range []struct{ name, body string }{
		{"weekdayRange", `if (weekdayRange("SUN", "SAT")) { return "PROXY p.test:1"; } return "DIRECT";`},
		{"dateRange", `if (dateRange(1, 31)) { return "PROXY p.test:1"; } return "DIRECT";`},
		{"timeRange", `if (timeRange(0, 24)) { return "PROXY p.test:1"; } return "DIRECT";`},
	} {
		result := answer(t, c.body)
		if result.Outcome != corepac.OutcomeAnswered {
			t.Errorf("%s: outcome %s (%s), want an answer - a legal file must not be called broken",
				c.name, result.Outcome, result.Detail)
			continue
		}
		if result.Raw != "PROXY p.test:1" {
			t.Errorf("%s: answered %q, want the always-true branch", c.name, result.Raw)
		}
		if !result.UsedClock {
			t.Errorf("%s: answered without recording that it read the clock, so the report would not "+
				"say this answer has a date on it", c.name)
		}
	}
}

func TestTheClockIsPinnedForOneEvaluation(t *testing.T) {
	// A file may call two time helpers, and a boundary crossed between them
	// would have it answering about two different moments - a branch no browser
	// would take. So the instant is taken once and handed to every helper.
	//
	// THE CLOCK HERE JUMPS THREE DAYS ON EVERY CALL, which no real clock does.
	// That is the point: an unpinned build would let the second helper see a
	// Thursday while the first saw a Monday, and this file reports both.
	monday := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	calls := 0
	sandbox := testSandbox()
	sandbox.Ports.Now = func() time.Time {
		calls++
		return monday.AddDate(0, 0, 3*(calls-1))
	}

	result := sandbox.Evaluate("function "+Entry+
		`(u, h) { return "PROXY " + weekdayRange("MON","MON") + "-" + weekdayRange("THU","THU") + ":1"; }`,
		"http://x.test/", "x.test")

	if want := "PROXY true-false:1"; result.Raw != want {
		t.Errorf("the file saw %q, want %q - both helpers must read ONE instant", result.Raw, want)
	}
	if calls != 1 {
		t.Errorf("the clock was read %d time(s), want exactly 1 for one evaluation", calls)
	}
}

func TestOnlyAFileThatAskedTheClockIsSaidToHaveAskedIt(t *testing.T) {
	// The caveat this flag produces tells a reader the answer has a date on it.
	// Set on a file that never asked, it would put a date on an answer that has
	// none - and a caveat nobody can act on is the shape docs/19 forbids by
	// calling these sentences measured rather than precautionary.
	//
	// THE Date ROW IS THE SECOND ROUTE AND IT WAS OPEN ALL ALONG. Measured
	// 2026-09-08: with Ports.Now nil the engine used its own default clock, so
	// new Date() answered while our three helpers threw. A file deciding that
	// way has just as much of a date on its answer.
	for _, c := range []struct {
		name string
		body string
		want bool
	}{
		{"no clock at all", `if (isPlainHostName(host)) { return "DIRECT"; } return "PROXY p.test:1";`, false},
		{"a helper", `if (timeRange(0, 24)) { return "PROXY p.test:1"; } return "DIRECT";`, true},
		{"the file's own Date", `return "PROXY d" + new Date().getDay() + ".test:1";`, true},
	} {
		result := answer(t, c.body)
		if result.Outcome != corepac.OutcomeAnswered {
			t.Fatalf("%s: outcome %s (%s)", c.name, result.Outcome, result.Detail)
		}
		if result.UsedClock != c.want {
			t.Errorf("%s: UsedClock %v, want %v", c.name, result.UsedClock, c.want)
		}
	}
}
