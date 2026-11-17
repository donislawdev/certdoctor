package main

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/pac"
	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// dieVariable makes the test binary, started as a PAC sandbox, end at once
// the way the Go runtime ends a process it cannot keep going - the one death
// no PAC file can be counted on to cause.
const dieVariable = "CERTDOCTOR_TEST_PAC_SANDBOX_DIES"

// TestMain lets this package's tests start the real process: startPACSandbox
// starts os.Executable, which under go test is this test binary, so the binary
// has to be able to be the sandbox too.
func TestMain(m *testing.M) {
	if isPACSandbox(os.Args) {
		if os.Getenv(dieVariable) != "" {
			fmt.Fprintln(os.Stderr, "fatal error: planted by the test")
			os.Exit(2)
		}
		os.Exit(servePACSandbox())
	}
	os.Exit(m.Run())
}

// liveIsolated is the evaluator the program wires, with its own limits and a
// resolver of the test's.
func liveIsolated(resolve func(string) ([]string, error)) pac.Isolated {
	return pac.Isolated{Start: startPACSandbox, Program: toolVersion, Allowance: pacStartAllowance, Sandbox: pac.Sandbox{
		Ports:   corepac.Ports{Resolve: resolve, Now: time.Now},
		Budget:  pacEvaluationBudget,
		Ceiling: pacCeiling, MaxSource: pacSourceLimit, MaxStack: pacStackLimit, MaxLookups: pacMaxLookups,
		MaxAnswer: pacAnswerLimit, MaxDirectives: pacDirectiveLimit,
	}}
}

func entry(body string) string { return "function " + pac.Entry + "(url, host) { " + body + " }" }

// TestAPACFileThatEndedTheRunNowEndsOnlyItsOwnProcess is OBS199 closed, on the
// real process: these lines ended the whole program with no report, because
// the built-ins they call allocate in native code the stopwatch cannot reach.
// They now end the process they run in, the run carries on and the row says
// what happened. Measured with the program before ADR150: each one killed it.
//
// Half a gigabyte is above the watchdog's line on every machine, so that row
// is memory_ceiling everywhere; ten gigabytes may instead be refused by the
// system before the watchdog sees anything - Windows does that past what it
// can commit - and then the row says the evaluator failed, with the runtime's
// own words. Either way this process is still here to say it.
func TestAPACFileThatEndedTheRunNowEndsOnlyItsOwnProcess(t *testing.T) {
	for _, c := range []struct {
		body string
		want []corepac.Outcome
	}{
		{`return "x".repeat(5e8);`, []corepac.Outcome{corepac.OutcomeMemoryCeiling}},
		{`return "x".repeat(1e10);`, []corepac.Outcome{corepac.OutcomeMemoryCeiling, corepac.OutcomeEvaluatorFailed}},
		{`return "".padStart(1e10);`, []corepac.Outcome{corepac.OutcomeMemoryCeiling, corepac.OutcomeEvaluatorFailed}},
	} {
		start := time.Now()
		result := liveIsolated(nil).Evaluate(context.Background(), entry(c.body), "http://x.test/", "x.test")
		elapsed := time.Since(start)
		t.Logf("%-28s -> %-16s %v %s", c.body, result.Outcome, elapsed.Round(time.Millisecond), result.Detail)
		if !containsOutcome(c.want, result.Outcome) {
			t.Errorf("%s came back %s (%s), want one of %v", c.body, result.Outcome, result.Detail, c.want)
		}
		if limit := pacEvaluationBudget + pacStartAllowance + 2*time.Second; elapsed > limit {
			t.Errorf("%s took %v, past %v", c.body, elapsed, limit)
		}
	}
}

// TestAFileStuckInNativeCodeIsEndedByTheClock: join grows its string with the
// collector freeing as it goes, so no memory line is crossed, and the stopwatch
// cannot interrupt it - the parent's clock is what ends it.
func TestAFileStuckInNativeCodeIsEndedByTheClock(t *testing.T) {
	start := time.Now()
	result := liveIsolated(nil).Evaluate(context.Background(), entry(`return new Array(15e8).join("x");`), "http://x.test/", "x.test")
	elapsed := time.Since(start)
	if result.Outcome != corepac.OutcomeTimeLimit && result.Outcome != corepac.OutcomeMemoryCeiling {
		t.Errorf("outcome %s (%s), want time_limit or memory_ceiling", result.Outcome, result.Detail)
	}
	if limit := pacEvaluationBudget + pacStartAllowance + time.Second; elapsed > limit {
		t.Errorf("it took %v, past %v - the clock did not end it", elapsed, limit)
	}
}

// TestAnHonestFileAnswersThroughTheProcessAndItsLookups: an answer and the names
// asked on the way come back, the names through this process's resolver.
func TestAnHonestFileAnswersThroughTheProcessAndItsLookups(t *testing.T) {
	var asked []string
	resolve := func(host string) ([]string, error) {
		asked = append(asked, host)
		return []string{"10.0.0.7"}, nil
	}
	result := liveIsolated(resolve).Evaluate(context.Background(),
		entry(`return isInNet(dnsResolve("gw.test"), "10.0.0.0", "255.0.0.0") ? "PROXY p.test:3128; DIRECT" : "DIRECT";`),
		"http://x.test/", "x.test")
	if result.Outcome != corepac.OutcomeAnswered || result.Raw != "PROXY p.test:3128; DIRECT" {
		t.Fatalf("%s %q (%s)", result.Outcome, result.Raw, result.Detail)
	}
	if want := []string{"gw.test"}; !reflect.DeepEqual(asked, want) || !reflect.DeepEqual(result.Asked, want) {
		t.Errorf("resolver asked %v, row says %v, want %v", asked, result.Asked, want)
	}
}

// TestAProcessThatDiesSaysHow: the code and the first line it wrote reach the
// row, and nothing in this program read that line for its meaning.
func TestAProcessThatDiesSaysHow(t *testing.T) {
	t.Setenv(dieVariable, "1")
	result := liveIsolated(nil).Evaluate(context.Background(), entry(`return "DIRECT";`), "http://x.test/", "x.test")
	if result.Outcome != corepac.OutcomeEvaluatorFailed ||
		!strings.Contains(result.Detail, "exit code 2: fatal error: planted by the test") {
		t.Errorf("%s %q", result.Outcome, result.Detail)
	}
}

// TestOnlyTheArgumentAloneMakesASandbox: the argument after a URL, beside
// others or spelled differently is a command line like any other.
func TestOnlyTheArgumentAloneMakesASandbox(t *testing.T) {
	for args, want := range map[string]bool{
		"certdoctor --pac-sandbox":                     true,
		"certdoctor --pac-sandbox --json":              false,
		"certdoctor https://example.com --pac-sandbox": false,
		"certdoctor --pac-sandbox=1":                   false,
		"certdoctor -pac-sandbox":                      false,
		"certdoctor":                                   false,
	} {
		if got := isPACSandbox(strings.Fields(args)); got != want {
			t.Errorf("%q: %v, want %v", args, got, want)
		}
	}
}

func containsOutcome(list []corepac.Outcome, o corepac.Outcome) bool {
	for _, x := range list {
		if x == o {
			return true
		}
	}
	return false
}
