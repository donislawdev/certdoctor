package pac

import (
	"strings"
	"testing"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// evaluateSource runs one snippet and hands back the result.
func evaluateSource(s Sandbox, body string) corepac.Result {
	return s.Evaluate("function "+Entry+"(url, host) { "+body+" }",
		"https://api.example.com/", "api.example.com")
}

// TestAHelperWithNoPortBehindItIsRecorded is the mechanism the layer's honesty
// rests on, and the reason is written at length on pac.Ports.IsResolvable: the
// PAC specification gives that function ONE boolean and no way to say "nobody
// could be asked", so a run with no resolver hands the file a false and the file
// takes a branch a browser would not take. Nothing in the answer shows it. This
// is what shows it.
func TestAHelperWithNoPortBehindItIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		call string
		want string
	}{
		{`isResolvable(host); return "DIRECT";`, "isResolvable"},
		{`isInNet(host, "10.0.0.0", "255.0.0.0"); return "DIRECT";`, "isInNet"},
		{`dnsResolve(host); return "DIRECT";`, "dnsResolve"},
		{`myIpAddress(); return "DIRECT";`, "myIpAddress"},
	} {
		result := evaluateSource(testSandbox(), tc.call)
		if result.Outcome != corepac.OutcomeAnswered {
			t.Fatalf("%s did not answer: %s / %s", tc.want, result.Outcome, result.Detail)
		}
		if len(result.Unanswered) != 1 || result.Unanswered[0] != tc.want {
			t.Errorf("calling %s recorded %v, want exactly [%s]", tc.want, result.Unanswered, tc.want)
		}
	}
}

// TestTheEightPureHelpersAreNeverRecorded is the other half. Recording one of
// them would make the layer refuse to rest a verdict on a file that asked
// nothing of the world - an UNKNOWN where a PASS was earned.
func TestTheEightPureHelpersAreNeverRecorded(t *testing.T) {
	result := evaluateSource(testSandbox(), `
		isPlainHostName(host);
		dnsDomainIs(host, ".example.com");
		localHostOrDomainIs(host, "api.example.com");
		dnsDomainLevels(host);
		shExpMatch(host, "api.*");
		weekdayRange("MON", "FRI");
		dateRange(1, 31);
		timeRange(0, 23);
		return "DIRECT";`)

	if result.Outcome != corepac.OutcomeAnswered {
		t.Fatalf("the eight pure helpers did not answer: %s / %s", result.Outcome, result.Detail)
	}
	if len(result.Unanswered) != 0 {
		t.Errorf("helpers needing nothing from the world were recorded as unanswered: %v", result.Unanswered)
	}
}

// TestAHelperWithAPortBehindItIsNotRecorded pins the condition rather than the
// call: what is recorded is a helper this run had NOTHING behind, so supplying
// the port has to empty the list.
func TestAHelperWithAPortBehindItIsNotRecorded(t *testing.T) {
	sandbox := testSandbox()
	sandbox.Ports.Resolve = func(string) ([]string, error) { return []string{"192.0.2.10"}, nil }
	sandbox.Ports.LocalAddress = func() (string, error) { return "192.0.2.7", nil }

	result := evaluateSource(sandbox, `
		isResolvable(host);
		isInNet(host, "10.0.0.0", "255.0.0.0");
		dnsResolve(host);
		myIpAddress();
		return "DIRECT";`)

	if len(result.Unanswered) != 0 {
		t.Errorf("helpers with ports behind them were recorded as unanswered: %v", result.Unanswered)
	}
}

// TestTheRecordedListIsInOneOrderHoweverTheFileCalledThem is the determinism
// guard reaching one field further. Two runs of one binary against one file have
// to produce one document, and a map's range order is not stable even inside a
// single run.
func TestTheRecordedListIsInOneOrderHoweverTheFileCalledThem(t *testing.T) {
	forwards := evaluateSource(testSandbox(),
		`isResolvable(host); isInNet(host, "10.0.0.0", "255.0.0.0"); dnsResolve(host); myIpAddress(); return "DIRECT";`)
	backwards := evaluateSource(testSandbox(),
		`myIpAddress(); dnsResolve(host); isInNet(host, "10.0.0.0", "255.0.0.0"); isResolvable(host); return "DIRECT";`)

	want := "isResolvable,isInNet,dnsResolve,myIpAddress"
	if got := strings.Join(forwards.Unanswered, ","); got != want {
		t.Errorf("calling them forwards recorded %q, want %q", got, want)
	}
	if got := strings.Join(backwards.Unanswered, ","); got != want {
		t.Errorf("calling them backwards recorded %q, want the same %q", got, want)
	}
}

// TestOneHelperCalledTwiceIsRecordedOnce keeps the sentence the layer builds
// from this readable. A PAC file resolving a name in a loop would otherwise
// produce a caveat naming one helper fifty times.
func TestOneHelperCalledTwiceIsRecordedOnce(t *testing.T) {
	result := evaluateSource(testSandbox(),
		`for (var i = 0; i < 5; i++) { dnsResolve(host); } return "DIRECT";`)

	if len(result.Unanswered) != 1 {
		t.Errorf("one helper called five times was recorded as %v", result.Unanswered)
	}
}

// TestAFileThatWentLookingAndThenBrokeStillSaysSo covers the paths that are not
// an answer. RunString has already run the file's top level by then, and
// caching a helper into a variable there is a real idiom - so a path that
// dropped the list would report "no entry point" about a file that had already
// gone looking for a resolver.
func TestAFileThatWentLookingAndThenBrokeStillSaysSo(t *testing.T) {
	noEntryPoint := testSandbox().Evaluate(`var cached = dnsResolve("api.example.com");`,
		"https://api.example.com/", "api.example.com")
	if noEntryPoint.Outcome != corepac.OutcomeMalformed {
		t.Fatalf("a file with no entry point answered %s", noEntryPoint.Outcome)
	}
	if len(noEntryPoint.Unanswered) != 1 {
		t.Errorf("a file that asked at its top level and defined no entry point recorded %v", noEntryPoint.Unanswered)
	}

	threw := evaluateSource(testSandbox(), `dnsResolve(host); throw new Error("no");`)
	if threw.Outcome != corepac.OutcomeMalformed {
		t.Fatalf("a file that threw answered %s", threw.Outcome)
	}
	if len(threw.Unanswered) != 1 {
		t.Errorf("a file that asked and then threw recorded %v", threw.Unanswered)
	}
}
