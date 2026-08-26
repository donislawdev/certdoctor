package tcp

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// closer counts how many times it was closed, and refuses to be closed twice.
//
// DOUBLE CLOSE IS COUNTED AS A DEFECT RATHER THAN IGNORED. "Closed exactly once
// on every path" is the property that is checkable everywhere, unlike counting
// file descriptors, which is not portable and answers a question about the
// operating system - docs/22 section 6a.
//
// IT COUNTS ATOMICALLY BECAUSE THE LAYER NOW CLOSES FROM SEVERAL GOROUTINES.
// docs/22 section 2 ends with that warning and this is the file it was written
// about: a double that races is a flaky test, and a flaky test teaches retrying
// instead of looking.
type closer struct {
	closed atomic.Int64
	failed atomic.Bool
}

func (c *closer) Close() error {
	if c.closed.Add(1) > 1 {
		c.failed.Store(true)
	}
	return nil
}

// handles collects the connections a test handed out, from whichever goroutine
// asked for one.
type handles struct {
	mu   sync.Mutex
	kept []*closer
}

func (h *handles) fresh() *closer {
	made := &closer{}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.kept = append(h.kept, made)
	return made
}

func (h *handles) all() []*closer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*closer(nil), h.kept...)
}

// workingInput reads the clock through safeClock, the one this package already
// has. A SECOND CLOCK OF ITS OWN WOULD BE A COPY OF A RULE THAT ALREADY HAS ONE
// - OBS50, measured on a boundary function - and nothing here asserts a
// particular number of milliseconds, only that an attempt which never left this
// machine carries none.
func workingInput(connect Connect) Input {
	return Input{
		Addresses:  func() []string { return []string{"192.0.2.10"} },
		Port:       443,
		Connect:    connect,
		Now:        safeClock(),
		PerAddress: 2 * time.Second,
	}
}

func connectFailing(err error) Connect {
	return func(context.Context, string, int) (io.Closer, error) { return nil, err }
}

func rowsOf(r Result) []report.TCPConnect {
	var out []report.TCPConnect
	for _, finding := range r.Findings {
		out = append(out, *finding.TCPConnect)
	}
	return out
}

// TestAskRefusesWhenItWasGivenNoWayToTry covers every missing port, and each one
// has to name ITSELF.
//
// A missing port is a defect on our side, and reporting it as a machine that
// cannot connect would accuse somebody's network of our own omission - inviolable
// rule 15. The addresses port is in here too: not knowing what to connect to is
// different from knowing there is nothing.
func TestAskRefusesWhenItWasGivenNoWayToTry(t *testing.T) {
	cases := []struct {
		name   string
		damage func(*Input)
		says   string
	}{
		{"no way to connect", func(in *Input) { in.Connect = nil }, "open a connection"},
		{"no clock", func(in *Input) { in.Now = nil }, "clock"},
		{"no way to learn the addresses", func(in *Input) { in.Addresses = nil }, "addresses"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := workingInput(connectFailing(ErrRefused))
			tc.damage(&in)

			got := Ask(context.Background(), in)
			if got.Status != status.Unknown || got.Reason != status.ReasonProbeError {
				t.Errorf("a missing port came back as %s/%s, want unknown with a probe error", got.Status, got.Reason)
			}
			if !strings.Contains(got.Detail, tc.says) {
				t.Errorf("the sentence does not say which port was missing: %q", got.Detail)
			}
			if got.Findings != nil {
				t.Errorf("a layer that could not look handed back findings: %v", got.Findings)
			}
		})
	}
}

// TestANameWithNoAddressesIsNotThisLayersFailure is the boundary between two
// layers, and getting it wrong counts one fault twice.
//
// A name that resolves nowhere is L1's finding and L1 already reports FAIL for
// it. This layer saying FAIL as well would make one broken name look like two
// broken things in the verdict, and the reader would go looking for a second
// cause that does not exist.
func TestANameWithNoAddressesIsNotThisLayersFailure(t *testing.T) {
	in := workingInput(connectFailing(ErrRefused))
	in.Addresses = func() []string { return nil }

	got := Ask(context.Background(), in)
	if got.Status != status.Unknown || got.Reason != status.ReasonNothingToCheck {
		t.Errorf("a name with no addresses came back as %s/%s, want unknown with nothing to check",
			got.Status, got.Reason)
	}
	if !strings.Contains(got.Detail, "nothing to connect to") {
		t.Errorf("the sentence does not say why there was nothing to do: %q", got.Detail)
	}
}

// TestEveryWayAnAttemptCanFailKeepsItsOwnWord is the table this layer exists for.
//
// "Cannot connect" is what a browser says, and it is the reason somebody reaches
// for this tool. Refused, timed out, reset and unreachable send a person to four
// different places, and collapsing them would rebuild the very message they came
// here to get past.
func TestEveryWayAnAttemptCanFailKeepsItsOwnWord(t *testing.T) {
	// THE STATUS COLUMN IS PER CASE RATHER THAN ONE ASSERTION FOR ALL SIX, AND
	// THAT IS ADR58. Five of these are the network answering, or failing to, and
	// the layer is right to call that a failure. The sixth is OUR OWN allowed set
	// refusing, so nothing was ever tried - and FAIL there says somebody's
	// address would not accept a connection about an address nothing dialled.
	cases := []struct {
		err        error
		want       report.ConnectOutcome
		wantStatus status.Status
	}{
		{ErrRefused, report.OutcomeRefused, status.Fail},
		{ErrTimeout, report.OutcomeTimeout, status.Fail},
		{ErrUnreachable, report.OutcomeUnreachable, status.Fail},
		{ErrReset, report.OutcomeReset, status.Fail},
		{ErrRefusedByRule, report.OutcomeRefusedByRule, status.Unknown},
		// A failure nobody anticipated must never read as a success, and it must
		// not claim to be one of the diagnoses either.
		{errors.New("something nobody wrote a case for"), report.OutcomeReset, status.Fail},
	}

	for _, tc := range cases {
		got := Ask(context.Background(), workingInput(connectFailing(tc.err)))
		rows := rowsOf(got)
		if len(rows) != 1 {
			t.Fatalf("%v produced %d rows", tc.err, len(rows))
		}
		if rows[0].Outcome != tc.want {
			t.Errorf("%v came out as %q, want %q", tc.err, rows[0].Outcome, tc.want)
		}
		if got.Status != tc.wantStatus {
			t.Errorf("%v left the layer at %s, want %s", tc.err, got.Status, tc.wantStatus)
		}
		if broken := got.Findings[0].Breach(); broken != "" {
			t.Errorf("%v produced a row its own contract refuses: %s", tc.err, broken)
		}
	}
}

// TestNothingEstablishedIsToldApartFromNothingFound is ADR20 applied to a seam,
// and both halves are here because either sentence alone reads as reasonable.
//
// An empty list is a MEASUREMENT: the layer above looked and found no address.
// A nil list means it established nothing at all - it never ran, or its answer
// broke its own contract and was thrown away. Saying "the name resolved to no
// address" in the second case is a claim about somebody's DNS assembled from our
// own discarded work.
func TestNothingEstablishedIsToldApartFromNothingFound(t *testing.T) {
	in := workingInput(connectFailing(ErrRefused))

	in.Addresses = func() []string { return nil }
	got := Ask(context.Background(), in)
	if got.Status != status.Unknown || got.Reason != status.ReasonNothingToCheck {
		t.Errorf("a layer handed nothing answered %s/%s", got.Status, got.Reason)
	}
	if !strings.Contains(got.Detail, "established no addresses") {
		t.Errorf("a nil list is described as %q, and nothing was established rather than found", got.Detail)
	}

	in.Addresses = func() []string { return []string{} }
	got = Ask(context.Background(), in)
	if !strings.Contains(got.Detail, "the name resolved to no address") {
		t.Errorf("an empty list is described as %q, and that IS a measurement about the name", got.Detail)
	}
}

// TestAVerdictAgainstTheseAddressesNeedsAWalkThatFinishedTrying is ADR58 and its
// twin, because either half alone can be satisfied by the wrong program.
//
// A layer that ran out of its own budget before dialling has measured nothing
// about anybody's addresses, and FAIL there says they would not accept a
// connection - about addresses nothing ever dialled. The twin underneath is what
// stops this from being satisfied by a layer that never says FAIL: when every
// address WAS tried and every one refused, the failure is real and stays.
func TestAVerdictAgainstTheseAddressesNeedsAWalkThatFinishedTrying(t *testing.T) {
	unfinished := workingInput(connectFailing(ErrRefused))
	unfinished.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }
	expired, cancel := context.WithDeadline(context.Background(), unfinished.Now().Add(-time.Second))
	defer cancel()

	got := Ask(expired, unfinished)
	if got.Status != status.Unknown {
		t.Errorf("a layer that dialled nothing answered %s, and it has measured nothing to answer about", got.Status)
	}
	if got.Reason != status.ReasonSkippedBudget {
		t.Errorf("the reason is %q, want %q", got.Reason, status.ReasonSkippedBudget)
	}
	if !strings.Contains(got.Detail, "did not finish trying") {
		t.Errorf("the sentence does not say the layer gave up early: %q", got.Detail)
	}

	// The twin: every address tried, every one refused, so the failure is theirs.
	finished := workingInput(connectFailing(ErrRefused))
	finished.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }
	if got := Ask(context.Background(), finished); got.Status != status.Fail {
		t.Errorf("a layer that tried every address and connected to none answered %s, want %s", got.Status, status.Fail)
	}
}

// TestTheSentenceForAnUnfinishedWalkNamesEveryCount is inviolable rule 1 on the
// one line anybody reads - the same rule, and the same three shapes, as the
// resolving layer's sentence.
func TestTheSentenceForAnUnfinishedWalkNamesEveryCount(t *testing.T) {
	addresses := []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"}

	budgetOnly := notFinishedDetail(3, 0, addresses)
	if !strings.Contains(budgetOnly, "3 of 3") || !strings.Contains(budgetOnly, "time budget") {
		t.Errorf("the budget-only sentence does not say how many were dropped or why: %q", budgetOnly)
	}
	if strings.Contains(budgetOnly, "refused") {
		t.Errorf("the budget-only sentence mentions a refusal that did not happen: %q", budgetOnly)
	}

	ruleOnly := notFinishedDetail(0, 2, addresses)
	if !strings.Contains(ruleOnly, "2 of 3") || !strings.Contains(ruleOnly, "own rule") {
		t.Errorf("the rule-only sentence does not say how many were refused or by what: %q", ruleOnly)
	}

	both := notFinishedDetail(1, 2, addresses)
	for _, want := range []string{"1 of 3", "2 more", "time budget", "own rule"} {
		if !strings.Contains(both, want) {
			t.Errorf("the sentence for a walk stopped both ways does not mention %q: %q", want, both)
		}
	}
}

// TestAnAttemptThatNeverLeftThisMachineCarriesNoTime pins the half of the
// contract that is easiest to break while making the other half work.
//
// A refusal by our own allowed set, and an address the budget never reached,
// both opened nothing. A duration beside either is a measurement of something
// that did not happen - and it is the field somebody fills in by reflex, because
// every other row has one.
func TestAnAttemptThatNeverLeftThisMachineCarriesNoTime(t *testing.T) {
	for _, err := range []error{ErrRefusedByRule} {
		rows := rowsOf(Ask(context.Background(), workingInput(connectFailing(err))))
		if rows[0].DurationMS != 0 {
			t.Errorf("%v reports %d ms spent on an attempt that never happened", err, rows[0].DurationMS)
		}
	}

	// The other one: a deadline already spent, so nothing is tried at all.
	in := workingInput(connectFailing(ErrRefused))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }
	expired, cancel := context.WithDeadline(context.Background(), in.Now().Add(-time.Second))
	defer cancel()

	got := Ask(expired, in)
	for _, row := range rowsOf(got) {
		if row.Outcome != report.OutcomeNotAttempted {
			t.Errorf("an address nobody had time for came out as %q", row.Outcome)
		}
		if row.DurationMS != 0 {
			t.Errorf("an address that was never tried reports %d ms", row.DurationMS)
		}
	}
	// AND IT IS NOT A TIMEOUT, which is the whole point of the seventh outcome:
	// a timeout says their network stayed silent, and nothing was ever sent here.
	if strings.Contains(got.Detail, "timed out") {
		t.Errorf("the sentence blames the network for our own budget: %q", got.Detail)
	}
}

// TestOneReachableAddressIsAPassAndTheSentenceSaysHowMany is the decision from
// ADR4 applied to this layer.
//
// A machine with no IPv6 has every AAAA address fail on every run, against every
// name. Warning on "some addresses failed" would therefore warn constantly on a
// working machine, which is how a tool gets switched off. So the fact goes in the
// sentence and in the rows, and the status stays PASS while anything answers.
func TestOneReachableAddressIsAPassAndTheSentenceSaysHowMany(t *testing.T) {
	opened := &closer{}
	in := workingInput(func(_ context.Context, address string, _ int) (io.Closer, error) {
		if strings.Contains(address, ":") {
			return nil, ErrUnreachable
		}
		return opened, nil
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "2001:db8::10"} }

	got := Ask(context.Background(), in)
	if got.Status != status.Pass {
		t.Errorf("one address answering left the layer at %s", got.Status)
	}
	if !strings.Contains(got.Detail, "1 of 2") {
		t.Errorf("the sentence does not count what answered: %q", got.Detail)
	}
	// The family is what turns arithmetic into a diagnosis: every IPv6 address
	// failing on a machine without IPv6 is a fact about the machine.
	if !strings.Contains(got.Detail, "IPv6") {
		t.Errorf("the sentence does not name the families it tried: %q", got.Detail)
	}
	if opened.closed.Load() != 1 || opened.failed.Load() {
		t.Errorf("the connection that opened was closed %d times", opened.closed.Load())
	}
}

// TestNoPathLeavesAConnectionOpen is docs/22 section 6a, point (a): the leak
// hides on the paths where something already went wrong.
//
// This layer's whole question is whether a connection opens, so it holds one for
// no longer than it takes to find out. Counting on the success path only would
// miss the case that matters - and the count is taken from a stand-in rather than
// from real handles, because "closed exactly once" is checkable everywhere while
// counting descriptors answers a question about the operating system.
func TestNoPathLeavesAConnectionOpen(t *testing.T) {
	opened := &handles{}
	in := workingInput(func(_ context.Context, address string, _ int) (io.Closer, error) {
		switch address {
		case "192.0.2.11":
			return nil, ErrRefused
		case "192.0.2.12":
			// A connection handed back TOGETHER with an error. The io contract
			// permits it, and a caller that returns early on err leaks it.
			return opened.fresh(), ErrReset
		}
		return opened.fresh(), nil
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} }

	Ask(context.Background(), in)

	kept := opened.all()
	if len(kept) == 0 {
		t.Fatal("no connection was opened at all, so nothing here established anything")
	}
	for i, handle := range kept {
		if handle.closed.Load() != 1 || handle.failed.Load() {
			t.Errorf("connection %d was closed %d times", i, handle.closed.Load())
		}
	}
}

// TestAnAttemptGetsThePerAddressCapOrWhatIsLeftOfTheLayer is ADR44, and it
// replaces the test that pinned ADR36's division here.
//
// THE DIVISION WENT AWAY BECAUSE ITS PREMISE DID, NOT BECAUSE THE PROPERTY IT
// DEFENDED STOPPED MATTERING. "One silent address must not spend the whole
// layer" is still true and is still tested - by
// TestASilentAddressNoLongerTakesTimeFromTheOthers, which asserts it directly
// instead of through arithmetic that only approximated it. What is pinned here is
// the narrower statement left over: an attempt may have the per-address cap, or
// what remains of the layer, whichever is smaller.
func TestAnAttemptGetsThePerAddressCapOrWhatIsLeftOfTheLayer(t *testing.T) {
	in := workingInput(connectFailing(ErrRefused))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} }

	// Three seconds left, an hour allowed per address: the layer's budget is the
	// tighter of the two, and ALL of it is on offer. Divided by the three
	// addresses, as it used to be, this would come back at about one second.
	in.PerAddress = time.Hour
	ctx, cancel := context.WithDeadline(context.Background(), in.Now().Add(3*time.Second))
	defer cancel()

	got := in.limitFor(ctx)
	if got <= 2900*time.Millisecond || got > 3*time.Second {
		t.Errorf("an attempt was offered %s of a three second budget that nothing else is competing for", got)
	}

	// And the flag still caps it when the flag is the tighter of the two, which
	// is the direction the flag documents.
	in.PerAddress = 200 * time.Millisecond
	if got := in.limitFor(ctx); got != 200*time.Millisecond {
		t.Errorf("the per-address limit stopped applying: %s", got)
	}
}

// TestEveryRowSaysWhichAddressAndPortItIsAbout is the contract from the other
// side: a row that cannot be attributed is a row nobody can act on.
func TestEveryRowSaysWhichAddressAndPortItIsAbout(t *testing.T) {
	// THE PORT HANDED TO THE DIALLER IS RECORDED, NOT JUST THE ONE IN THE ROW,
	// and the difference is not academic. The allowed set holds address and port
	// joined into one string, so a port that never reaches the dialler means
	// every connection is refused BY OUR OWN RULE on a machine where everything
	// works - which is exactly what happened the first time this was wired.
	//
	// The mutation register found this: an entry replacing the port with zero
	// survived, because the row's port comes from Input and the assertions only
	// read the row.
	var mu sync.Mutex
	var asked []int
	in := workingInput(func(_ context.Context, _ string, port int) (io.Closer, error) {
		mu.Lock()
		asked = append(asked, port)
		mu.Unlock()
		return nil, ErrRefused
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "2001:db8::10"} }

	got := Ask(context.Background(), in)

	if len(asked) != 2 {
		t.Fatalf("two addresses produced %d attempts", len(asked))
	}
	for _, port := range asked {
		if port != in.Port {
			t.Errorf("the dialler was asked for port %d while the run is about port %d", port, in.Port)
		}
	}
	if len(got.Findings) != 2 {
		t.Fatalf("two addresses produced %d rows", len(got.Findings))
	}
	for _, finding := range got.Findings {
		if broken := finding.Breach(); broken != "" {
			t.Errorf("a row is refused by its own contract: %s", broken)
		}
		if finding.TCPConnect.Port != 443 {
			t.Errorf("a row reports port %d, and the target names 443", finding.TCPConnect.Port)
		}
		if !strings.Contains(finding.Summary, finding.TCPConnect.Address) {
			t.Errorf("the summary does not name the address it is about: %q", finding.Summary)
		}
	}
}

// TestSwitchingEveryBudgetOffMeansNoLimitRatherThanNoAttempt is OBS62, and the
// defect it pins was reported by this layer as a fact about somebody's network.
//
// BOTH FLAGS DOCUMENT ZERO AS "no limit", and one of them is suggested by the
// tool's own error text - "Give 0 if that is what you want". With both switched
// off there is no layer deadline and no per-attempt cap, and limitFor used to
// answer zero, which every call site here reads as "no time left, do not try".
// Measured on the shipped binary: every address came back not_attempted, the
// layer said none of them accepted a connection, and L1 above it said neither
// view answered - on a machine where the name resolves in milliseconds.
//
// IT ASSERTS BOTH HALVES. That the attempts happen, and that no deadline was
// invented for them: capping an uncapped attempt at some arbitrary value would
// turn one wrong answer into a quieter one.
func TestSwitchingEveryBudgetOffMeansNoLimitRatherThanNoAttempt(t *testing.T) {
	var asked, deadlines atomic.Int64
	in := workingInput(func(ctx context.Context, _ string, _ int) (io.Closer, error) {
		asked.Add(1)
		if _, set := ctx.Deadline(); set {
			deadlines.Add(1)
		}
		return nil, ErrRefused
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }
	// --probe-timeout 0, and context.Background() below is --timeout 0.
	in.PerAddress = 0

	got := Ask(context.Background(), in)

	if asked.Load() != 2 {
		t.Errorf("two addresses produced %d attempt(s) when the caller asked for no limits", asked.Load())
	}
	if deadlines.Load() != 0 {
		t.Errorf("%d attempt(s) were given a deadline of their own when nothing caps them", deadlines.Load())
	}
	if got.Status != status.Fail {
		t.Errorf("two refused addresses gave %s", got.Status)
	}
	for _, finding := range got.Findings {
		if finding.TCPConnect.Outcome == report.OutcomeNotAttempted {
			t.Errorf("an address was reported as never tried while the caller had asked for no limit at all")
		}
	}
}

// TestAnAttemptFallingOverIsThisLayersDefectRatherThanTheProcessDying is R-1
// arriving at the layer that has to say what it means.
//
// net.Dialer is not code this program owns, and the goroutine it runs on is one
// the orchestrator's recover cannot see. Before this, a panic there took the
// whole run down with no report and an exit code from outside the table.
func TestAnAttemptFallingOverIsThisLayersDefectRatherThanTheProcessDying(t *testing.T) {
	in := workingInput(func(context.Context, string, int) (io.Closer, error) {
		panic("the dialler fell over")
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11"} }

	got := Ask(context.Background(), in)
	if got.Status != status.Unknown {
		t.Errorf("an attempt fell over inside this program and the layer said %s", got.Status)
	}
	if got.Reason != status.ReasonProbeError {
		t.Errorf("the reason is %q, and probe_error is what means the probe fell over", got.Reason)
	}
	if !strings.Contains(got.Detail, "fell over") {
		t.Errorf("the sentence does not say what happened: %q", got.Detail)
	}
	// AND IT SAYS NOTHING ABOUT ANY ADDRESS. Rows from the same call as a panic
	// are rows from code we have just watched misbehave.
	if len(got.Findings) != 0 {
		t.Errorf("the layer kept %d row(s) from the call that fell over", len(got.Findings))
	}

	// THE TWIN. An ordinary failure is still a finding about the address rather
	// than about this program, or this rule would swallow every real refusal.
	ordinary := Ask(context.Background(), workingInput(connectFailing(errors.New("connection refused"))))
	if ordinary.Reason == status.ReasonProbeError {
		t.Errorf("an ordinary refusal came out as this program falling over: %q", ordinary.Detail)
	}
}
