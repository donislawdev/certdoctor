package tcp

import (
	"context"
	"errors"
	"io"
	"strings"
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
type closer struct {
	closed int
	failed bool
}

func (c *closer) Close() error {
	c.closed++
	if c.closed > 1 {
		c.failed = true
	}
	return nil
}

func fixedClock() func() time.Time {
	at := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		at = at.Add(3 * time.Millisecond)
		return at
	}
}

func workingInput(connect Connect) Input {
	return Input{
		Addresses:  func() []string { return []string{"192.0.2.10"} },
		Port:       443,
		Connect:    connect,
		Now:        fixedClock(),
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
	cases := []struct {
		err  error
		want report.ConnectOutcome
	}{
		{ErrRefused, report.OutcomeRefused},
		{ErrTimeout, report.OutcomeTimeout},
		{ErrUnreachable, report.OutcomeUnreachable},
		{ErrReset, report.OutcomeReset},
		{ErrRefusedByRule, report.OutcomeRefusedByRule},
		// A failure nobody anticipated must never read as a success, and it must
		// not claim to be one of the diagnoses either.
		{errors.New("something nobody wrote a case for"), report.OutcomeReset},
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
		if got.Status != status.Fail {
			t.Errorf("%v left the layer at %s, and no address accepted a connection", tc.err, got.Status)
		}
		if broken := got.Findings[0].Breach(); broken != "" {
			t.Errorf("%v produced a row its own contract refuses: %s", tc.err, broken)
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
	if opened.closed != 1 || opened.failed {
		t.Errorf("the connection that opened was closed %d times", opened.closed)
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
	handles := []*closer{}
	in := workingInput(func(_ context.Context, address string, _ int) (io.Closer, error) {
		switch address {
		case "192.0.2.11":
			return nil, ErrRefused
		case "192.0.2.12":
			// A connection handed back TOGETHER with an error. The io contract
			// permits it, and a caller that returns early on err leaks it.
			handle := &closer{}
			handles = append(handles, handle)
			return handle, ErrReset
		}
		handle := &closer{}
		handles = append(handles, handle)
		return handle, nil
	})
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} }

	Ask(context.Background(), in)

	if len(handles) == 0 {
		t.Fatal("no connection was opened at all, so nothing here established anything")
	}
	for i, handle := range handles {
		if handle.closed != 1 || handle.failed {
			t.Errorf("connection %d was closed %d times", i, handle.closed)
		}
	}
}

// TestOneSlowAddressDoesNotSpendTheWholeLayer is ADR36, measured for L1 and
// binding here for the same reason.
//
// With a fixed per-attempt limit, the first address is entitled to the whole
// budget - so one address behind a silently dropping firewall means the working
// ones are never tried, and the layer reports a machine that cannot connect while
// the second address would have answered instantly.
func TestOneSlowAddressDoesNotSpendTheWholeLayer(t *testing.T) {
	in := workingInput(connectFailing(ErrRefused))
	in.Addresses = func() []string { return []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} }
	in.PerAddress = time.Hour

	deadline := in.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	if share := in.limitFor(ctx, 3); share > 1200*time.Millisecond {
		t.Errorf("the first of three addresses may spend %s of a three second budget", share)
	}
	// And the layer's own limit still caps it when the layer limit is the tighter
	// of the two, which is the direction the flag documents.
	in.PerAddress = 200 * time.Millisecond
	if share := in.limitFor(ctx, 1); share != 200*time.Millisecond {
		t.Errorf("the per-address limit stopped applying: %s", share)
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
	var asked []int
	in := workingInput(func(_ context.Context, _ string, port int) (io.Closer, error) {
		asked = append(asked, port)
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
