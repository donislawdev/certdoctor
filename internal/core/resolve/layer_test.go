package resolve

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/dnsmsg"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// answering builds an Exchange that replies to whatever it is asked, so a test
// only has to say what came back rather than how the wire works.
//
// It reads the identifier out of the query and echoes it, because that is what a
// real resolver does - and a stand-in that ignored it would make the layer's own
// identifier check untestable, which is the shape OBS43 names: a fixture that
// cannot tell two states apart quietly invalidates the test.
func answering(reply func(id uint16, recordType dnsmsg.Type) ([]byte, error)) Exchange {
	return func(_ context.Context, _ string, query []byte) ([]byte, error) {
		id := uint16(query[0])<<8 | uint16(query[1])
		asked := dnsmsg.Type(uint16(query[len(query)-4])<<8 | uint16(query[len(query)-3]))
		return reply(id, asked)
	}
}

// replyWith assembles an answer packet carrying one address of the type asked.
func replyWith(id uint16, recordType dnsmsg.Type, rcode byte, addresses ...[]byte) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x81, rcode, 0, 1, byte(len(addresses) >> 8), byte(len(addresses)), 0, 0, 0, 0}
	question := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	msg = append(msg, question...)
	msg = append(msg, byte(uint16(recordType)>>8), byte(recordType), 0, 1)
	for _, address := range addresses {
		msg = append(msg, 0xc0, 0x0c)
		msg = append(msg, byte(uint16(recordType)>>8), byte(recordType), 0, 1, 0, 0, 0, 60)
		msg = append(msg, byte(len(address)>>8), byte(len(address)))
		msg = append(msg, address...)
	}
	return msg
}

// addressFor hands back an address of the right WIDTH for the type asked.
//
// It exists because a four byte address inside a AAAA record is a malformed
// packet, which the parser refuses - correctly. A fixture that ignored the type
// would make every AAAA row come back unreadable and the test would be measuring
// its own mistake.
func addressFor(recordType dnsmsg.Type) []byte {
	if recordType == dnsmsg.TypeAAAA {
		return []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	}
	return []byte{192, 0, 2, 10}
}

func fixedClock() func() time.Time {
	at := time.Unix(1_770_000_000, 0).UTC()
	return func() time.Time {
		at = at.Add(4 * time.Millisecond)
		return at
	}
}

func workingInput(exchange Exchange) Input {
	var next uint16
	return Input{
		Name:          "example.com",
		Resolvers:     []string{"192.0.2.53", "198.51.100.53"},
		ResolversFrom: "resolv.conf",
		Exchange:      exchange,
		QueryID:       func() uint16 { next += 7; return next },
		Now:           fixedClock(),
		PerQuery:      3 * time.Second,
	}
}

// TestAskRefusesWhenItWasGivenNoWayToAsk covers every missing port, and each one
// has to name ITSELF.
//
// "L1 could not run" with no reason is the shape of silence this whole program is
// built against, and a missing port is a defect on our side rather than anything
// about the machine being diagnosed.
func TestAskRefusesWhenItWasGivenNoWayToAsk(t *testing.T) {
	cases := []struct {
		name   string
		damage func(*Input)
		says   string
	}{
		{"no exchange", func(in *Input) { in.Exchange = nil }, "no way to send a query"},
		{"no identifiers", func(in *Input) { in.QueryID = nil }, "off-path answer undetectable"},
		{"no clock", func(in *Input) { in.Now = nil }, "no clock was supplied"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := workingInput(answering(func(uint16, dnsmsg.Type) ([]byte, error) { return nil, nil }))
			c.damage(&in)
			got := Ask(context.Background(), in)

			if got.Status != status.Unknown {
				t.Errorf("a layer with %s answered %s, and it established nothing", c.name, got.Status)
			}
			if got.Reason != status.ReasonProbeError {
				t.Errorf("the reason is %q where the fault is ours", got.Reason)
			}
			if !strings.Contains(got.Detail, c.says) {
				t.Errorf("the detail reads %q and does not mention %q", got.Detail, c.says)
			}
			// Nil, not empty. Nobody looked, and ADR20 keeps those apart.
			if got.Findings != nil {
				t.Errorf("a layer that could not ask reported %d findings", len(got.Findings))
			}
		})
	}
}

// TestAMachineWithNoResolverIsNotOurFailure is inviolable rule 15 pointed at the
// likeliest wrong answer.
//
// A machine that lists no resolver has not made our probe break. Reporting
// probe_error there would blame this program for a fact about somebody else's
// machine, and the report would send them to the wrong place.
func TestAMachineWithNoResolverIsNotOurFailure(t *testing.T) {
	in := workingInput(answering(func(uint16, dnsmsg.Type) ([]byte, error) { return nil, nil }))
	in.Resolvers = nil
	got := Ask(context.Background(), in)

	if got.Status != status.Unknown {
		t.Errorf("a machine with no resolver was reported as %s", got.Status)
	}
	if got.Reason != status.ReasonNothingToCheck {
		t.Errorf("the reason is %q, which says this program broke rather than that there was nobody to ask", got.Reason)
	}
	if !strings.Contains(got.Detail, "nobody to ask") {
		t.Errorf("the detail reads %q", got.Detail)
	}
}

// TestAResolverListThatCouldNotBeReadSaysSoInsteadOfClaimingThereIsNone is the
// other half of the case above, and the two are DIFFERENT FACTS.
//
// "This machine has no DNS configured" is a confident statement about somebody's
// machine. "We could not read what it has" is a gap on our side. Folding them
// together would state the first when the truth is the second.
func TestAResolverListThatCouldNotBeReadSaysSoInsteadOfClaimingThereIsNone(t *testing.T) {
	in := workingInput(answering(func(uint16, dnsmsg.Type) ([]byte, error) { return nil, nil }))
	in.Resolvers = nil
	in.ResolversError = errors.New("the registry key could not be opened")
	got := Ask(context.Background(), in)

	if !strings.Contains(got.Detail, "could not be read") {
		t.Errorf("a failed enumeration reads %q, which does not say the reading failed", got.Detail)
	}
	if !strings.Contains(got.Detail, "registry key") {
		t.Errorf("the detail drops what actually went wrong: %q", got.Detail)
	}
	if strings.Contains(got.Detail, noResolvers) {
		t.Error("a failed enumeration was reported as a machine with no resolvers")
	}
}

// TestEveryResolverAndTypeGetsItsOwnRow is the shape D3 asks for: one finding per
// ANSWER, not per name.
//
// A resolver that answers for one record type and not the other is the
// hangs-thirty-seconds-then-works class, and folding the pair into one row would
// make that invisible.
func TestEveryResolverAndTypeGetsItsOwnRow(t *testing.T) {
	got := Ask(context.Background(), workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		if recordType == dnsmsg.TypeAAAA {
			// Answered, with nothing of that type - NODATA, a real answer and
			// half of the class this layer exists for.
			return replyWith(id, recordType, 0), nil
		}
		return replyWith(id, recordType, 0, []byte{192, 0, 2, 10}), nil
	})))

	if got.Status != status.Pass {
		t.Fatalf("a run where every resolver answered came back %s: %s", got.Status, got.Detail)
	}
	if len(got.Findings) != 4 {
		t.Fatalf("two resolvers and two record types produced %d rows", len(got.Findings))
	}

	seen := map[string]bool{}
	for _, finding := range got.Findings {
		if breach := finding.Breach(); breach != "" {
			t.Errorf("the layer produced a finding that %s", breach)
		}
		answer := finding.NameResolution
		seen[answer.Resolver+" "+answer.QueryType] = true
		if answer.View != report.ViewDirect {
			t.Errorf("our own query came out as the %s view", answer.View)
		}
		if finding.Source != report.SourceDetected {
			t.Errorf("our own measurement was reported as %s", finding.Source)
		}
		if answer.DurationMS <= 0 {
			t.Errorf("%s took %d ms, so nothing was timed", answer.Resolver, answer.DurationMS)
		}
	}
	for _, want := range []string{"192.0.2.53 A", "192.0.2.53 AAAA", "198.51.100.53 A", "198.51.100.53 AAAA"} {
		if !seen[want] {
			t.Errorf("no row for %s", want)
		}
	}
}

// TestNODATAIsReportedAsAnAnswerAndNotAsSilence pins the distinction the whole
// second view exists for.
//
// "The name exists and has no AAAA record" arrived from the resolver. Reporting
// it with a reason for having no answer would turn a measurement into a gap.
func TestNODATAIsReportedAsAnAnswerAndNotAsSilence(t *testing.T) {
	in := workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyWith(id, recordType, 0), nil
	}))
	in.Resolvers = []string{"192.0.2.53"}
	got := Ask(context.Background(), in)

	for _, finding := range got.Findings {
		answer := finding.NameResolution
		if answer.ResponseCode != dnsmsg.NODATA {
			t.Errorf("an empty NOERROR came out as %q", answer.ResponseCode)
		}
		if answer.NoAnswer != "" {
			t.Errorf("an answer that arrived carries the reason %q for not arriving", answer.NoAnswer)
		}
	}
	if got.Status != status.Pass {
		t.Errorf("a resolver that answered NODATA left the layer at %s", got.Status)
	}
}

// TestEachWayOfNotAnsweringKeepsItsOwnReason is ADR30 walked end to end.
//
// Silence, a refusal by our own rule and a reply we cannot read send a person to
// three different places. A layer that folded them into one would send everybody
// to the same wrong one.
func TestEachWayOfNotAnsweringKeepsItsOwnReason(t *testing.T) {
	cases := []struct {
		name  string
		fails error
		reply []byte
		want  report.NoAnswer
	}{
		{"our own rule refused the address", ErrRefused, nil, report.NoAnswerRefusedByRule},
		{"nothing came back in time", ErrTimeout, nil, report.NoAnswerTimeout},
		{"the context ran out", context.DeadlineExceeded, nil, report.NoAnswerTimeout},
		{"the network failed outright", errors.New("network is unreachable"), nil, report.NoAnswerTransportError},
		{"something unreadable came back", nil, []byte{1, 2, 3}, report.NoAnswerUnreadableAnswer},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := workingInput(func(context.Context, string, []byte) ([]byte, error) {
				if c.fails != nil {
					return nil, fmt.Errorf("asking failed: %w", c.fails)
				}
				return c.reply, nil
			})
			in.Resolvers = []string{"192.0.2.53"}
			got := Ask(context.Background(), in)

			for _, finding := range got.Findings {
				if breach := finding.Breach(); breach != "" {
					t.Errorf("the layer produced a finding that %s", breach)
				}
				answer := finding.NameResolution
				if answer.NoAnswer != c.want {
					t.Errorf("%s came out as %q and should be %q", c.name, answer.NoAnswer, c.want)
				}
				if answer.ResponseCode != "" {
					t.Errorf("a query with no answer carries the response code %q", answer.ResponseCode)
				}
				if len(answer.Addresses) != 0 {
					t.Errorf("a query with no answer brought %d addresses back", len(answer.Addresses))
				}
			}
		})
	}
}

// TestNobodyAnsweringIsUnknownAndNotAFailure is the localhost lesson from D13,
// applied one slice early.
//
// The direct view never reads the hosts file, so a name that resolves only there
// gets nothing from every resolver. Calling that FAIL would accuse somebody's
// network of a limitation of our own instrument - inviolable rule 21 pointed at
// DNS - and it is exactly the answer that looks right with one view.
func TestNobodyAnsweringIsUnknownAndNotAFailure(t *testing.T) {
	in := workingInput(func(context.Context, string, []byte) ([]byte, error) {
		return nil, ErrTimeout
	})
	got := Ask(context.Background(), in)

	if got.Status == status.Fail {
		t.Fatal("the direct view alone called a name unresolvable, which is a verdict on half the evidence")
	}
	if got.Status != status.Unknown {
		t.Errorf("a run where nobody answered came back %s", got.Status)
	}
	// THIS ASSERTION SAID probe_error UNTIL ADR36 AND IT WAS THE WRONG WORD, not
	// a weaker one. Every resolver here times out, nothing on our side fell over,
	// and probe_error means exactly that it did - so the old value sent a reader
	// to look at certdoctor for a fact about somebody's network. The check is
	// still an exact value rather than a range, because a reason that drifts is
	// the same as no reason.
	if got.Reason != status.ReasonTimeout {
		t.Errorf("the reason is %q, and every resolver here timed out", got.Reason)
	}
	// The rows are still there. A run that asked and got nothing is not a run
	// that did not ask.
	if len(got.Findings) != 4 {
		t.Errorf("the rows for the queries that were sent went missing: %d", len(got.Findings))
	}
}

// TestAQueryThereWasNoTimeForIsNamedRatherThanDropped is inviolable rule 1 at the
// place it will actually bite.
//
// Three resolvers times two record types at three seconds each is eighteen
// seconds against a ten second layer budget, so queries WILL be dropped on a slow
// network. A report with fewer rows reads as a machine with fewer resolvers.
func TestAQueryThereWasNoTimeForIsNamedRatherThanDropped(t *testing.T) {
	in := workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyWith(id, recordType, 0, []byte{192, 0, 2, 10}), nil
	}))
	// A clock that jumps a second per reading exhausts the deadline part way
	// through, which is the shape a slow network produces.
	at := time.Unix(1_770_000_000, 0).UTC()
	in.Now = func() time.Time {
		at = at.Add(time.Second)
		return at
	}
	ctx, cancel := context.WithDeadline(context.Background(), at.Add(3*time.Second))
	defer cancel()

	got := Ask(ctx, in)

	if len(got.Findings) != 4 {
		t.Fatalf("the layer reported %d rows where four queries were planned", len(got.Findings))
	}
	skipped := 0
	for _, finding := range got.Findings {
		if breach := finding.Breach(); breach != "" {
			t.Errorf("the layer produced a finding that %s", breach)
		}
		if finding.NameResolution.NoAnswer == report.NoAnswerNotAsked {
			skipped++
		}
	}
	if skipped == 0 {
		t.Fatal("the budget ran out and every query still claims to have been asked")
	}
	if skipped == 4 {
		t.Fatal("nothing was asked at all, so this proves nothing about naming the skipped ones")
	}
}

// TestOneQueryCannotSpendTheWholeLayerBudget covers the cap, which is the half
// of the budget arithmetic that does nothing until it matters.
//
// The other half - the layer deadline cutting a query short - is exercised by the
// skipping test above. THIS one is the reverse: a generous layer deadline with a
// tight per query limit, where a missing cap would let the first resolver hang
// for the whole layer and every later row would come back not_asked. Reading the
// deadline the exchange actually receives is the only way to see it, because both
// versions produce the same rows on a fast fixture.
//
// IT USES THE REAL CLOCK ON PURPOSE, AND THE FIRST VERSION DID NOT. A context
// deadline is kept against the real clock, so a test that fed the layer a frozen
// clock and then read ctx.Deadline() was comparing two timelines that have
// nothing to do with each other - it reported the PARENT's deadline and failed
// while the cap was working perfectly. The injected clock is right for counting
// elapsed milliseconds and wrong for anything context measures itself.
func TestOneQueryCannotSpendTheWholeLayerBudget(t *testing.T) {
	var handed []time.Duration
	in := workingInput(nil)
	in.Resolvers = []string{"192.0.2.53"}
	in.PerQuery = 3 * time.Second
	in.Now = time.Now
	in.Exchange = func(ctx context.Context, _ string, query []byte) ([]byte, error) {
		deadline, set := ctx.Deadline()
		if !set {
			t.Error("a query was sent with no deadline, so a hung resolver would hang the run")
			return nil, ErrTimeout
		}
		handed = append(handed, time.Until(deadline))
		id := uint16(query[0])<<8 | uint16(query[1])
		asked := dnsmsg.Type(uint16(query[len(query)-4])<<8 | uint16(query[len(query)-3]))
		return replyWith(id, asked, 0, addressFor(asked)), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	Ask(ctx, in)

	if len(handed) == 0 {
		t.Fatal("no query was sent, so this proves nothing about the cap")
	}
	for _, limit := range handed {
		if limit > in.PerQuery {
			t.Errorf("one query was allowed %s out of a one minute layer budget, and its own limit is %s",
				limit, in.PerQuery)
		}
	}
}

// TestASilentResolverDoesNotStopTheOthersBeingAsked is the defect OBS53 measured,
// written as a rule.
//
// THE FAILURE IT DEFENDS AGAINST WAS REAL AND MEASURED, not imagined. On a
// machine listing an unroutable resolver first and a working one second, this
// layer spent 10008 ms of its ten second budget on the silent one, marked the
// other three queries not_asked, and said "no resolver answered" - about a
// machine where the second resolver answers in milliseconds and Go's own
// resolver had just used it. The rows were honest one by one; the layer's
// summary was a statement about somebody else's DNS that came from our
// arithmetic.
//
// IT USES THE REAL CLOCK, for the reason written on the test below it: a context
// deadline is kept against the real clock, and reading it through an injected one
// compares two timelines that have nothing to do with each other (OBS49).
//
// PerQuery IS SET EQUAL TO THE LAYER BUDGET ON PURPOSE - that is how the entry
// point wires it, and it is exactly the configuration in which the old cap never
// bit.
func TestASilentResolverDoesNotStopTheOthersBeingAsked(t *testing.T) {
	const silent, answering = "192.0.2.53", "198.51.100.53"
	const budget = 600 * time.Millisecond

	in := workingInput(nil)
	in.Resolvers = []string{silent, answering}
	in.Now = time.Now
	in.PerQuery = budget
	in.Exchange = func(ctx context.Context, resolver string, query []byte) ([]byte, error) {
		if resolver == silent {
			// Silence, not refusal. A resolver that accepts the packet and never
			// answers is the shape that starves the budget - a refusal comes back
			// at once and costs nothing.
			<-ctx.Done()
			return nil, ErrTimeout
		}
		id := uint16(query[0])<<8 | uint16(query[1])
		asked := dnsmsg.Type(uint16(query[len(query)-4])<<8 | uint16(query[len(query)-3]))
		return replyWith(id, asked, 0, addressFor(asked)), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	got := Ask(ctx, in)

	asked := map[string]int{}
	for _, finding := range got.Findings {
		body := finding.NameResolution
		if body.ResponseCode != "" {
			asked[body.Resolver]++
		}
	}
	if asked[answering] == 0 {
		t.Errorf("the resolver that answers was never asked: one silent resolver spent the whole layer budget.\n"+
			"status %s, reason %q, detail %q\nrows: %s", got.Status, got.Reason, got.Detail, rowsOf(got))
	}
	// The other side, so this cannot be satisfied by never asking the silent one:
	// every query still has to produce a row, and the silent resolver's rows have
	// to say what happened to them rather than vanishing.
	if len(got.Findings) != len(in.Resolvers)*len(dnsmsg.AllTypes) {
		t.Errorf("the layer produced %d rows for %d resolvers and %d record types",
			len(got.Findings), len(in.Resolvers), len(dnsmsg.AllTypes))
	}
}

// TestNobodyAnsweringIsNotReportedAsOurOwnFailure is ADR36 part 2.
//
// probe_error means "the probe fell over", and ADR33 says so in as many words.
// Reporting a run in which every resolver stayed silent as OUR failure sends the
// reader to look at certdoctor, which is the one place the answer is not.
func TestNobodyAnsweringIsNotReportedAsOurOwnFailure(t *testing.T) {
	in := workingInput(nil)
	in.Now = time.Now
	in.PerQuery = 400 * time.Millisecond
	in.Exchange = func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ErrTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	got := Ask(ctx, in)

	if got.Status != status.Unknown {
		t.Errorf("nobody answered and the layer said %s", got.Status)
	}
	if got.Reason != status.ReasonTimeout {
		t.Errorf("every resolver timed out and the reason is %q, which blames us rather than naming what happened",
			got.Reason)
	}
}

// TestEveryWayOfEstablishingNothingPicksItsOwnReason is ADR33 and ADR39 as one
// table, and the rule it defends is that the reason points somewhere true.
//
// A reason is where the report sends the reader. probe_error sends them to
// certdoctor, which is the one place the answer is not when a cable is out, and
// that was the answer to a transport failure until the seventh reason existed.
// The order matters as much as the values: a timeout is the CAUSE and a skipped
// query is its CONSEQUENCE, so naming the consequence would point at our own
// arithmetic instead of at the resolver that never answered.
func TestEveryWayOfEstablishingNothingPicksItsOwnReason(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want status.Reason
	}{
		{"nothing came back in time", ErrTimeout, status.ReasonTimeout},
		{"the wire said no", errors.New("network is unreachable"), status.ReasonTransportError},
		{"our own set refused us", ErrRefused, status.ReasonProbeError},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := workingInput(func(context.Context, string, []byte) ([]byte, error) {
				return nil, c.err
			})
			got := Ask(context.Background(), in)

			if got.Status != status.Unknown {
				t.Fatalf("nothing was established and the layer said %s", got.Status)
			}
			if got.Reason != c.want {
				t.Errorf("%v came back as %q, want %q - the reason is where this report sends the reader",
					c.err, got.Reason, c.want)
			}
		})
	}
}

// TestTheLayerSaysHowManyQueriesItNeverAsked keeps inviolable rule 1 on the one
// sentence a reader actually reads.
//
// A run that asked one query out of four and reports "no resolver answered" is
// true about the queries it sent and misleading about the machine. The count is
// what tells those apart, and it has to be IN THE SENTENCE, because the rows
// carrying not_asked are below the fold of the terminal report.
// THE FIXTURE OVERRUNS ITS SHARE ON PURPOSE, AND AN EARLIER VERSION OF THIS TEST
// COULD NOT PRODUCE THE STATE IT WAS ABOUT. Waiting on the context makes every
// query end exactly when its share ends, so after ADR36 nothing is ever skipped
// and the test skipped itself - a check that reports "nothing to see" is one a
// mutation walks straight past (OBS28). A resolver whose reply lands after the
// deadline is both realistic and the only way to spend more than the share.
func TestTheLayerSaysHowManyQueriesItNeverAsked(t *testing.T) {
	const budget = 200 * time.Millisecond
	const overrun = 150 * time.Millisecond

	in := workingInput(nil)
	in.Now = time.Now
	in.PerQuery = 0 // no limit of its own: the layer deadline is the only cap
	in.Exchange = func(context.Context, string, []byte) ([]byte, error) {
		time.Sleep(overrun)
		return nil, ErrTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	got := Ask(ctx, in)

	skipped := 0
	for _, finding := range got.Findings {
		if finding.NameResolution.NoAnswer == report.NoAnswerNotAsked {
			skipped++
		}
	}
	if skipped == 0 {
		t.Fatalf("two queries at %s each cannot fit in %s, so some had to be skipped: %s", overrun, budget, rowsOf(got))
	}
	if !strings.Contains(got.Detail, "not asked") {
		t.Errorf("%d queries were never asked and the sentence does not say so: %q", skipped, got.Detail)
	}
	// The count has to be the real one. A sentence that says "some" would pass a
	// check for the words and tell the reader nothing.
	if !strings.Contains(got.Detail, fmt.Sprintf("%d of %d", skipped, len(got.Findings))) {
		t.Errorf("the sentence does not carry the actual count %d of %d: %q", skipped, len(got.Findings), got.Detail)
	}
}

// TestALayerThatArrivedTooLateSaysSoRatherThanBlamingItself covers the state
// skipped_budget was put in the list for.
//
// The layer can be reached with its budget already gone - earlier layers are
// entitled to spend it, and the run deadline is shared. Nothing is sent, every
// row is not_asked, and NOTHING TIMED OUT, because a query that never went out
// cannot time out. probe_error here would say certdoctor fell over, and
// `timeout` would say a resolver was slow: both name something that did not
// happen, on a run where we simply never asked.
func TestALayerThatArrivedTooLateSaysSoRatherThanBlamingItself(t *testing.T) {
	in := workingInput(func(context.Context, string, []byte) ([]byte, error) {
		t.Error("a query went out on a budget that was already spent")
		return nil, ErrTimeout
	})
	in.Now = time.Now

	// A deadline in the past: the shape of a layer reached last on a slow run.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	got := Ask(ctx, in)

	if got.Status != status.Unknown {
		t.Errorf("a layer that asked nothing answered %s", got.Status)
	}
	if got.Reason != status.ReasonSkippedBudget {
		t.Errorf("the reason is %q, and no query was ever sent", got.Reason)
	}
	for _, finding := range got.Findings {
		if finding.NameResolution.NoAnswer != report.NoAnswerNotAsked {
			t.Errorf("a query that never went out is recorded as %q", finding.NameResolution.NoAnswer)
		}
	}
	if !strings.Contains(got.Detail, fmt.Sprintf("%d of %d", len(got.Findings), len(got.Findings))) {
		t.Errorf("the sentence does not say that every query was skipped: %q", got.Detail)
	}
}

// TestASuccessfulWalkStillSaysWhatItSkipped is the same rule as the test above,
// on the path where it is easiest to lose.
//
// A layer that answers PASS has already told the reader the good news, and a
// query nobody sent is exactly the kind of thing that disappears behind it.
// Inviolable rule 1 does not have an exception for runs that went well: a walk
// that asked three of four questions and reports only what came back is a
// partial result wearing the shape of a complete one.
func TestASuccessfulWalkStillSaysWhatItSkipped(t *testing.T) {
	const quick, slow = "192.0.2.53", "198.51.100.53"

	in := workingInput(nil)
	in.Resolvers = []string{quick, slow}
	in.Now = time.Now
	in.PerQuery = 0
	in.Exchange = func(_ context.Context, resolver string, query []byte) ([]byte, error) {
		if resolver == slow {
			// Lands after the layer deadline, which leaves nothing for the query
			// after it.
			time.Sleep(150 * time.Millisecond)
			return nil, ErrTimeout
		}
		id := uint16(query[0])<<8 | uint16(query[1])
		asked := dnsmsg.Type(uint16(query[len(query)-4])<<8 | uint16(query[len(query)-3]))
		return replyWith(id, asked, 0, addressFor(asked)), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got := Ask(ctx, in)

	if got.Status != status.Pass {
		t.Fatalf("two queries answered and the layer said %s: %s", got.Status, rowsOf(got))
	}
	skipped := 0
	for _, finding := range got.Findings {
		if finding.NameResolution.NoAnswer == report.NoAnswerNotAsked {
			skipped++
		}
	}
	if skipped == 0 {
		t.Fatalf("nothing was skipped, so this proves nothing about a PASS hiding one: %s", rowsOf(got))
	}
	if !strings.Contains(got.Detail, "not asked") {
		t.Errorf("a PASS hid %d query nobody sent: %q", skipped, got.Detail)
	}
}

// systemAnswering builds a system lens that always says the same thing.
func systemAnswering(a SystemAnswer) SystemLookup {
	return func(context.Context, string) SystemAnswer { return a }
}

// systemRowOf finds the one row the system lens produces, or fails.
func systemRowOf(t *testing.T, r Result) report.Finding {
	t.Helper()
	for _, finding := range r.Findings {
		if finding.NameResolution.View == report.ViewSystem {
			return finding
		}
	}
	t.Fatalf("the walk produced no system row at all: %s", rowsOf(r))
	return report.Finding{}
}

// TestTheSystemRowLeavesTheThreeColumnsItCannotKnowEmpty is the contract from K2,
// checked at the one place that could fill them in.
//
// The platform resolves a name and does not say which server answered, which
// record type it asked for, or what the reply's code was. Those are the three
// most useful columns of a row, which is exactly why a plausible mistake fills
// them in - and a filled-in row reads like a measurement rather than a guess.
// The finding contract refuses them, and this checks that the layer does not
// have to be refused.
func TestTheSystemRowLeavesTheThreeColumnsItCannotKnowEmpty(t *testing.T) {
	in := workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyWith(id, recordType, 0, addressFor(recordType)), nil
	}))
	in.System = systemAnswering(SystemAnswer{Addresses: []string{"192.0.2.10"}, ViaPlatform: true})

	row := systemRowOf(t, Ask(context.Background(), in))
	body := row.NameResolution
	if body.Resolver != "" {
		t.Errorf("the system row names %q as the resolver, which this view cannot know", body.Resolver)
	}
	if body.QueryType != "" {
		t.Errorf("the system row says it asked for %q, which this view does not split by", body.QueryType)
	}
	if body.ResponseCode != "" {
		t.Errorf("the system row carries the response code %q, which the platform does not hand back", body.ResponseCode)
	}
	if broken := row.Breach(); broken != "" {
		t.Errorf("the row this layer built is refused by its own contract: %s", broken)
	}
}

// TestTheSystemRowSaysWhoDidTheWork is ADR28 in one assertion, and it is the
// whole reason the adapter reports a fact instead of the core asking a question.
//
// Probe S10 measured a cgo-enabled binary on glibc going through Go's own
// resolver, which is why neither the operating system nor the build settings can
// decide this. What decides it is whether our dialler was called during THIS
// query, and the core does nothing with that fact but translate it.
func TestTheSystemRowSaysWhoDidTheWork(t *testing.T) {
	for _, c := range []struct {
		name        string
		viaPlatform bool
		want        report.Source
	}{
		{"the platform resolved it", true, report.SourceDetected},
		{"our own resolver stood in", false, report.SourceDerived},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
				return replyWith(id, recordType, 0, addressFor(recordType)), nil
			}))
			in.System = systemAnswering(SystemAnswer{Addresses: []string{"192.0.2.10"}, ViaPlatform: c.viaPlatform})

			row := systemRowOf(t, Ask(context.Background(), in))
			if row.Source != c.want {
				t.Errorf("the platform did the work: %v, and the row says %q", c.viaPlatform, row.Source)
			}
			if broken := row.Breach(); broken != "" {
				t.Errorf("the row is refused by its own contract: %s", broken)
			}
		})
	}
}

// TestAMachineWithNoResolverOfItsOwnIsStillAsked is the state S11 measured and
// this layer used to get wrong.
//
// An empty resolv.conf does not mean names do not resolve - it means the
// platform asks loopback, and a container whose local resolver answered got
// "there was nobody to ask" out of this layer. Nothing to check now needs BOTH
// lenses to be missing.
func TestAMachineWithNoResolverOfItsOwnIsStillAsked(t *testing.T) {
	// THE EXCHANGE IS WIRED AND MUST NEVER BE CALLED, which is two assertions in
	// one fixture. A nil one would be refused before the walk even starts - a
	// missing port is our own defect whatever the machine looks like - and in
	// production it is always wired, so a test handing nil would be measuring a
	// state that cannot happen.
	in := workingInput(func(context.Context, string, []byte) ([]byte, error) {
		t.Error("a query went out although this machine lists no resolver to send one to")
		return nil, ErrTimeout
	})
	in.Resolvers = nil
	in.System = systemAnswering(SystemAnswer{Addresses: []string{"203.0.113.10"}})

	got := Ask(context.Background(), in)
	if got.Reason == status.ReasonNothingToCheck {
		t.Fatalf("the platform resolved the name and the layer said there was nothing to check: %q", got.Detail)
	}
	if got.Status != status.Pass {
		t.Errorf("the platform answered and the layer said %s: %q", got.Status, got.Detail)
	}
	row := systemRowOf(t, got)
	if len(row.NameResolution.Addresses) == 0 {
		t.Error("the system row carries no addresses, so the answer was lost on the way")
	}
	// And the sentence has to admit which lens did it, because on this machine
	// the direct view established nothing at all.
	if !strings.Contains(got.Detail, "no resolver of its own") {
		t.Errorf("the sentence does not say the direct view had nobody to ask: %q", got.Detail)
	}
}

// TestTheSystemViewIsCountedInTheBudgetLikeAnyOtherQuery keeps ADR36 whole.
//
// Leaving the second lens out of the arithmetic would hand it whatever the
// direct view left over, which is the same starvation OBS53 measured arriving
// from the other side. Here the direct view is silent and eats its shares, and
// the system view still has to be asked rather than dropped.
func TestTheSystemViewIsCountedInTheBudgetLikeAnyOtherQuery(t *testing.T) {
	const budget = 500 * time.Millisecond

	asked := false
	in := workingInput(nil)
	in.Now = time.Now
	in.PerQuery = budget
	in.Exchange = func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ErrTimeout
	}
	in.System = func(context.Context, string) SystemAnswer {
		asked = true
		return SystemAnswer{Addresses: []string{"203.0.113.10"}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	got := Ask(ctx, in)

	if !asked {
		t.Fatalf("four silent resolvers spent the whole budget and the platform was never asked: %s", rowsOf(got))
	}
	if got.Status != status.Pass {
		t.Errorf("the platform answered and the layer said %s: %q", got.Status, got.Detail)
	}
}

// TestWhenNeitherLensResolvesTheNameTheSentenceStopsApologisingForOne is the
// half of inviolable rule 1 that only shows up once the second lens exists.
//
// The sentence for "nobody answered" was written while this layer had one view,
// and it says so: it explains that with only our own view there is no telling a
// name that does not resolve from one this view cannot see. That is true, and it
// stops being true the moment the platform has been asked too. A sentence that
// keeps apologising for a lens it is holding is worse than one that never had it.
func TestWhenNeitherLensResolvesTheNameTheSentenceStopsApologisingForOne(t *testing.T) {
	in := workingInput(func(context.Context, string, []byte) ([]byte, error) {
		return nil, ErrTimeout
	})
	in.System = systemAnswering(SystemAnswer{NoAnswer: report.NoAnswerTransportError})

	got := Ask(context.Background(), in)
	// THIS SAID UNKNOWN UNTIL THE CLASSIFICATION ARRIVED, and the change is D13
	// rather than a relaxation. With one lens, "nobody answered" cannot tell a
	// name that does not resolve from one that lens cannot see - so unknown was
	// the only honest answer, and the test one screen down still pins it for that
	// case. With BOTH lenses silent there is nothing left to be unsure about.
	if got.Status != status.Fail {
		t.Errorf("neither of the two lenses resolved the name and the layer said %s", got.Status)
	}
	if strings.Contains(got.Detail, "with only our own view") {
		t.Errorf("both lenses were used and the sentence still says only one was: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "neither view") {
		t.Errorf("the sentence does not say that both lenses came back empty: %q", got.Detail)
	}
	// And the row itself has to say what happened rather than looking like a
	// lookup nobody performed.
	row := systemRowOf(t, got)
	if !strings.Contains(row.Summary, "no answer") {
		t.Errorf("the system row reads %q, which does not say it failed", row.Summary)
	}
}

// TestAPassStillAdmitsThatTheOtherLensSaidNothing is the same rule on the path
// where it is easiest to lose: the good news has already been delivered.
func TestAPassStillAdmitsThatTheOtherLensSaidNothing(t *testing.T) {
	in := workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyWith(id, recordType, 0, addressFor(recordType)), nil
	}))
	in.System = systemAnswering(SystemAnswer{NoAnswer: report.NoAnswerTimeout})

	got := Ask(context.Background(), in)
	if got.Status != status.Pass {
		t.Fatalf("our own view answered and the layer said %s: %q", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "the system view did not answer") {
		t.Errorf("a PASS hid the fact that the second lens said nothing: %q", got.Detail)
	}
}

// TestTheSystemViewIsNamedRatherThanDroppedWhenTheBudgetIsGone is inviolable
// rule 1 for the row that arrives last.
//
// Being last is exactly why it is the one that gets dropped, and a report with
// no system row reads like a run that never had a second lens rather than one
// that ran out of time before using it.
func TestTheSystemViewIsNamedRatherThanDroppedWhenTheBudgetIsGone(t *testing.T) {
	in := workingInput(func(context.Context, string, []byte) ([]byte, error) {
		return nil, ErrTimeout
	})
	in.Now = time.Now
	in.System = func(context.Context, string) SystemAnswer {
		t.Error("the platform was asked although the budget was already gone")
		return SystemAnswer{}
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	got := Ask(ctx, in)

	row := systemRowOf(t, got)
	if row.NameResolution.NoAnswer != report.NoAnswerNotAsked {
		t.Errorf("the system row says %q where nothing was ever sent", row.NameResolution.NoAnswer)
	}
}

// TestEveryDivergenceClassIsReachedAndOnlyThreeCarryAVerdict is D13, ADR38 and
// ADR40 as one table, and the ratio in the name is the decision it defends.
//
// Probe S4 measured the two views disagreeing on five names out of five. A layer
// that warned on "they differ" would therefore warn in almost every run on
// Windows, which is the shape ADR4 names as the way a tool gets switched off. So
// most of the classes are named and left alone, and the test asserts the STATUS
// as well as the class - a table that only checked the class would pass just as
// well if every one of them raised a warning.
//
// IT NOW ASSERTS THAT THE TABLE COVERS THE REGISTRY, and that assertion is here
// because its absence cost a real defect. agree_none was reachable in production
// for a whole slice while this table looked complete: a class nobody wrote a row
// for is a class nobody checked the status of, and the list is closed precisely
// so that this can be asked mechanically.
func TestEveryDivergenceClassIsReachedAndOnlyThreeCarryAVerdict(t *testing.T) {
	const a, b, c = "192.0.2.10", "192.0.2.11", "192.0.2.12"

	cases := []struct {
		name   string
		direct []string
		system []string
		// answeredEmpty turns an empty address list from silence into an ANSWER
		// that carried no address - NXDOMAIN from every resolver and a system
		// lookup that came back with nothing. Those are different facts about
		// somebody's network, and telling them apart is the whole of ADR40.
		answeredEmpty bool
		want          report.Divergence
		wantStatus    status.Status
	}{
		{"the same addresses", []string{a, b}, []string{b, a}, false, report.DivergenceAgree, status.Pass},
		{"ours has more", []string{a, b}, []string{a}, false, report.DivergenceSuperset, status.Pass},
		{"theirs has more", []string{a}, []string{a, b}, false, report.DivergenceSuperset, status.Pass},
		{"nothing in common", []string{a}, []string{b}, false, report.DivergenceDisjoint, status.Warn},
		{"only ours answered", []string{a}, nil, false, report.DivergenceOneSided, status.Pass},
		{"only theirs answered", nil, []string{a}, false, report.DivergenceOneSided, status.Pass},
		{"neither answered", nil, nil, false, report.DivergenceNeitherAnswered, status.Fail},
		// ADR38. Five classes did not cover this and a rotating subset produces it
		// routinely - one address in both, one in each alone.
		{"a shared address and one each", []string{a, b}, []string{b, c}, false, report.DivergenceOverlap, status.Pass},
		// ADR40, and this row is the one the table was missing. Both lenses reply,
		// neither reply carries an address, and the set comparison below would call
		// two empty sets equal - which is how a name that resolves nowhere came out
		// as agreement, with a pass under it.
		{"both said there is no such name", nil, nil, true, report.DivergenceAgreeNone, status.Fail},
	}

	// ADR42, and these two are here because the bench found them rather than
	// anybody reading the code. Both need a lens that ANSWERED WITHOUT AN ADDRESS
	// beside a lens in a different state, which the table above cannot express -
	// its empty list means either silence or an empty answer, for both lenses at
	// once.
	t.Run("a SERVFAIL beside a silent platform is not one lens succeeding", func(t *testing.T) {
		// OBS60, measured on the testbed: our own view answered SERVFAIL and the
		// platform said nothing. The name resolves no way at all, and this used to
		// come back as one_sided with a PASS under it, claiming one view had
		// resolved it.
		in := workingInput(answeringServerFailure())
		in.Resolvers = []string{"192.0.2.53"}
		in.System = systemAnswering(SystemAnswer{NoAnswer: report.NoAnswerTimeout})

		got := Ask(context.Background(), in)
		if class := systemRowOf(t, got).NameResolution.Divergence; class != report.DivergenceAgreeNone {
			t.Errorf("a SERVFAIL beside a silent platform classified as %q, want %q", class, report.DivergenceAgreeNone)
		}
		if got.Status != status.Fail {
			t.Errorf("a name that resolves no way at all came back as %s", got.Status)
		}
		if strings.Contains(got.Detail, "one view resolved") {
			t.Errorf("the sentence says a view resolved the name and none did: %q", got.Detail)
		}
	})

	t.Run("addresses beside an empty answer is one lens succeeding", func(t *testing.T) {
		// OBS57, the mirror image. One lens holds addresses, the other answered
		// and found none - which is one_sided, and used to be superset. Superset
		// claims one view contains the other, and an empty view contains nothing.
		in := workingInput(answeringWith([]string{"192.0.2.10"}))
		in.Resolvers = []string{"192.0.2.53"}
		in.System = systemAnswering(SystemAnswer{})

		got := Ask(context.Background(), in)
		if class := systemRowOf(t, got).NameResolution.Divergence; class != report.DivergenceOneSided {
			t.Errorf("addresses beside an empty answer classified as %q, want %q", class, report.DivergenceOneSided)
		}
		if got.Status != status.Pass {
			t.Errorf("one lens resolving the name came back as %s", got.Status)
		}
	})

	covered := map[report.Divergence]bool{}
	for _, tc := range cases {
		covered[tc.want] = true
		t.Run(tc.name, func(t *testing.T) {
			exchange := answeringWith(tc.direct)
			if len(tc.direct) == 0 && tc.answeredEmpty {
				exchange = answeringNoSuchName()
			}
			in := workingInput(exchange)
			in.Resolvers = []string{"192.0.2.53"}
			switch {
			case len(tc.system) > 0:
				in.System = systemAnswering(SystemAnswer{Addresses: tc.system})
			case tc.answeredEmpty:
				// An answer holding no address, which is what the platform hands
				// back for a name that does not exist. Not the same as silence.
				in.System = systemAnswering(SystemAnswer{})
			default:
				in.System = systemAnswering(SystemAnswer{NoAnswer: report.NoAnswerTimeout})
			}

			got := Ask(context.Background(), in)
			row := systemRowOf(t, got)
			if row.NameResolution.Divergence != tc.want {
				t.Errorf("direct %v against system %v classified as %q, want %q",
					tc.direct, tc.system, row.NameResolution.Divergence, tc.want)
			}
			if got.Status != tc.wantStatus {
				t.Errorf("class %q came with status %s, want %s - only disjoint, neither_answered and agree_none "+
					"carry a verdict", tc.want, got.Status, tc.wantStatus)
			}
			if broken := row.Breach(); broken != "" {
				t.Errorf("the row is refused by its own contract: %s", broken)
			}
		})
	}

	// THE TABLE HAS TO COVER THE REGISTRY, and this is the assertion whose absence
	// let agree_none reach production unexamined. A class with no row here has
	// nobody asking what status it carries.
	for _, class := range report.AllDivergences {
		if !covered[class] {
			t.Errorf("the class %q has no row in this table, so nothing here says which status it carries", class)
		}
	}
}

// TestANameThatResolvesNowhereIsNotCalledAgreement is the sentence, which is the
// part of this a person actually reads.
//
// MEASURED BY RUNNING THE BINARY, NOT REASONED ABOUT. A target under .invalid
// produced four NXDOMAIN rows, a system view with no address, and the line "both
// views resolved this name to the same addresses" - about a name that resolves
// nowhere - with a PASS in front of it. Nothing in the tree was red.
//
// THE ROWS ARE ASSERTED AS WELL AS THE VERDICT, and that is OBS56 applied to this
// test's own fixture. A status of FAIL is also what neither_answered produces, so
// a fixture where the resolvers simply stayed silent would satisfy a check on the
// status alone - and would then be passing for a reason this test is not about.
// The rows carrying NXDOMAIN are what says both resolvers ANSWERED.
func TestANameThatResolvesNowhereIsNotCalledAgreement(t *testing.T) {
	in := workingInput(answeringNoSuchName())
	in.System = systemAnswering(SystemAnswer{})

	got := Ask(context.Background(), in)

	if got.Status != status.Fail {
		t.Errorf("a name that resolves no way at all came back as %s", got.Status)
	}
	if strings.Contains(got.Detail, "same addresses") {
		t.Errorf("the sentence claims the views agreed on addresses neither of them found: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "neither") {
		t.Errorf("the sentence does not say that neither view found an address: %q", got.Detail)
	}

	row := systemRowOf(t, got)
	if row.NameResolution.Divergence != report.DivergenceAgreeNone {
		t.Errorf("the comparison came out as %q, want %q", row.NameResolution.Divergence, report.DivergenceAgreeNone)
	}

	// The other half of the fixture, without which the check above would be
	// satisfied by two resolvers that never replied.
	answers := 0
	for _, finding := range got.Findings {
		if finding.NameResolution.View != report.ViewDirect {
			continue
		}
		if finding.NameResolution.ResponseCode != "NXDOMAIN" {
			t.Errorf("a direct row reads %q, so this fixture is not the one this test is about",
				finding.NameResolution.ResponseCode)
		}
		answers++
	}
	if answers == 0 {
		t.Fatal("no direct row was produced at all, so nothing here established that the resolvers answered")
	}
}

// answeringServerFailure replies SERVFAIL to every query.
//
// It is a REPLY carrying no address, which is the state that separates ADR42
// from what came before: the resolver was reached and answered, and the answer
// was that it could not resolve the name.
func answeringServerFailure() Exchange {
	return answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyWith(id, recordType, 2), nil
	})
}

// answeringNoSuchName replies NXDOMAIN to every query, carrying no address.
//
// It is the difference between a resolver that said "there is no such name" and
// one that said nothing at all - answeringWith folds the second into an empty
// list, and ADR40 turns on telling them apart.
func answeringNoSuchName() Exchange {
	return answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyWith(id, recordType, 3), nil
	})
}

// answeringWith replies with a fixed address list for every query, or with a
// timeout when the list is empty.
func answeringWith(addresses []string) Exchange {
	return func(_ context.Context, _ string, query []byte) ([]byte, error) {
		if len(addresses) == 0 {
			return nil, ErrTimeout
		}
		id := uint16(query[0])<<8 | uint16(query[1])
		asked := dnsmsg.Type(uint16(query[len(query)-4])<<8 | uint16(query[len(query)-3]))
		// Only the A queries carry addresses. Putting four byte addresses into a
		// AAAA answer would make a malformed packet, which the parser refuses -
		// correctly - and the test would then be measuring its own fixture.
		if asked != dnsmsg.TypeA {
			return replyWith(id, asked, 0), nil
		}
		raw := make([][]byte, 0, len(addresses))
		for _, address := range addresses {
			parts := [4]byte{}
			var n1, n2, n3, n4 int
			_, _ = fmt.Sscanf(address, "%d.%d.%d.%d", &n1, &n2, &n3, &n4)
			parts = [4]byte{byte(n1), byte(n2), byte(n3), byte(n4)}
			raw = append(raw, parts[:])
		}
		return replyWith(id, asked, 0, raw...), nil
	}
}

// TestTheUnionIsEveryResolverAndNotTheFirstOne is ADR31, at the place where
// taking a shortcut would be invisible.
//
// Comparing against one resolver's answer would be a silent judgement about
// whose answer counts, and on a machine whose resolvers agree it would produce
// exactly the same output as the union - so nothing would ever show it. Here the
// two resolvers answer differently on purpose: only the union covers what the
// platform returned, and a first-resolver comparison would call it disjoint,
// which is the class that raises a warning.
func TestTheUnionIsEveryResolverAndNotTheFirstOne(t *testing.T) {
	const first, second = "192.0.2.10", "192.0.2.11"

	in := workingInput(func(_ context.Context, resolver string, query []byte) ([]byte, error) {
		id := uint16(query[0])<<8 | uint16(query[1])
		asked := dnsmsg.Type(uint16(query[len(query)-4])<<8 | uint16(query[len(query)-3]))
		if asked != dnsmsg.TypeA {
			return replyWith(id, asked, 0), nil
		}
		if resolver == "192.0.2.53" {
			return replyWith(id, asked, 0, []byte{192, 0, 2, 10}), nil
		}
		return replyWith(id, asked, 0, []byte{192, 0, 2, 11}), nil
	})
	in.System = systemAnswering(SystemAnswer{Addresses: []string{first, second}})

	got := Ask(context.Background(), in)
	row := systemRowOf(t, got)
	if row.NameResolution.Divergence != report.DivergenceAgree {
		t.Errorf("the platform returned exactly what the two resolvers said between them, and the class is %q",
			row.NameResolution.Divergence)
	}
	if got.Status != status.Pass {
		t.Errorf("a comparison against every resolver agrees, and the layer said %s: %q", got.Status, got.Detail)
	}
}

// TestADirectRowMayNotCarryTheComparison is the contract rule from ADR37, and
// the failure it prevents is arithmetic rather than dramatic.
//
// Two resolvers times two record types is four direct rows. A class copied onto
// each of them is one fact stored four times, which stays true exactly until
// somebody edits one copy - and a reader has no way to know which of the four is
// the one that was computed.
func TestADirectRowMayNotCarryTheComparison(t *testing.T) {
	// THE SUMMARY IS FILLED IN AND THE FIRST VERSION OF THIS TEST LEFT IT EMPTY,
	// which the mutation register caught and reading never would have. A finding
	// with no summary breaches the contract on its own, so the assertion "this
	// row is refused" was satisfied whatever the divergence rule did - the test
	// passed for a reason it was not about. Hence the second assertion too: the
	// refusal has to NAME the thing being defended.
	row := report.Finding{
		Kind:    report.FindingNameResolution,
		Summary: "192.0.2.53 answered NOERROR for example.com A",
		Source:  report.SourceDetected,
		NameResolution: &report.NameResolution{
			Name:         "example.com",
			View:         report.ViewDirect,
			Resolver:     "192.0.2.53",
			QueryType:    "A",
			ResponseCode: "NOERROR",
			Divergence:   report.DivergenceAgree,
		},
	}
	broken := row.Breach()
	if broken == "" {
		t.Fatal("a direct row carried the comparison of the two views and the contract accepted it")
	}
	if !strings.Contains(broken, "divergence") {
		t.Errorf("the row was refused for something else, so this test proves nothing about the rule: %s", broken)
	}

	// The other side, so the rule cannot be satisfied by refusing every direct
	// row: the same row without the class has to be accepted.
	row.NameResolution.Divergence = ""
	if broken := row.Breach(); broken != "" {
		t.Errorf("an ordinary direct row was refused: %s", broken)
	}
}

// TestTheComparisonIsBySetAndNotByOrder pins the property the acceptance suite
// paid for once already.
//
// A resolver behind a large name rotates the order it hands addresses back, and
// a comparison sensitive to that would report a working load balancer as a
// divergence - which is exactly how the determinism check broke at K3b-1.
func TestTheComparisonIsBySetAndNotByOrder(t *testing.T) {
	in := workingInput(answeringWith([]string{"192.0.2.10", "192.0.2.11"}))
	in.Resolvers = []string{"192.0.2.53"}
	in.System = systemAnswering(SystemAnswer{Addresses: []string{"192.0.2.11", "192.0.2.10"}})

	row := systemRowOf(t, Ask(context.Background(), in))
	if row.NameResolution.Divergence != report.DivergenceAgree {
		t.Errorf("the same two addresses in a different order classified as %q", row.NameResolution.Divergence)
	}
}

// TestADerivedAnswerSaysWhatItWasDerivedFrom is the second half of ADR28, which
// stood in the decision register unkept until now.
//
// A derived answer means OUR resolver stood in for the platform's. The question
// that then matters is whether the thing it stood in for would have looked
// somewhere we never look - and the hosts file is exactly that place. Probe S10
// measured it: change the line to "hosts: dns" and an entry in the hosts file
// stops resolving. That is the whole explanation for the disagreement D13 saw on
// localhost, and without it the report shows the disagreement and not the cause.
//
// THE NOT-DERIVED CASE IS IN THE TABLE ON PURPOSE. When the platform did the
// work itself, its own order is what it used and nothing needs explaining - a
// note there would be noise, and noise in every run is how notes stop being read.
func TestADerivedAnswerSaysWhatItWasDerivedFrom(t *testing.T) {
	cases := []struct {
		name     string
		platform bool
		sources  NameSources
		failed   error
		want     string
		absent   string
	}{
		{
			name:    "the file names the hosts source",
			sources: NameSources{Declared: true, Order: []string{"files", "dns"}},
			want:    "looks in the hosts file",
		},
		{
			name:    "the file names dns alone",
			sources: NameSources{Declared: true, Order: []string{"dns"}},
			want:    "does not look in the hosts file",
		},
		{
			name: "nothing was declared anywhere",
			want: "records no order of its own",
		},
		{
			name:   "the file could not be read",
			failed: errors.New("permission denied"),
			want:   "could not be read",
		},
		{
			// THE PLATFORM DID IT ITSELF, so its own order is not our business.
			name:     "the platform resolved it",
			platform: true,
			sources:  NameSources{Declared: true, Order: []string{"files", "dns"}},
			absent:   "hosts file",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
				return replyWith(id, recordType, 0, addressFor(recordType)), nil
			}))
			in.Sources = c.sources
			in.SourcesError = c.failed
			in.System = systemAnswering(SystemAnswer{Addresses: []string{"192.0.2.10"}, ViaPlatform: c.platform})

			row := systemRowOf(t, Ask(context.Background(), in))
			if c.want != "" && !strings.Contains(row.Summary, c.want) {
				t.Errorf("the row does not say %q: %s", c.want, row.Summary)
			}
			if c.absent != "" && strings.Contains(row.Summary, c.absent) {
				t.Errorf("the row explains the platform's own order back to it: %s", row.Summary)
			}
		})
	}
}

// rowsOf renders the rows compactly for a failure message. A failing budget test
// that does not show what each resolver did leaves the reader guessing which half
// broke.
func rowsOf(r Result) string {
	var out strings.Builder
	for _, finding := range r.Findings {
		body := finding.NameResolution
		fmt.Fprintf(&out, "\n  %s %s code=%q no_answer=%q", body.Resolver, body.QueryType, body.ResponseCode, body.NoAnswer)
	}
	return out.String()
}

// TestTheLayerSentenceCountsResolversAndNamesNone is ADR32 defended at the one
// place a resolver address would leak by being written before anybody thought
// about masking.
func TestTheLayerSentenceCountsResolversAndNamesNone(t *testing.T) {
	got := Ask(context.Background(), workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyWith(id, recordType, 0, []byte{192, 0, 2, 10}), nil
	})))

	for _, resolver := range []string{"192.0.2.53", "198.51.100.53"} {
		if strings.Contains(got.Detail, resolver) {
			t.Errorf("the layer's own sentence names a resolver: %q", got.Detail)
		}
	}
	if !strings.Contains(got.Detail, "2 resolver(s)") {
		t.Errorf("the sentence does not say how many resolvers were asked: %q", got.Detail)
	}
}

// TestAnAnswerToSomebodyElsesQuestionIsNotBelieved covers the identifier check,
// which is the only thing standing between this layer and an off-path reply.
//
// It is here rather than in dnsmsg because the identifier is generated in one
// place and compared in another: the first version of the layer built the query
// with a fresh identifier and parsed the reply against a literal zero, so every
// real answer would have been reported as unreadable.
func TestAnAnswerToSomebodyElsesQuestionIsNotBelieved(t *testing.T) {
	in := workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		return replyWith(id+1, recordType, 0, []byte{192, 0, 2, 10}), nil
	}))
	in.Resolvers = []string{"192.0.2.53"}
	got := Ask(context.Background(), in)

	for _, finding := range got.Findings {
		if finding.NameResolution.NoAnswer != report.NoAnswerUnreadableAnswer {
			t.Errorf("an answer carrying somebody else's identifier was accepted as %q",
				finding.NameResolution.ResponseCode)
		}
	}
}

// TestATruncatedAnswerSaysSoInTheSentence keeps the TC bit visible on every
// surface.
//
// The alternative to saying it is handing back a shortened list of addresses that
// looks complete, which is a confident wrong answer about somebody's DNS.
func TestATruncatedAnswerSaysSoInTheSentence(t *testing.T) {
	in := workingInput(answering(func(id uint16, recordType dnsmsg.Type) ([]byte, error) {
		reply := replyWith(id, recordType, 0, addressFor(recordType))
		reply[2] |= 0x02
		return reply, nil
	}))
	in.Resolvers = []string{"192.0.2.53"}
	got := Ask(context.Background(), in)

	for _, finding := range got.Findings {
		if !strings.Contains(finding.Summary, "truncated") {
			t.Errorf("a truncated answer renders as %q, which reads as a complete list", finding.Summary)
		}
	}
}

// TestANameThatCannotBeAskedAboutIsARowNotACrash covers the degenerate input
// this layer will really get: a target whose host is not a name a resolver would
// accept.
func TestANameThatCannotBeAskedAboutIsARowNotACrash(t *testing.T) {
	in := workingInput(answering(func(uint16, dnsmsg.Type) ([]byte, error) {
		return nil, errors.New("the exchange should never have been reached")
	}))
	in.Name = strings.Repeat("a", 64) + ".example.com"
	in.Resolvers = []string{"192.0.2.53"}
	got := Ask(context.Background(), in)

	if len(got.Findings) == 0 {
		t.Fatal("a name that cannot be encoded produced no row at all")
	}
	for _, finding := range got.Findings {
		if breach := finding.Breach(); breach != "" {
			t.Errorf("the layer produced a finding that %s", breach)
		}
		if finding.NameResolution.NoAnswer == "" {
			t.Error("a query that was never sent claims to have an answer")
		}
	}
}
