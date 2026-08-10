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
	if got.Reason != status.ReasonProbeError {
		t.Errorf("the reason is %q", got.Reason)
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
