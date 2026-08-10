package resolve

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/dnsmsg"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Exchange sends one query to one resolver and hands back what came home.
//
// IT TAKES AND RETURNS BYTES, AND THE LAYER NEVER HOLDS A SOCKET. That is not
// tidiness: a socket has to be closed on every path out, including the ones
// where something already went wrong, and the count of those paths is where a
// leak hides. Keeping the whole lifetime inside one adapter puts the leak test
// in one place too - docs/22 section 6a.
//
// It is declared HERE rather than imported from the adapter that implements it,
// because the core may not name a type from internal/adapter - the layer guard
// refuses that import by name. The plumbing arrives from cmd, the same way the
// environment reaches L0.
type Exchange func(ctx context.Context, resolver string, query []byte) ([]byte, error)

// The three failures a caller of Exchange has to be able to tell apart.
//
// THEY ARE SENTINELS HERE AND NOT TYPES FROM THE ADAPTER, for the same reason
// Exchange is declared here: the refusal this layer cares about is produced by
// dial.Guarded, which lives one floor up and cannot be named from the core. The
// adapter maps its own errors onto these three, so the decision "which reason
// does the report show" is made where the report is built.
//
// ANYTHING ELSE IS A TRANSPORT ERROR, and that is the deliberate default. A
// failure we did not anticipate is reported as one that happened on the wire
// rather than silently as something we understood.
var (
	// ErrRefused - the allowed set refused this address, so nothing was sent.
	// It is a fact about US and must never be shown as a network failure.
	ErrRefused = errors.New("this resolver is not in the set of places this run may connect to")
	// ErrTimeout - the query went out and nothing came back in time.
	//
	// SILENCE IS NOT SERVFAIL, and this project has the measurement: a forward
	// to an unroutable address produces nothing at all, where a broken upstream
	// produces a response code. Two facts, two places to go and look.
	ErrTimeout = errors.New("nothing came back before the deadline")
)

// Input is everything one walk of L1 was handed.
//
// EVERY FIELD IS A PORT OR A VALUE, and nothing here reaches the machine. That
// is what lets the awkward cases - a resolver that answers for A and not AAAA, a
// budget that runs out half way - be tested without owning a machine that has
// them.
type Input struct {
	// Name is the host to resolve, RAW.
	//
	// IT IS NOT run.Options.Target AND THE DIFFERENCE IS THE WHOLE POINT. That
	// field carries the target AFTER masking, so a layer fed from it would spend
	// the run under --redact resolving the literal name [host-1]. The entry point
	// hands the real host over separately, and a test pins that it does.
	Name string
	// Resolvers are the addresses to ask, in the order the machine lists them.
	//
	// ORDER IS CONFIGURATION, NOT PREFERENCE, and it is preserved for that
	// reason: a resolver library tries them in this order, so a report that
	// reordered them would describe a machine that does not exist.
	//
	// They arrive already enumerated rather than being read here, because the
	// masking has to know them BEFORE the walk starts - a pseudonym is issued
	// once per report and the redaction is built at the entry point (ADR32).
	Resolvers []string
	// ResolversFrom says how the list was obtained, or is empty when the
	// enumeration itself failed. It goes straight into the layer's own sentence.
	ResolversFrom string
	// ResolversError is what went wrong while enumerating, or nil.
	//
	// IT IS A VALUE AND NOT A PANIC OR AN EARLY RETURN AT THE ENTRY POINT,
	// because "this machine has no resolver we could find" is a diagnosis and
	// belongs in the report as one - inviolable rule 15, degrade with a reason.
	ResolversError error

	// Exchange is how a query reaches a resolver. A nil one refuses everything,
	// the same direction dial.Guarded and file.Guarded chose: a forgotten port
	// must read as a program that cannot ask, never as one with no restrictions.
	Exchange Exchange
	// QueryID picks the identifier of one query.
	//
	// IT IS A PORT BECAUSE THE CORE HAS NO SOURCE OF RANDOMNESS, and the value
	// matters: an unpredictable identifier is the only thing that makes an
	// off-path answer detectable at all. A nil one is a defect on our side and
	// the layer says so rather than sending a predictable zero.
	QueryID func() uint16
	// Now is the clock, taken as a port so the budget arithmetic is testable
	// without waiting for real time to pass.
	Now func() time.Time
	// PerQuery is the longest one query may take. It is capped by whatever is
	// left of the layer's own deadline, never the other way round.
	PerQuery time.Duration
}

// Result is what L1 established, before anything has been masked.
type Result struct {
	Status status.Status
	Reason status.Reason
	Detail string
	// Findings is one entry per answer - per resolver and per record type.
	//
	// Nil means this layer did not look and an empty slice means it looked and
	// found nothing, and the two are kept apart deliberately - ADR20.
	Findings []report.Finding
}

// Sentences for the cases where the layer establishes nothing. They are
// constants so that the same wording cannot drift between here and a test.
const (
	noExchange      = "no way to send a query was supplied, so nothing about name resolution was established"
	noQueryID       = "no source of query identifiers was supplied, and a predictable identifier would make an off-path answer undetectable"
	noClock         = "no clock was supplied, so the time each answer took could not be established"
	noResolvers     = "this machine lists no DNS resolver we could find, so there was nobody to ask"
	nothingAnswered = "no resolver answered, and with only our own view there is no way to tell a name that does not resolve from one this view cannot see"
)

// Ask walks every resolver and every record type once, and reports what came
// back.
//
// WHAT IT DELIBERATELY DOES NOT DO YET: compare views. This is the direct view
// alone - our own queries to named resolvers - and the system view arrives in the
// next slice together with the divergence classification from D13. The report
// says so in a note rather than leaving the reader to notice one lens missing.
func Ask(ctx context.Context, in Input) Result {
	if broken := in.unusable(); broken != "" {
		return Result{Status: status.Unknown, Reason: status.ReasonProbeError, Detail: broken}
	}
	if len(in.Resolvers) == 0 {
		return Result{Status: status.Unknown, Reason: status.ReasonNothingToCheck, Detail: in.noResolverDetail()}
	}

	findings := make([]report.Finding, 0, len(in.Resolvers)*len(dnsmsg.AllTypes))
	answered := 0
	for _, resolver := range in.Resolvers {
		for _, recordType := range dnsmsg.AllTypes {
			finding := in.askOne(ctx, resolver, recordType)
			if finding.NameResolution.ResponseCode != "" {
				answered++
			}
			findings = append(findings, finding)
		}
	}

	if answered == 0 {
		return Result{
			Status:   status.Unknown,
			Reason:   status.ReasonProbeError,
			Detail:   nothingAnswered,
			Findings: findings,
		}
	}
	return Result{Status: status.Pass, Detail: in.answeredDetail(answered), Findings: findings}
}

// unusable names the port this layer was not given, or returns empty.
//
// Each of these is a defect on OUR side rather than anything about the machine
// being diagnosed, so each ends the walk before a single query goes out - and
// each says which port was missing, because "L1 could not run" without a reason
// is the shape of silence this whole program is built against.
func (in Input) unusable() string {
	switch {
	case in.Exchange == nil:
		return noExchange
	case in.QueryID == nil:
		return noQueryID
	case in.Now == nil:
		return noClock
	}
	return ""
}

// noResolverDetail explains an empty resolver list, and the two causes are not
// the same fact.
//
// A machine that genuinely lists none is a finding about that machine. An
// enumeration that FAILED is a gap in what we could read, and reporting it as
// the former would state, confidently, that somebody has no DNS configured.
func (in Input) noResolverDetail() string {
	if in.ResolversError != nil {
		return fmt.Sprintf("the resolvers this machine uses could not be read, so there was nobody to ask: %v",
			in.ResolversError)
	}
	return noResolvers
}

// answeredDetail is the layer's one line when it established something.
//
// IT COUNTS RESOLVERS AND NAMES NONE OF THEM, and that is not brevity. A
// resolver address is masked under --redact (ADR32) and this sentence goes
// through the same masking as everything else - but a sentence built from counts
// cannot leak one by being written before somebody thought about it.
func (in Input) answeredDetail(answered int) string {
	return fmt.Sprintf("asked %d resolver(s) for %d record type(s) and got %d answer(s)",
		len(in.Resolvers), len(dnsmsg.AllTypes), answered)
}

// askOne sends a single query and turns whatever happened into one finding.
//
// IT ALWAYS PRODUCES A ROW. A query that was refused, timed out or was never
// asked at all is still a row saying so - inviolable rule 1 - because a report
// with fewer rows reads as a machine with fewer resolvers rather than as a run
// that did less than it promised.
func (in Input) askOne(ctx context.Context, resolver string, recordType dnsmsg.Type) report.Finding {
	remaining := in.remaining(ctx)
	if remaining <= 0 {
		return in.finding(resolver, recordType, answer{noAnswer: report.NoAnswerNotAsked})
	}

	// THE IDENTIFIER IS KEPT AND CHECKED AGAINST THE REPLY, and the first version
	// of this function did not keep it - it built the query with a fresh one and
	// then parsed with a literal zero. Every real answer would have come back as
	// unreadable, and on a machine where DNS works that reads as DNS being broken.
	// Comparing it is also the whole reason the identifier is unpredictable: it is
	// what makes an answer from somewhere else detectable.
	id := in.QueryID()
	query, err := dnsmsg.Query(id, in.Name, recordType)
	if err != nil {
		// The name cannot be put on the wire at all. It is a fact about what the
		// user typed, not about their network, and it is the same for every
		// resolver - which the row says by carrying the reason rather than a
		// response code somebody could read as coming from this resolver.
		return in.finding(resolver, recordType, answer{noAnswer: report.NoAnswerUnreadableAnswer})
	}

	queryCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()

	started := in.Now()
	reply, err := in.Exchange(queryCtx, resolver, query)
	elapsed := in.Now().Sub(started)

	if err != nil {
		return in.finding(resolver, recordType, answer{noAnswer: reasonFor(err), elapsed: elapsed})
	}
	message, err := dnsmsg.Parse(reply, id, recordType)
	if err != nil {
		return in.finding(resolver, recordType, answer{noAnswer: report.NoAnswerUnreadableAnswer, elapsed: elapsed})
	}
	return in.finding(resolver, recordType, answer{
		code:      message.ResponseCode,
		truncated: message.Truncated,
		addresses: message.Addresses,
		elapsed:   elapsed,
	})
}

// remaining is how long one query may take: the shorter of its own limit and
// whatever is left of the layer's deadline.
//
// THE CAP IS THE POINT AND THE ARITHMETIC IS WHY THIS LAYER NAMES SKIPPED
// QUERIES. Three resolvers times two record types at three seconds each is
// eighteen seconds against a ten second layer budget, so on a slow network the
// last queries WILL be dropped. A layer that let each query take its full limit
// would spend the whole run's time and then report a timeout of its own.
func (in Input) remaining(ctx context.Context) time.Duration {
	deadline, set := ctx.Deadline()
	if !set {
		return in.PerQuery
	}
	left := deadline.Sub(in.Now())
	if in.PerQuery > 0 && in.PerQuery < left {
		return in.PerQuery
	}
	return left
}

// reasonFor maps an exchange failure onto the closed list of reasons.
//
// The default is transport error rather than anything more specific, because a
// failure nobody anticipated is better reported as having happened on the wire
// than as one we recognised and did not.
func reasonFor(err error) report.NoAnswer {
	switch {
	case errors.Is(err, ErrRefused):
		return report.NoAnswerRefusedByRule
	case errors.Is(err, ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return report.NoAnswerTimeout
	}
	return report.NoAnswerTransportError
}

// answer is what one exchange produced, before it becomes a finding.
type answer struct {
	code      string
	noAnswer  report.NoAnswer
	truncated bool
	addresses []string
	elapsed   time.Duration
}

// finding wraps one answer into the shape the report holds.
//
// The direct view is always detected and never derived - it is our own
// measurement, and the finding contract refuses the other combination rather
// than trusting anybody to remember (ADR23).
func (in Input) finding(resolver string, recordType dnsmsg.Type, a answer) report.Finding {
	return report.Finding{
		Kind:    report.FindingNameResolution,
		Summary: summaryOf(in.Name, resolver, recordType, a),
		Source:  report.SourceDetected,
		NameResolution: &report.NameResolution{
			Name:         in.Name,
			View:         report.ViewDirect,
			Resolver:     resolver,
			QueryType:    recordType.String(),
			ResponseCode: a.code,
			NoAnswer:     a.noAnswer,
			Addresses:    a.addresses,
			// Whole milliseconds, and deliberately coarse - D13 forbids putting
			// two answers' times side by side, and a unit that cannot express the
			// difference between two warm cache hits does not invite it.
			DurationMS: a.elapsed.Milliseconds(),
		},
	}
}

// summaryOf is the sentence every surface renders without knowing the kind.
//
// THE RESPONSE CODE LIVES HERE AND NOT IN A COLUMN, and that is what keeps the
// three output surfaces at parity by default. A SERVFAIL visible only in a
// column this renderer happens to print would be invisible in markdown the day
// that renderer exists.
func summaryOf(name, resolver string, recordType dnsmsg.Type, a answer) string {
	if a.noAnswer != "" {
		return fmt.Sprintf("%s gave no answer for %s %s: %s", resolver, name, recordType, a.noAnswer.Meaning())
	}
	summary := fmt.Sprintf("%s answered %s for %s %s", resolver, a.code, name, recordType)
	if a.truncated {
		// REPORTED, NEVER SWALLOWED. The alternative to saying this is handing
		// back a shortened list of addresses that looks complete, which is a
		// confident wrong answer about somebody's DNS.
		summary += " (truncated, so this list may be short)"
	}
	return summary
}
