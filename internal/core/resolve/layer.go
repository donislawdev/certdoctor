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
	// System asks the platform the same question, and is the second of the two
	// lenses D3 requires.
	//
	// A NIL ONE IS NOT A DEFECT AND DOES NOT STOP THE WALK, unlike the ports
	// above. The direct view establishes something on its own, so a run without
	// the system lens is a narrower answer rather than no answer - and the report
	// says which of the two it is holding rather than leaving the reader to count
	// lenses.
	System SystemLookup
	// Sources is what this machine records about WHERE it looks a name up, as
	// opposed to which server it asks.
	//
	// IT IS THE SECOND HALF OF WHAT ADR28 PROMISED. A derived answer has to say
	// what it was derived FROM, and the hosts line is the part that explains the
	// disagreement D13 measured on localhost: the platform may look in the hosts
	// file and our own view never does, under any configuration. The zero value
	// says nothing was declared, which is a fact rather than a gap.
	Sources NameSources
	// SourcesError is what went wrong while reading that, or nil.
	//
	// IT IS A VALUE FOR THE SAME REASON ResolversError IS, and this field exists
	// because dropping it hid a real defect for the length of one measurement:
	// the reader was never wired at all, and the layer reported "this machine
	// records no order of its own" about a machine whose file says files dns.
	// "Nothing was declared" and "we could not read what was declared" are two
	// facts, and the second one is about US.
	SourcesError error
	// PerQuery is the longest one query may take. It is capped by whatever is
	// left of the layer's own deadline, never the other way round.
	PerQuery time.Duration
}

// SystemLookup asks the platform to resolve a name the way any other program on
// this machine would.
//
// IT TAKES NO RESOLVER AND RETURNS NO RESPONSE CODE, and neither is an
// oversight. The platform resolves a name and does not say which server answered
// it, which record type it asked for, or what the reply's code was - so the
// finding contract refuses a system row carrying any of the three. Those are the
// three most useful columns of a row, which makes them the three a plausible
// mistake fills in, and a filled-in row reads like a measurement.
type SystemLookup func(ctx context.Context, name string) SystemAnswer

// SystemAnswer is what the platform said, plus the one fact only the adapter can
// establish.
type SystemAnswer struct {
	// Addresses are what the name resolved to, in the order the platform gave
	// them.
	Addresses []string
	// ViaPlatform says the question went through the platform's own resolver
	// rather than the one built into this binary.
	//
	// ADR28: THE ADAPTER DECIDES THIS AT RUN TIME AND THE CORE ONLY TRANSLATES.
	// It is not a fact about the operating system or about how this was built -
	// probe S10 measured a cgo-enabled binary on glibc going through Go's own
	// resolver anyway - it is a fact about what happened during THIS query. The
	// core turns it into detected or derived and asks nothing else.
	ViaPlatform bool
	// NoAnswer says why there is no answer, and is empty when there is one.
	NoAnswer report.NoAnswer
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
	// A MACHINE THAT LISTS NO RESOLVER CAN STILL RESOLVE NAMES, and that is not a
	// theory - S11 measured it. With an empty resolv.conf the platform asks
	// loopback, and a container whose local resolver answered had this layer
	// report there was nobody to ask. So "nothing to check" now needs BOTH lenses
	// to be missing, not just our own list.
	if len(in.Resolvers) == 0 && in.System == nil {
		return Result{Status: status.Unknown, Reason: status.ReasonNothingToCheck, Detail: in.noResolverDetail()}
	}

	counted := tallies{total: len(in.Resolvers) * len(dnsmsg.AllTypes)}
	if in.System != nil {
		// THE SYSTEM VIEW COUNTS AS A QUERY IN THE BUDGET ARITHMETIC. Leaving it
		// out would hand it whatever the direct view left over, which is the same
		// starvation ADR36 was written to remove, arriving from the other side.
		counted.total++
	}

	findings := make([]report.Finding, 0, counted.total)
	seen := map[report.NoAnswer]int{}
	sent := 0
	for _, resolver := range in.Resolvers {
		for _, recordType := range dnsmsg.AllTypes {
			finding := in.askOne(ctx, resolver, recordType, counted.total-sent)
			sent++
			counted.direct += tally(finding, seen)
			findings = append(findings, finding)
		}
	}

	// THE SYSTEM VIEW GOES LAST AND THE ORDER IS FIXED RATHER THAN CONVENIENT.
	// Whichever lens goes second asks a resolver whose cache the first one just
	// warmed, so its timing is flattering and means nothing. D13 part 2 forbids
	// putting the two views' times side by side for exactly this reason - probe
	// S4 was measured the wrong way round and its numbers could not be quoted. A
	// fixed order at least keeps the bias in one direction and written down.
	if in.System != nil {
		counted.systemAsked = true
		finding := in.askSystem(ctx, counted.total-sent)
		counted.systemAnswered = tally(finding, seen) == 1
		// THE CLASSIFICATION IS WRITTEN ONTO THIS ROW AND NOWHERE ELSE - ADR37.
		// There is one comparison per run and many direct rows, and this is the
		// row that completes it: it arrives after the union of the direct answers
		// exists, which is what ADR31 asks to compare against.
		counted.divergence = classify(unionOf(findings), finding.NameResolution.Addresses,
			counted.direct > 0, counted.systemAnswered)
		finding.NameResolution.Divergence = counted.divergence
		findings = append(findings, finding)
	}

	// D13 GIVES A VERDICT TO EXACTLY TWO OF THE CLASSES, and the other four are
	// named and left alone. That ratio is the decision: probe S4 measured the two
	// views disagreeing on five names out of five, so a layer that warned on
	// "they differ" would warn in nearly every run.
	switch counted.divergence {
	case report.DivergenceNeitherAnswered:
		// With BOTH lenses silent this stops being unknown and becomes a finding.
		// With one lens it stays unknown, and the test that pins it still passes -
		// there is no divergence to classify when there was nothing to compare.
		return Result{Status: status.Fail, Detail: in.divergenceDetail(counted), Findings: findings}
	case report.DivergenceDisjoint:
		return Result{Status: status.Warn, Detail: in.divergenceDetail(counted), Findings: findings}
	}

	if counted.direct+boolToInt(counted.systemAnswered) == 0 {
		// STILL UNKNOWN RATHER THAN FAIL, EVEN WITH BOTH LENSES SILENT, AND THAT
		// IS NOT AN OVERSIGHT. D13 does call that case FAIL, but it says so as one
		// of five named divergence classes, and the classification is the next
		// slice. Reaching for the verdict here would implement half of D13 and
		// leave the other four cases unnamed.
		return Result{
			Status:   status.Unknown,
			Reason:   reasonForNothingAnswered(seen),
			Detail:   nothingAnsweredDetail(counted, seen[report.NoAnswerNotAsked]),
			Findings: findings,
		}
	}
	counted.notAsked = seen[report.NoAnswerNotAsked]
	return Result{Status: status.Pass, Detail: in.answeredDetail(counted), Findings: findings}
}

// classify says which of the named classes describes the difference between the
// two views - D13, compared over the UNION of the direct answers (ADR31).
//
// THE UNION IS NOT AN APPROXIMATION, IT IS A CHOICE WITH A PRICE. The direct
// view produces one answer per resolver and record type, and classifying each
// against the system view separately would produce several classes in one run -
// a result no single status can carry. Union is the only fold that does not
// require picking a "main" resolver, and picking one would be a silent judgement
// about whose answer counts. The price: a resolver disagreeing with its
// neighbours vanishes into the union and is visible only in its own row.
//
// COMPARISON IS BY SET, NOT BY ORDER. Resolvers rotate the order they hand
// addresses back - the acceptance suite already caught that once, reporting a
// working load balancer as a defect in our output.
func classify(direct, system []string, directAnswered, systemAnswered bool) report.Divergence {
	switch {
	case !directAnswered && !systemAnswered:
		return report.DivergenceNeitherAnswered
	case !directAnswered || !systemAnswered:
		return report.DivergenceOneSided
	}

	inDirect := setOf(direct)
	inSystem := setOf(system)
	shared, onlyDirect, onlySystem := 0, 0, 0
	for address := range inDirect {
		if inSystem[address] {
			shared++
		} else {
			onlyDirect++
		}
	}
	for address := range inSystem {
		if !inDirect[address] {
			onlySystem++
		}
	}

	switch {
	case onlyDirect == 0 && onlySystem == 0:
		return report.DivergenceAgree
	case shared == 0:
		return report.DivergenceDisjoint
	case onlyDirect == 0 || onlySystem == 0:
		return report.DivergenceSuperset
	}
	// D13 NAMES FIVE CLASSES AND THIS IS A SIXTH SHAPE: both views answered,
	// they share an address, and each has one the other lacks. It is not
	// disjoint - they agree on something - and calling it that would raise a
	// warning about split horizon DNS on the ordinary behaviour of a load
	// balancer handing out rotating subsets, which is the exact failure D13 was
	// written to avoid. It is not a superset either, in either direction.
	return report.DivergenceOverlap
}

// setOf is comparison by membership rather than by position, because resolvers
// rotate the order they answer in and that order is not a fact about the name.
func setOf(addresses []string) map[string]bool {
	out := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		out[address] = true
	}
	return out
}

// tallies is what one walk counted. It exists so the sentence builders take one
// argument instead of four numbers whose order nobody can check at the call site.
type tallies struct {
	total          int
	direct         int
	notAsked       int
	systemAsked    bool
	systemAnswered bool
	// divergence is empty when there was no second lens to compare against.
	divergence report.Divergence
}

// unionOf folds every direct answer into one set of addresses - ADR31.
//
// IT SKIPS THE SYSTEM ROW BY CONSTRUCTION, because it is called before that row
// is appended. Reading the view field instead would work today and would break
// silently the day a third row kind appears.
func unionOf(direct []report.Finding) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, finding := range direct {
		for _, address := range finding.NameResolution.Addresses {
			if !seen[address] {
				seen[address] = true
				out = append(out, address)
			}
		}
	}
	return out
}

// divergenceDetail is the layer's sentence when the comparison itself is the
// finding.
//
// IT NAMES HOW MANY RESOLVERS WENT INTO THE UNION - ADR31 asks for exactly that,
// because "the two views disagree" means something different when the union came
// from one resolver than from three. It names a COUNT and never an address:
// this sentence goes through the same masking as everything else, but a sentence
// built out of counts cannot leak one by being written before somebody thought
// about ADR32.
func (in Input) divergenceDetail(t tallies) string {
	return fmt.Sprintf("%s, comparing what %d resolver(s) told us against what this system resolves the name to",
		t.divergence.Meaning(), len(in.Resolvers))
}

// tally counts one row as an answer or as a reason for not having one.
//
// "NO REASON" IS THE SAME FACT AS "A RESPONSE CODE" AND THAT IS ENFORCED, not
// assumed: the finding contract refuses a direct row carrying neither and refuses
// one carrying both. The system view never carries a code at all, so asking
// about the reason is the only question that fits both lenses.
func tally(finding report.Finding, seen map[report.NoAnswer]int) int {
	if finding.NameResolution.NoAnswer == "" {
		return 1
	}
	seen[finding.NameResolution.NoAnswer]++
	return 0
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// askSystem asks the platform once, inside its own share of the budget.
func (in Input) askSystem(ctx context.Context, queriesLeft int) report.Finding {
	remaining := in.limitFor(ctx, queriesLeft)
	if remaining <= 0 {
		return in.systemFinding(SystemAnswer{NoAnswer: report.NoAnswerNotAsked}, 0)
	}

	queryCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()

	started := in.Now()
	answer := in.System(queryCtx, in.Name)
	return in.systemFinding(answer, in.Now().Sub(started))
}

// systemFinding turns the platform's answer into the one row this view produces.
//
// THE THREE MOST USEFUL COLUMNS ARE LEFT EMPTY ON PURPOSE and the finding
// contract refuses them here: which resolver answered, which record type was
// asked for, and what the response code was. The platform reports none of the
// three, so filling any of them in would be inventing a measurement.
func (in Input) systemFinding(a SystemAnswer, elapsed time.Duration) report.Finding {
	// ADR28 AND ADR23 MEET HERE. The adapter reports whether the question went
	// through the platform's resolver, and that single fact - not the operating
	// system, not how this was built - decides whether the row is something we
	// observed or something our own resolver produced in the platform's place.
	source := report.SourceDerived
	if a.ViaPlatform {
		source = report.SourceDetected
	}
	return report.Finding{
		Kind:    report.FindingNameResolution,
		Summary: systemSummaryOf(in.Name, a, source, in.Sources, in.SourcesError),
		Source:  source,
		NameResolution: &report.NameResolution{
			Name:       in.Name,
			View:       report.ViewSystem,
			Addresses:  a.Addresses,
			NoAnswer:   a.NoAnswer,
			DurationMS: elapsed.Milliseconds(),
		},
	}
}

// sourcesNote says what a DERIVED answer was derived from - ADR28.
//
// IT IS ONLY ADDED WHEN THE ANSWER IS DERIVED, and that is the whole point: when
// the platform did the work itself, its own order of name sources is what it
// used and nothing here needs explaining. When OUR resolver stood in for it, the
// interesting question is whether the thing it stood in for would have looked
// somewhere we never look - and the hosts file is exactly that place. Probe S10
// measured it: change that line to "hosts: dns" and an entry in the hosts file
// stops resolving.
func sourcesNote(source report.Source, sources NameSources, failed error) string {
	if source != report.SourceDerived {
		return ""
	}
	switch {
	case failed != nil:
		return ", and where this system looks names up could not be read, so this row does not say"
	case !sources.Declared:
		return ", and this system records no order of its own for name sources, so that order is the platform default"
	case sources.ConsultsHostsFile():
		return ", which looks in the hosts file as well as in DNS - our own view never does, under any configuration"
	default:
		return ", which does not look in the hosts file, so neither view does"
	}
}

// systemSummaryOf says which resolver actually did the work, because that is the
// difference between a measurement and a reconstruction.
func systemSummaryOf(name string, a SystemAnswer, source report.Source, sources NameSources, failed error) string {
	how := "through the resolver this platform uses"
	if source == report.SourceDerived {
		how = "through the resolver built into this program, because the platform's own was not used"
	}
	if a.NoAnswer != "" {
		return fmt.Sprintf("the system view got no answer for %s %s: %s", name, how, a.NoAnswer.Meaning())
	}
	how += sourcesNote(source, sources, failed)
	return fmt.Sprintf("the system view resolved %s to %d address(es) %s", name, len(a.Addresses), how)
}

// reasonForNothingAnswered picks which of the closed list of reasons describes a
// walk where no resolver produced a response code.
//
// IT EXISTS BECAUSE probe_error USED TO BE THE ANSWER TO ALL OF THEM, and that
// word means "the probe fell over" - ADR33 says so in as many words. A run where
// every resolver stayed silent sends the reader to look at certdoctor, which is
// the one place the answer is not.
//
// TIMEOUT OUTRANKS SKIPPING BECAUSE IT IS THE CAUSE AND SKIPPING IS THE
// CONSEQUENCE. A budget spent waiting is why the later queries were never sent,
// and naming the consequence would point at our arithmetic instead of at the
// resolver that never answered.
//
// WHAT LANDS ON probe_error IS NAMED RATHER THAN LEFT TO BE DISCOVERED. A
// refusal by the allowed set genuinely is our own doing, so it belongs there.
// A transport error - the wire said no - does NOT, and there is no value in the
// closed list that says it. It is the least wrong of six rather than the right
// one, and the list is a public contract that does not grow without the owner.
func reasonForNothingAnswered(seen map[report.NoAnswer]int) status.Reason {
	switch {
	case seen[report.NoAnswerTimeout] > 0:
		return status.ReasonTimeout
	case seen[report.NoAnswerNotAsked] > 0:
		return status.ReasonSkippedBudget
	case seen[report.NoAnswerUnreadableAnswer] > 0:
		return status.ReasonUnparseable
	case seen[report.NoAnswerTransportError] > 0:
		// ADDED WITH THE SEVENTH REASON - ADR39, closing OBS55. This used to fall
		// through to probe_error, which says this program broke, and sent the
		// reader to look at certdoctor while the answer was a cable or a firewall.
		return status.ReasonTransportError
	}
	// WHAT IS LEFT IS OURS AND ONLY OURS: a refusal by our own allowed set. It is
	// the one remaining way to reach this line, and probe_error is the right word
	// for it - the run was stopped by a rule this program applied to itself.
	return status.ReasonProbeError
}

// nothingAnsweredDetail adds the count of queries that never went out.
//
// INVIOLABLE RULE 1 ON THE ONE SENTENCE ANYBODY READS. "No resolver answered" is
// true about the queries that were sent and misleading about the machine when
// three of four were never sent at all. The rows carry not_asked honestly, but
// they are below the fold of a terminal report and the sentence is not.
func nothingAnsweredDetail(t tallies, notAsked int) string {
	// ONE LENS IS THE ONLY WAY TO REACH THIS SENTENCE, and it took the
	// classification to make that true. A run holding both lenses where neither
	// answered is classified neither_answered and ends as a verdict before it
	// gets here - so the branch that used to swap in a two-lens wording was
	// unreachable the moment D13 was implemented, and the coverage gate found it
	// the same hour. That is the fifth piece of defensive code in this tree that
	// defended nothing, and the fifth deleted with its reason rather than kept.
	said := nothingAnswered
	if notAsked == 0 {
		return said
	}
	return fmt.Sprintf("%s. %d of %d queries were not asked, because this layer ran out of its budget first",
		said, notAsked, t.total)
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
// It also names queries that never went out, for the same reason the sentence
// above does: a walk that asked half of what it planned and says only what came
// back is a partial result wearing the shape of a complete one.
func (in Input) answeredDetail(t tallies) string {
	// "asked 0 resolver(s) for 2 record type(s)" is arithmetic rather than a
	// sentence, and it is what a machine with an empty resolv.conf produced. The
	// direct view having nobody to ask is a fact worth saying in words, because
	// it is half of the answer on exactly the machine where the other half comes
	// from the platform.
	said := "this machine lists no resolver of its own to ask"
	if len(in.Resolvers) > 0 {
		said = fmt.Sprintf("asked %d resolver(s) for %d record type(s) and got %d answer(s)",
			len(in.Resolvers), len(dnsmsg.AllTypes), t.direct)
	}
	if t.notAsked > 0 {
		said += fmt.Sprintf(", and %d query(ies) were not asked within the budget", t.notAsked)
	}
	// WHICH LENSES WERE USED IS PART OF THE ANSWER, NOT A FOOTNOTE. A report
	// holding one view reads exactly like a report holding two unless it says so,
	// and D3 asks for both - so a run with only ours has to admit it in the same
	// sentence that carries the good news.
	switch {
	case !t.systemAsked:
		said += ", with our own view only"
	case t.systemAnswered:
		said += ", and the system view answered"
	default:
		said += ", and the system view did not answer"
	}
	// The class goes in the sentence as well as in the field, because the two
	// classes that are not a verdict are still the interesting half of the
	// answer - "one view saw an address the other did not" is what somebody came
	// here to read, and a reader of the terminal report never sees the field.
	if t.divergence != "" {
		said += fmt.Sprintf(", and %s", t.divergence.Meaning())
	}
	return said
}

// askOne sends a single query and turns whatever happened into one finding.
//
// IT ALWAYS PRODUCES A ROW. A query that was refused, timed out or was never
// asked at all is still a row saying so - inviolable rule 1 - because a report
// with fewer rows reads as a machine with fewer resolvers rather than as a run
// that did less than it promised.
// queriesLeft counts this query and every one after it, so the share it is given
// shrinks as the walk goes on and grows again whenever somebody answers early.
func (in Input) askOne(ctx context.Context, resolver string, recordType dnsmsg.Type, queriesLeft int) report.Finding {
	remaining := in.limitFor(ctx, queriesLeft)
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

// limitFor is how long one query may take: the shorter of its own limit and its
// SHARE of whatever is left of the layer's deadline.
//
// THE SHARE IS THE POINT, AND IT REPLACED AN ARITHMETIC THAT WAS MEASURABLY
// WRONG - OBS53, ADR36. This used to hand each query everything that was left,
// which is only a cap when PerQuery is smaller than the layer budget. The entry
// point derives both from the same switch, so it never was: one silent resolver
// took 10008 ms of a ten second budget, three of four queries came back
// not_asked, and the layer reported "no resolver answered" about a machine whose
// second resolver answers in milliseconds.
//
// DIVIDING WHAT IS LEFT, RATHER THAN THE WHOLE BUDGET, IS WHAT MAKES THIS CHEAP.
// A query that answered in 30 ms hands the rest of its share back to the queries
// after it, so a healthy machine is not slowed down by arithmetic meant for a
// broken one. A fixed split would punish the fast machine to protect the slow.
//
// THE PRICE IS NAMED RATHER THAN HIDDEN: a slow but working resolver can now be
// cut off where it used to finish. That is the better half of the trade, because
// the alternative is letting one resolver answer on behalf of the whole layer.
func (in Input) limitFor(ctx context.Context, queriesLeft int) time.Duration {
	deadline, set := ctx.Deadline()
	if !set {
		// No layer deadline at all: there is nothing to divide, and the query's
		// own limit is the only thing left. Zero here means the caller asked for
		// no limit and got one, which is what it asked for.
		return in.PerQuery
	}
	left := deadline.Sub(in.Now())
	if left <= 0 {
		return 0
	}
	share := left
	if queriesLeft > 1 {
		share = left / time.Duration(queriesLeft)
	}
	if in.PerQuery > 0 && in.PerQuery < share {
		return in.PerQuery
	}
	return share
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
