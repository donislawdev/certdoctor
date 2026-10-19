package trust

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Probe asks one runtime family what it makes of the presented chain.
//
// IT RETURNS EVIDENCE AND NEVER A STATUS - ADR7. A probe says what it found:
// which installations exist, where each keeps its anchors, and whether the chain
// builds a path in that store. Turning those into PASS, WARN, FAIL or UNKNOWN is
// this layer's job, and keeping the two apart is what lets a probe be tested
// against a real machine without a verdict getting in the way.
//
// ZERO INSTANCES IS A LEGITIMATE ANSWER and it is not an error: the runtime is
// simply not on this machine. docs/20 rule 1 puts that outside the matrix with a
// note rather than inside it as a status, because "there is no git here" is not
// a fact about trust.
type Probe func(ctx context.Context, chain [][]byte) ([]report.TrustStore, error)

// Input is everything one walk of L5 was handed.
type Input struct {
	// PresentedChain is what L4 saw, DER encoded, leaf first - asked for AT WALK
	// TIME, the same seam L3 and L4 use and for the same reason: it does not
	// exist when the entry point assembles everything else.
	//
	// IT IS RAW BYTES RATHER THAN report.Certificate, and the difference is
	// forced: verifying a path needs the certificate, and report.Certificate is a
	// SUMMARY built for people to read. This layer does not import L4 - the bytes
	// arrive through this port, exactly as addresses do one layer up.
	PresentedChain func() [][]byte
	// ChainComplete says whether L4 found the chain structurally whole - asked at
	// walk time, through the same seam and for the same reason as the chain
	// itself.
	//
	// IT IS A REQUIRED PORT RATHER THAN AN OPTIONAL ONE, and that is deliberate.
	// Without it this layer cannot tell "your store is missing a CA" from "the
	// server never sent its intermediate", and those two produce the SAME red row
	// and need opposite advice - measured on the bench 2026-08-19. A layer that
	// could not tell them apart would rather say so than quietly stop offering
	// commands, because a feature that silently never appears is not noticed.
	ChainComplete func() bool
	// PresentedLeaf is L4's summary of the leaf - asked at walk time, through
	// the same seam as the two ports above and for the same reason.
	//
	// IT IS A SUMMARY RATHER THAN BYTES, and that is the opposite choice from
	// PresentedChain one field up. Verifying a path needs the certificate, so
	// that port carries DER. Naming the signer needs an issuer and a
	// fingerprint, both of which the adapter has already rendered for the report
	// - and rendering them a second time here would be a second place turning
	// bytes into a distinguished name, which is exactly how a complete chain
	// starts looking broken. It is nil when no handshake completed.
	PresentedLeaf func() *report.Certificate
	// Plaintext says the target was given as http://, so no certificate was
	// ever going to arrive - ADR100. The entry point hands L4 the same answer,
	// worked out once.
	Plaintext bool
	// Probes are the runtime families to ask, keyed by descriptor id.
	Probes map[string]Probe
	// Machine is what a remediation command needs to know about where it will be
	// run - handed in, never read here.
	Machine Machine
	// Now is the clock, and it is a port for the same reason it is one in every
	// other layer: a budget that read the real clock would behave differently
	// under test than in production, which is the one place a wrong measurement
	// is invisible.
	Now func() time.Time
	// PerProbe caps ONE probe - R-5.
	//
	// WITHOUT IT THIS LAYER ACCUSED THE MACHINE OF ITS OWN ARITHMETIC. A probe
	// runs somebody else's process, six keytool calls measured at 3.4 s on the
	// owner's machine, and until now they were handed the run's context and
	// nothing else. When that context expired every store came back unassessed
	// and the verdict said access_denied - "certdoctor was not allowed to read
	// this" - about stores nobody had failed to read. Zero means no cap of its
	// own, and the share of the layer's remaining time still applies.
	PerProbe time.Duration
}

// Result is what this layer establishes.
type Result struct {
	Status   status.Status
	Reason   status.Reason
	Detail   string
	Findings []report.Finding
}

// Sentences for the cases where the layer establishes nothing.
const (
	noChain  = "no way to learn what the server presented was supplied, so no store could be asked about anything"
	noWhole  = "no way to learn whether the presented chain was complete was supplied, so a store failing could not be told from a server failing"
	noLeaf   = "no way to learn what the server's leaf was supplied, so who signed it could not be named"
	noOS     = "no platform was supplied, so a command this machine could run could not be written"
	noProbes = "no probes were supplied, so nothing on this machine was asked"
	noClock  = "no clock was supplied, so no probe could be given a share of the time this layer has left"
	nothing  = "the server presented no certificate, so there was nothing for any store to judge"
	noneHere = "no runtime this program knows how to ask was found on this machine"
	// plaintextTarget is its own sentence because "the server presented no
	// certificate" would say a server was asked, and on an http:// target none
	// was.
	plaintextTarget = "the target does not use TLS, so there is no certificate for any store to judge"
)

// Ask walks every declared probe and reports what each store made of the chain.
//
// SEQUENTIALLY, AND THAT IS A DECISION RATHER THAN AN OVERSIGHT. ADR15 point 3
// anticipated a branch per probe here, and it may still arrive - but docs/23
// forbids optimising before measuring, and a fan-out would need a fourth entry
// on the concurrency allowlists to buy a saving nobody has measured yet. When a
// measurement shows the probes do not fit the budget, the shared fan-out in
// internal/core/fanout is what they will use - never a second copy of it.
func Ask(ctx context.Context, in Input) Result {
	if broken := in.breach(); broken != "" {
		return Result{Status: status.Unknown, Reason: status.ReasonProbeError, Detail: broken}
	}
	if in.Plaintext {
		// No probe is asked. There is no chain, and a store asked about nothing
		// has nothing to say - ADR100.
		return Result{Status: status.Unknown, Reason: status.ReasonNothingToCheck, Detail: plaintextTarget}
	}

	chain := in.PresentedChain()
	if len(chain) == 0 {
		// L4 established nothing, so there is nothing here to judge. This is not
		// a failure of any store and must not be reported as one.
		return Result{Status: status.Unknown, Reason: status.ReasonNothingToCheck, Detail: nothing}
	}
	// Asked ONCE rather than per store: it is a fact about what the server sent,
	// so a value that could differ between two rows of one report would mean the
	// port was answering something else.
	whole := in.ChainComplete()

	rows, timedOut := in.walkProbes(ctx, chain)
	// A ROW THAT DEFERS GETS ITS ANSWER BEFORE ANYTHING IS COUNTED - ADR108 part
	// 4. Counting first would report curl on Schannel as unassessed on every run
	// on Windows, which is the warning this part exists to remove.
	leaf := in.PresentedLeaf()
	rows = settleDeferred(rows, leaf != nil && leaf.SelfSigned)
	counted := tallyOf(rows, timedOut)

	// THE MATRIX IS WALKED BEFORE ANY COMMAND IS WRITTEN, AND THAT ORDER IS THE
	// WHOLE OF ADR55. Whether a refusing store can be repaired depends on a fact
	// no single row knows: whether ANY store on this machine closed this very
	// chain. If one did, an anchor that closes it exists, so the store that
	// refused can be given it - even when the server sent an incomplete chain.
	// Measured on the bench 2026-08-19: a middlebox signing straight from its
	// own root produces exactly that state, and the old single-pass gate refused
	// a command for the one case where adding the certificate is the repair.
	//
	// It cannot be done inside the walk, because the answer is not known until
	// the last probe has been asked.
	closed := counted.trusting > 0

	findings := in.findingsFrom(rows, whole, closed)

	return verdict(findings, counted.asked, counted.trusting, counted.unassessed, counted.timedOut)
}

// tally is what the walk counted, kept together because the verdict needs all
// four of them and a walk returning four bare integers is four chances to hand
// them over in the wrong order.
type tally struct {
	asked      int
	trusting   int
	unassessed int
	timedOut   int
}

// tallyOf counts the rows the verdict is built from. Every row is one store
// asked, a probe that could not run included.
func tallyOf(rows []row, timedOut int) tally {
	counted := tally{asked: len(rows), timedOut: timedOut}
	for _, r := range rows {
		switch {
		case r.store.TrustsPresentedChain == nil:
			counted.unassessed++
		case *r.store.TrustsPresentedChain:
			counted.trusting++
		}
	}
	return counted
}

// walkProbes asks every declared probe that this machine has, and collects a row
// for each store, along with how many probes ran out of time.
//
// IT DECIDES NOTHING. No status, no command, no sentence about a signer - those
// need facts about the WHOLE matrix, which do not exist until this returns. The
// split is OBS85's named moment taken before anything new was added to this
// layer rather than after: breaking a function up once the mutation entries are
// green turns evidence just collected into evidence to collect again.
func (in Input) walkProbes(ctx context.Context, chain [][]byte) ([]row, int) {
	var rows []row
	timedOut := 0

	// HOW MANY PROBES ARE LEFT TO ASK, COUNTED BEFORE THE FIRST ONE RUNS - R-5.
	// The share arithmetic needs a divisor, and one taken inside the loop would
	// shrink as the loop advanced, so the last probe would be handed everything
	// that was left - which is the starvation ADR36 removed from L1.
	left := 0
	for _, descriptor := range descriptors {
		if _, present := in.Probes[descriptor.ID]; present {
			left++
		}
	}

	for _, descriptor := range descriptors {
		probe, present := in.Probes[descriptor.ID]
		if !present {
			continue
		}
		probeCtx, done, remaining := in.share(ctx, left)
		left--
		if remaining == 0 {
			// NOT A REFUSAL AND NOT AN EMPTY STORE. Nothing was asked, so nothing
			// was denied - this row is about our budget.
			rows = append(rows, unaskable(descriptor, errNoTimeLeft))
			timedOut++
			continue
		}
		stores, err := askProbe(probeCtx, probe, chain)
		// THE BUDGET IS ASKED ABOUT ITSELF, RATHER THAN READ OFF A PROBE'S
		// ERROR. Every probe in this tree turns a failure into a row and
		// returns no error at all - java/probe.go, curl/probe.go, git/probe.go
		// all end in "return stores, nil" - so the line below it was the only
		// witness, and it never fired outside a test. That is why R-5's counter
		// could grow one way only: through the remaining == 0 branch above, for
		// a probe that never started.
		//
		// IT IS READ BEFORE done(), NOT AFTER. Cancelling replaces the
		// deadline's error with context.Canceled, which is a different fact -
		// somebody stopped this run - and counting it as a timeout would blame
		// the clock for a person pressing Ctrl-C.
		//
		// A probe that finished everything and only then ran out of time still
		// increments this, and that is harmless: the verdict reads the counter
		// only when NOTHING could be assessed.
		expired := errors.Is(probeCtx.Err(), context.DeadlineExceeded)
		if done != nil {
			done()
		}
		if expired || errors.Is(err, context.DeadlineExceeded) {
			timedOut++
		}
		if err != nil {
			// ONE PROBE FAILING DOES NOT SINK THE LAYER. It becomes a row saying
			// so, because "we could not ask git" is a different fact from "git
			// does not trust this" and inviolable rule 15 wants the difference
			// visible rather than averaged away.
			rows = append(rows, unaskable(descriptor, err))
			continue
		}
		for _, store := range stores {
			rows = append(rows, row{store: store})
		}
	}
	return rows, timedOut
}

// findingsFrom turns the collected rows into what the report carries, once the
// two facts no single row knows - whether the chain was whole, and whether any
// store on this machine closed it - have been worked out.
func (in Input) findingsFrom(rows []row, whole, closed bool) []report.Finding {
	findings := make([]report.Finding, 0, len(rows)+1)
	// THE SUMMARY LINE COMES FIRST because it is what a reader needs before the
	// rows mean anything: who signed this, and how much of this machine has
	// heard of them.
	if named := authorityOf(in.PresentedLeaf(), storesOf(rows)); named != nil {
		findings = append(findings, *named)
	}
	for _, r := range rows {
		if r.store.TrustsPresentedChain != nil && !*r.store.TrustsPresentedChain {
			// THE COMMAND IS ATTACHED HERE AND NOWHERE ELSE, so that a row
			// carrying one has passed through the branch that says it was
			// refused. A probe filling this in itself would be a probe producing
			// a verdict, which ADR7 keeps out of the adapters.
			var unwritable string
			r.store.Fix, unwritable = fixFor(r.store, whole, closed, in.Machine)
			// A REFUSED COMMAND SAYS SO ON THE ROW, AND AN ORDINARY nil DOES NOT.
			// "No command" is the usual answer and needs no sentence - ADR51 -
			// but "there is a command for this and we will not write it" is a
			// different fact, and leaving it silent would be rule 1 broken in the
			// one place this program tells somebody to do something. ADR59.
			if unwritable != "" {
				r.summary = summaryOf(r.store) + " - " + unwritable
			}
		}
		findings = append(findings, r.finding())
	}
	return findings
}

// errNoTimeLeft is what a probe that never ran carries into its row.
//
// It is a value rather than a sentence built at the call site, because the row
// and the verdict have to agree about which of the two things happened, and a
// second spelling of it is a second place for one fact.
var errNoTimeLeft = errors.New("this layer had no time left to ask, so this store was never read")

// share is one probe's slice of whatever the layer has left - R-5, and the
// arithmetic is ADR36's.
//
// IT IS WRITTEN HERE RATHER THAN SHARED WITH L1, AND THE REASON IS MEASURED
// RATHER THAN AESTHETIC. The two are the same shape and carry different
// vocabulary - queries against probes - and the mutation register anchors on an
// exact string inside one named file, so neither copy disarms the other's entry.
// That is the harm OBS50 measured, and it does not arise here. A THIRD copy
// would be the moment to extract it.
//
// A layer with no deadline at all falls back to the probe's own cap, and to no
// cap when there is not one - the same two answers, and the same OBS62 trap, as
// every other budget in this program.
func (in Input) share(ctx context.Context, probesLeft int) (context.Context, context.CancelFunc, time.Duration) {
	deadline, set := ctx.Deadline()
	if !set {
		if in.PerProbe > 0 {
			limited, cancel := context.WithTimeout(ctx, in.PerProbe)
			return limited, cancel, in.PerProbe
		}
		return ctx, nil, unlimited
	}
	remaining := deadline.Sub(in.Now())
	if remaining <= 0 {
		return ctx, nil, 0
	}
	if probesLeft > 1 {
		remaining /= time.Duration(probesLeft)
	}
	if in.PerProbe > 0 && in.PerProbe < remaining {
		remaining = in.PerProbe
	}
	limited, cancel := context.WithTimeout(ctx, remaining)
	return limited, cancel, remaining
}

// unlimited is the answer for a probe nothing caps at all. It is negative rather
// than zero because zero means "no time left, do not ask" - OBS62, paid for once
// already in L1.
const unlimited = -1

// row is one line of the matrix as first collected, before anything that needs
// the whole matrix has been worked out.
type row struct {
	store report.TrustStore
	// summary replaces the ordinary wording in the two cases where the ordinary
	// wording would leave something out: a probe that could not run at all, whose
	// row describes the asking rather than the store, and a store whose command
	// this program refused to write - ADR59.
	summary string
}

// finding wraps one row in the envelope every surface can render.
func (r row) finding() report.Finding {
	summary := r.summary
	if summary == "" {
		summary = summaryOf(r.store)
	}
	store := r.store
	return report.Finding{
		Kind:       report.FindingTrustStore,
		Summary:    summary,
		Source:     report.SourceDetected,
		TrustStore: &store,
	}
}

// storesOf hands the collected stores to the one place allowed to judge them.
func storesOf(rows []row) []report.TrustStore {
	stores := make([]report.TrustStore, 0, len(rows))
	for _, r := range rows {
		stores = append(stores, r.store)
	}
	return stores
}

// summaryOf is the one line a surface prints without knowing the kind.
func summaryOf(store report.TrustStore) string {
	switch {
	case store.TrustsPresentedChain == nil:
		return fmt.Sprintf("%s %s could not be assessed: %s", store.Runtime, store.Instance, store.NotAssessed)
	case *store.TrustsPresentedChain:
		return fmt.Sprintf("%s %s trusts the presented chain (%d anchors)", store.Runtime, store.Instance, store.TrustAnchorCount)
	default:
		return fmt.Sprintf("%s %s does NOT trust the presented chain (%d anchors)", store.Runtime, store.Instance, store.TrustAnchorCount)
	}
}

// unaskable is the row for a probe that could not run at all.
// askProbe runs one probe and turns a panic into an ordinary error, so that a
// probe falling over becomes a row like any other failure.
//
// WHY THIS LAYER NEEDS IT AND THE OTHERS DID NOT NOTICE. L3 and L4 reach code
// this program does not own too, but they reach it under fanout.Over, whose
// goroutines catch their own panics because nothing else can - ADR67. This layer
// asks its probes in a plain sequential loop, so before this existed a panic
// went straight past it to the recover in main: the exit code stayed inside the
// table and the whole report went with it, after every layer had finished and
// every store had been read. That is the inversion the orchestrator forbids in
// so many words - a probe that cannot answer degrades, and it degrades ALONE.
//
// AND THE PROBES HERE ARE THE ONES MOST EXPOSED. They pull PEM out of keytool's
// output, INI out of a gitconfig somebody else wrote, and hand certificates
// from the wire to crypto/x509. None of that is ours and none of it promised
// not to panic.
//
// IT IS A SECOND recover IN THIS TREE AND THAT IS DELIBERATE RATHER THAN
// OVERLOOKED. Routing this through fanout.Over would consume the existing one
// and costs no exemption - measured, internal/core/tcp/fanout.go and
// internal/core/handshake/fanout.go both call it and neither is on any
// concurrency list. It was refused for what it would invite: this layer asks
// its probes ONE AT A TIME because they share one budget by division, and a
// fan-out primitive sitting here is an invitation to raise the one to N without
// going back through that arithmetic. The two recovers also answer different
// questions - a goroutine's panic cannot reach its caller at all, this one can
// and is deliberately turned into a row - and the mutation register keeps them
// apart by file, so neither entry blunts the other.
//
// The named returns are what let the deferred function replace both: a probe
// that fell over has no stores, and handing back whatever it managed to append
// before falling would be reporting a half-read machine as a whole one.
func askProbe(ctx context.Context, probe Probe, chain [][]byte) (stores []report.TrustStore, err error) {
	defer func() {
		if cause := recover(); cause != nil {
			stores, err = nil, fmt.Errorf("it fell over inside this program: %v", cause)
		}
	}()
	return probe(ctx, chain)
}

func unaskable(descriptor Descriptor, err error) row {
	return row{
		store: report.TrustStore{
			Runtime:     descriptor.Runtime,
			Instance:    descriptor.ID,
			StoreForm:   report.StoreSystem,
			NotAssessed: fmt.Sprintf("the probe could not run: %v", err),
			SelectedBy:  []string{},
		},
		summary: fmt.Sprintf("%s could not be asked: %v", descriptor.Runtime, err),
	}
}

// verdict turns the rows into one status.
//
// BOTH COUNTS TRAVEL WHEN BOTH EXIST - D10, decided for the run verdict and
// binding here for the same reason: a sentence naming only the failures reads as
// though everything else was fine, and one naming only the unknowns reads as
// though nothing was established.
func verdict(findings []report.Finding, asked, trusting, unassessed, timedOut int) Result {
	if asked == 0 {
		// docs/20 rule 1: a runtime that is not installed sits outside the
		// matrix. Finding none of them is not a failure of this machine.
		return Result{Status: status.Unknown, Reason: status.ReasonNothingToCheck, Detail: noneHere}
	}

	distrusting := asked - trusting - unassessed
	switch {
	case distrusting > 0 && unassessed > 0:
		return Result{Status: status.Fail, Detail: fmt.Sprintf(
			"%d of %d store(s) do not trust the presented chain, and %d could not be assessed",
			distrusting, asked, unassessed), Findings: findings}
	case distrusting > 0:
		return Result{Status: status.Fail, Detail: fmt.Sprintf(
			"%d of %d store(s) do not trust the presented chain", distrusting, asked), Findings: findings}
	case unassessed == asked:
		// WHICH OF THE TWO HAPPENED, RATHER THAN ONE ANSWER FOR BOTH - R-5.
		// A layer whose budget ran out was not refused anything, and sending
		// somebody to look at file permissions for our own arithmetic is the
		// shape ADR58 removed from L1.
		//
		// AND THE OTHER OF THE TWO IS NO LONGER access_denied - ADR80, closing
		// OBS90. That word says "certdoctor was not allowed to read this", and
		// this branch said it on a machine where nobody had refused this program
		// anything: measured 2026-09-03 in an alpine container with git and no
		// /etc/gitconfig, where the one row said, correctly, that git names no
		// backend so its bundle is compiled in. The row was true and the layer
		// above it turned that into an accusation about permissions.
		//
		// undetermined is about the ANSWER; the other seven are about the
		// ASKING. Nothing here produces access_denied any more, and the reason
		// that is not a bug is written where the word is declared.
		reason := status.ReasonUndetermined
		if timedOut > 0 {
			reason = status.ReasonTimeout
		}
		return Result{Status: status.Unknown, Reason: reason, Detail: fmt.Sprintf(
			"none of the %d store(s) found could be assessed", asked), Findings: findings}
	case unassessed > 0:
		return Result{Status: status.Warn, Detail: fmt.Sprintf(
			"%d of %d store(s) trust the presented chain, and %d could not be assessed",
			trusting, asked, unassessed), Findings: findings}
	default:
		return Result{Status: status.Pass, Detail: fmt.Sprintf(
			"all %d store(s) found trust the presented chain", asked), Findings: findings}
	}
}

func (in Input) breach() string {
	switch {
	case in.PresentedChain == nil:
		return noChain
	case in.ChainComplete == nil:
		return noWhole
	case in.PresentedLeaf == nil:
		return noLeaf
	case in.Machine.OS == "":
		return noOS
	case len(in.Probes) == 0:
		return noProbes
	case in.Now == nil:
		return noClock
	}
	return ""
}
