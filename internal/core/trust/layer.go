package trust

import (
	"context"
	"fmt"

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
	// Probes are the runtime families to ask, keyed by descriptor id.
	Probes map[string]Probe
	// Machine is what a remediation command needs to know about where it will be
	// run - handed in, never read here.
	Machine Machine
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
	nothing  = "the server presented no certificate, so there was nothing for any store to judge"
	noneHere = "no runtime this program knows how to ask was found on this machine"
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

	var rows []row
	var asked, trusting, unassessed int

	for _, descriptor := range descriptors {
		probe, present := in.Probes[descriptor.ID]
		if !present {
			continue
		}
		stores, err := probe(ctx, chain)
		if err != nil {
			// ONE PROBE FAILING DOES NOT SINK THE LAYER. It becomes a row saying
			// so, because "we could not ask git" is a different fact from "git
			// does not trust this" and inviolable rule 15 wants the difference
			// visible rather than averaged away.
			rows = append(rows, unaskable(descriptor, err))
			asked++
			unassessed++
			continue
		}
		for _, store := range stores {
			asked++
			switch {
			case store.TrustsPresentedChain == nil:
				unassessed++
			case *store.TrustsPresentedChain:
				trusting++
			}
			rows = append(rows, row{store: store})
		}
	}

	// THE MATRIX IS WALKED BEFORE ANY COMMAND IS WRITTEN, AND THAT ORDER IS THE
	// WHOLE OF ADR55. Whether a refusing store can be repaired depends on a fact
	// no single row knows: whether ANY store on this machine closed this very
	// chain. If one did, an anchor that closes it exists, so the store that
	// refused can be given it - even when the server sent an incomplete chain.
	// Measured on the bench 2026-08-19: a middlebox signing straight from its
	// own root produces exactly that state, and the old single-pass gate refused
	// a command for the one case where adding the certificate is the repair.
	//
	// It cannot be done in the loop above, because the answer is not known until
	// the last probe has been asked.
	closed := trusting > 0

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
			r.store.Fix = fixFor(r.store, whole, closed, in.Machine)
		}
		findings = append(findings, r.finding())
	}

	return verdict(findings, asked, trusting, unassessed)
}

// row is one line of the matrix as first collected, before anything that needs
// the whole matrix has been worked out.
type row struct {
	store report.TrustStore
	// summary replaces the ordinary wording for a probe that could not run at
	// all, whose row describes the asking rather than the store.
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
func verdict(findings []report.Finding, asked, trusting, unassessed int) Result {
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
		return Result{Status: status.Unknown, Reason: status.ReasonAccessDenied, Detail: fmt.Sprintf(
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
	}
	return ""
}
