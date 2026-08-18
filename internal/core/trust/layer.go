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
	// Probes are the runtime families to ask, keyed by descriptor id.
	Probes map[string]Probe
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

	var findings []report.Finding
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
			findings = append(findings, unaskable(descriptor, err))
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
			findings = append(findings, finding(store))
		}
	}

	return verdict(findings, asked, trusting, unassessed)
}

// finding wraps one store in the envelope every surface can render.
func finding(store report.TrustStore) report.Finding {
	return report.Finding{
		Kind:       report.FindingTrustStore,
		Summary:    summaryOf(store),
		Source:     report.SourceDetected,
		TrustStore: &store,
	}
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
func unaskable(descriptor Descriptor, err error) report.Finding {
	store := report.TrustStore{
		Runtime:     descriptor.Runtime,
		Instance:    descriptor.ID,
		StoreForm:   report.StoreSystem,
		NotAssessed: fmt.Sprintf("the probe could not run: %v", err),
		SelectedBy:  []string{},
	}
	return report.Finding{
		Kind:       report.FindingTrustStore,
		Summary:    fmt.Sprintf("%s could not be asked: %v", descriptor.Runtime, err),
		Source:     report.SourceDetected,
		TrustStore: &store,
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
	case len(in.Probes) == 0:
		return noProbes
	}
	return ""
}
