package status

// Reason says why a result is not a plain Pass. It is a field, never a status:
// four statuses stay four regardless of how many ways there are to fail to
// assess something.
//
// The list is closed for the same reason the status list is. Every value here
// appears in --json, so it is a public contract.
type Reason string

const (
	// ReasonUnparseable - the probe ran and produced output we do not recognise.
	// This is the reason the product exists to report honestly rather than guess.
	ReasonUnparseable Reason = "unrecognized_output"
	// ReasonTimeout - the probe did not finish inside its time limit.
	ReasonTimeout Reason = "timeout"
	// ReasonAccessDenied - we were not allowed to read a store or a directory.
	// A refusal is an answer about our permissions, not an answer about trust.
	ReasonAccessDenied Reason = "access_denied"
	// ReasonProbeError - the probe itself broke, distinct from the target failing.
	ReasonProbeError Reason = "probe_error"
	// ReasonSkippedBudget - the run exceeded its overall budget and deliberately
	// dropped this probe. Without this reason a run that ran out of time would be
	// indistinguishable from a run that found nothing.
	ReasonSkippedBudget Reason = "skipped_budget"
	// ReasonNothingToCheck - the layer ran correctly and there was nothing on
	// this machine for it to look at.
	//
	// THE SIXTH REASON, AND IT EXISTS BECAUSE THE OTHER FIVE WOULD ALL HAVE BEEN
	// A LIE - ADR33. L1 on a machine that lists no DNS resolver has not timed
	// out, has not been refused access, has not produced output we cannot read
	// and has not broken: it worked, and there was nobody to ask. Reporting that
	// as probe_error would blame this program for a fact about somebody's
	// machine, which is the exact inversion inviolable rule 15 exists to stop.
	//
	// It is deliberately general rather than about resolvers. The same shape is
	// waiting at L2 with no proxy configured and at L5 with no runtime
	// installed, and a reason named after L1 would be reinvented twice.
	ReasonNothingToCheck Reason = "nothing_to_check"
	// ReasonTransportError - every attempt to ask failed on the wire, and none of
	// them failed inside this program.
	//
	// THE SEVENTH REASON, AND IT EXISTS FOR THE SAME MEASURED CAUSE AS THE SIXTH
	// - ADR39. A run where every resolver was unreachable had nowhere honest to
	// land: it did not time out, it was not refused access, nothing was
	// unreadable and nothing here broke. It fell to probe_error, which says the
	// probe itself failed, so the reader was sent to look at certdoctor while the
	// answer was a cable, a firewall or a network that is down.
	//
	// IT IS THE SAME WORD AS THE ROW-LEVEL REASON ON PURPOSE. A reader who sees
	// transport_error on four rows and something different on the layer above
	// them would reasonably assume the two describe different things.
	ReasonTransportError Reason = "transport_error"
)

// AllReasons lists every reason exactly once.
var AllReasons = []Reason{
	ReasonUnparseable,
	ReasonTimeout,
	ReasonAccessDenied,
	ReasonProbeError,
	ReasonSkippedBudget,
	ReasonNothingToCheck,
	ReasonTransportError,
}

// reasonDescriptions carries the English one-liner shown to the user. Keeping it
// here rather than at the call site is what stops the same reason from being
// worded three different ways in three renderers.
var reasonDescriptions = map[Reason]string{
	ReasonUnparseable:    "the probe produced output certdoctor does not recognize",
	ReasonTimeout:        "the probe did not finish within its time limit",
	ReasonAccessDenied:   "certdoctor was not allowed to read this",
	ReasonProbeError:     "the probe itself failed to run",
	ReasonSkippedBudget:  "skipped because the run exceeded its overall time budget",
	ReasonNothingToCheck: "this layer ran and there was nothing on this machine for it to look at",
	ReasonTransportError: "every attempt to ask failed on the wire rather than inside certdoctor",
}

// Valid reports whether r is one of the declared reasons.
func (r Reason) Valid() bool {
	_, ok := reasonDescriptions[r]
	return ok
}

// Description returns the user-facing English text for r, or the empty string
// for an unknown reason. Callers render the empty string as nothing rather than
// as a lie about what happened.
func (r Reason) Description() string { return reasonDescriptions[r] }

// String makes Reason printable without a conversion at every call site.
func (r Reason) String() string { return string(r) }

// ReasonForNothingAttempted names why a layer got not one attempt off this
// machine, given how many it dropped for its own budget.
//
// IT LIVES HERE, IN THE VOCABULARY, BECAUSE THREE LAYERS ASK IT AND THE ANSWER
// IS ABOUT US - ADR58. L1, L3 and L4 each have their own words for what
// happened to one attempt: a NoAnswer, a ConnectOutcome, an error sentinel.
// What they share is the question, and a copy of the answer in each of them
// would be one rule in three places, which is the measured shape of OBS50 -
// three mutation entries turning into SKIP while the summary differs from a
// clean one by a single number.
//
// THE RANKING IS BUDGET FIRST, AND THAT IS A DECISION RATHER THAN AN ORDERING.
// Both can be true in one walk. A budget is something the person running this
// can change, and it is the reason the later attempts never happened at all -
// so naming it points at the thing that can be turned, while naming our own
// refusal points at us for a run that also ran out of time.
//
// WHAT LANDS ON probe_error IS OURS AND ONLY OURS, exactly as it is in the
// resolving layer's own chooser: what is left once the budget is ruled out is a
// refusal by the allowed set, which is this program applying a rule to itself.
//
// IT TAKES ONE COUNT RATHER THAN TWO, AND THAT IS DELIBERATE. A second
// parameter for the refusals would read as though it decided something, and it
// would not - everything that is not the budget arrives at the same word.
// Whether nothing left this machine at all is the CALLER's question, asked over
// the caller's own vocabulary, and this function is only the name for it.
func ReasonForNothingAttempted(skippedForBudget int) Reason {
	if skippedForBudget > 0 {
		return ReasonSkippedBudget
	}
	return ReasonProbeError
}
