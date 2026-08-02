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
)

// AllReasons lists every reason exactly once.
var AllReasons = []Reason{
	ReasonUnparseable,
	ReasonTimeout,
	ReasonAccessDenied,
	ReasonProbeError,
	ReasonSkippedBudget,
}

// reasonDescriptions carries the English one-liner shown to the user. Keeping it
// here rather than at the call site is what stops the same reason from being
// worded three different ways in three renderers.
var reasonDescriptions = map[Reason]string{
	ReasonUnparseable:   "the probe produced output certdoctor does not recognize",
	ReasonTimeout:       "the probe did not finish within its time limit",
	ReasonAccessDenied:  "certdoctor was not allowed to read this",
	ReasonProbeError:    "the probe itself failed to run",
	ReasonSkippedBudget: "skipped because the run exceeded its overall time budget",
}

// Valid reports whether r is one of the five.
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
