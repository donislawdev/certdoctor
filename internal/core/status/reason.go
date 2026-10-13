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
	//
	// NOTHING IN THIS PROGRAM PRODUCES IT TODAY, AND THAT IS WRITTEN HERE SO IT
	// IS NOT TIDIED AWAY - ADR80, OBS98. Its one producer was the L5 verdict
	// branch that said it about stores nobody had refused, and that branch now
	// says undetermined. The word stays because the case is real and this
	// program simply cannot recognise it yet: a probe would have to classify its
	// own failure - errors.Is(err, fs.ErrPermission), never the message, which
	// is inviolable rule 19 - and today no probe returns a failure at all.
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
	// ReasonUndetermined - the layer asked, and what came back does not settle
	// the question it was asked.
	//
	// THE EIGHTH REASON, AND IT EXISTS BECAUSE THE OTHER SEVEN WOULD ALL HAVE
	// BEEN A LIE - ADR80, closing OBS90. Measured 2026-09-03 in an alpine
	// container with git installed and no /etc/gitconfig: every store L5 found
	// came back unassessed, so the layer said access_denied - "certdoctor was
	// not allowed to read this" - on a machine where nobody had refused this
	// program anything. It had not timed out, nothing was unreadable, no output
	// was unrecognised and nothing here broke; the honest sentence was that git
	// names no backend, so which bundle it reads is compiled into it.
	//
	// IT IS ABOUT THE ANSWER, NOT ABOUT THE ASKING, and that is what separates
	// it from the seven above. Every one of those says the question could not be
	// PUT - the clock, the permissions, the wire, our own code. This one says it
	// was put and answered, and the answer decides nothing.
	//
	// It is deliberately general rather than about trust stores. The same shape
	// is waiting wherever this program reads somebody's configuration and finds
	// it silent, and a reason named after L5 would be reinvented at the next
	// layer that meets it.
	//
	// IT IS THE SAME WORD AS report.NoteUndetermined ON PURPOSE, and the
	// argument is ADR39's, made there about transport_error. That note kind says
	// "a field we could not establish, left empty rather than guessed", which is
	// this same fact about a smaller thing. docs/18 asks for one name per
	// concept, and a reader meeting the word twice is meeting one concept in two
	// registers - two fields, never two vocabularies. Two different words for it
	// would have been the thing to explain.
	ReasonUndetermined Reason = "undetermined"
	// ReasonLimitExceeded - a ceiling THIS PROGRAM sets stopped the work before
	// it produced an answer.
	//
	// THE NINTH REASON, NAMED BY ADR80 AND DECLARED HERE WITH ITS FIRST
	// PRODUCER. That record named it and deliberately left it out of this file:
	// a value in a public contract that nothing can produce is a promise nobody
	// keeps, which is the charge this register lays against access_denied
	// (OBS98). L2 fetching and running an automatic configuration script is what
	// produces it, so it arrives with that slice and not before.
	//
	// THE BOUNDARY WITH timeout IS WRITTEN DOWN AND BINDING - ADR80 part 3. TIME
	// STAYS WITH timeout; every OTHER ceiling of ours comes here. A PAC file
	// stopped for allocating past the sandbox's memory ceiling did not run out
	// of time, and one refused for being larger than this run accepts was never
	// started at all - reporting either as a timeout would send somebody to
	// look at a clock.
	//
	// IT SAYS THE LIMIT IS OURS, AND THAT IS THE WHOLE OF IT. The sandbox's
	// memory ceiling is a ceiling on what gets NOTICED rather than on what gets
	// allocated - the overshoot was measured at 1.75x and 1.88x on two runs of
	// one file - so a sentence built on this reason may say that this run
	// stopped the file and may not say that the file is a bomb.
	ReasonLimitExceeded Reason = "limit_exceeded"
	// ReasonCredentialsRequired - the proxy this URL goes through will not pass a
	// request until it is told who is asking, and this run has nothing to tell it.
	//
	// THE TENTH REASON, NAMED BY ADR80 AND DECLARED HERE WITH ITS FIRST PRODUCER,
	// which is the rule the ninth arrived under and the charge this register lays
	// against access_denied (OBS98). L2 asking a proxy is what produces it, so it
	// arrives with that slice and not before.
	//
	// IT IS UNKNOWN AND NOT FAIL, AND THAT IS INVIOLABLE RULE 15 READ CAREFULLY -
	// testbed/expected/proxy-auth.txt fixed the word before this code existed. A
	// proxy asking who you are is neither a broken proxy nor a broken machine; it
	// is a machine that has not been told. This program knows the proxy applies
	// and knows it will challenge. It does NOT know whether credentials exist
	// somewhere it cannot see - a keyring, a domain login, a config file it does
	// not read - so it must not pronounce on the outcome.
	//
	// ONLY A 407 PRODUCES IT, AND THAT IS A MEASUREMENT RATHER THAN CAUTION -
	// probe S15, 2026-09-07, against the bench's squid. A CONNECT to a port that
	// is not in SSL_ports comes back 403 from a proxy that wants no credentials
	// at all, and a CONNECT the proxy ALLOWED came back 503 when the origin was
	// out of reach. From the client's side all three look like "no tunnel" and
	// they mean three different things, so everything that is not a 407 is
	// undetermined instead. Answering otherwise would accuse a working proxy and
	// a working machine, which is inviolable rule 21 met from the proxy's side.
	ReasonCredentialsRequired Reason = "credentials_required"
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
	ReasonUndetermined,
	ReasonLimitExceeded,
	ReasonCredentialsRequired,
}

// reasonDescriptions carries an English one-liner for every declared reason,
// and its keys are the list Valid answers from - so it is not dead code even
// though nothing reads the sentences.
//
// NO SURFACE SHOWS THESE TODAY - OBS151, measured 2026-09-23. Description has
// no caller outside the tests, and every renderer prints the reason token
// alone. This comment used to say the text was shown to the user, which was a
// promise in prose that no code kept. Showing them changes the text on four
// surfaces and waits in the backlog, and some no longer fit every case they
// are attached to: nothing_to_check also stands for a target without TLS
// (ADR100) and for L4 after L3 reached nothing. They have to be worded again
// before anybody renders them. Kept here rather than at a call site, so that
// when they are shown, one reason is worded one way on every surface.
var reasonDescriptions = map[Reason]string{
	ReasonUnparseable:    "the probe produced output certdoctor does not recognize",
	ReasonTimeout:        "the probe did not finish within its time limit",
	ReasonAccessDenied:   "certdoctor was not allowed to read this",
	ReasonProbeError:     "the probe itself failed to run",
	ReasonSkippedBudget:  "skipped because the run exceeded its overall time budget",
	ReasonNothingToCheck: "this layer ran and there was nothing on this machine for it to look at",
	ReasonTransportError: "every attempt to ask failed on the wire rather than inside certdoctor",
	ReasonUndetermined:   "this layer asked, and what came back does not settle the question",
	ReasonLimitExceeded:  "a ceiling certdoctor sets stopped this before it produced an answer",

	ReasonCredentialsRequired: "the proxy this URL goes through demands credentials, and this run has none to offer",
}

// Valid reports whether r is one of the declared reasons.
func (r Reason) Valid() bool {
	_, ok := reasonDescriptions[r]
	return ok
}

// Description returns the English one-liner for r, or the empty string for an
// unknown reason. No renderer calls it yet (OBS151). One that does should
// render the empty string as nothing rather than as a lie about what happened.
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
