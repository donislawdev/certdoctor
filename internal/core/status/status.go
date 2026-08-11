// Package status defines certdoctor's status vocabulary: the exactly four
// values a layer or a probe may report.
//
// The list is closed and is a public contract. These strings appear in --json
// and they decide the process exit code, so adding a fifth value is a breaking
// change and the owner's decision, never a convenience.
//
// Why closure matters more here than in a typical project: the product promises
// that a probe which did not understand what it saw reports Unknown rather than
// Pass. That promise holds only while Unknown is the single escape hatch. An
// open list invites a fifth value such as "SKIPPED", which looks harmless and
// reads like success.
//
// Appearance - glyph, colour, ASCII fallback - deliberately lives outside this
// package. The core does not know that a terminal exists.
package status

import "fmt"

// Status is one of exactly four values. Its zero value is intentionally invalid
// so that a forgotten assignment fails a check instead of defaulting to Pass.
type Status string

const (
	// Fail means the probe ran, its output was understood, and trust does not work.
	Fail Status = "FAIL"
	// Warn means it works, but something is off and worth knowing about.
	Warn Status = "WARN"
	// Unknown means we could not assess it. It always carries a Reason.
	Unknown Status = "UNKNOWN"
	// Pass means the probe ran, its output was understood, and trust works.
	Pass Status = "PASS"
)

// All lists every status exactly once, most severe first. Anything that needs
// to enumerate statuses reads this slice rather than repeating the list, so a
// new value cannot be added in one place and forgotten in another.
var All = []Status{Fail, Warn, Unknown, Pass}

// severity orders statuses for reporting. Lower is more severe, so sorting
// ascending puts Fail at the top of a report deterministically, independent of
// map iteration order.
var severity = map[Status]int{
	Fail:    1,
	Warn:    2,
	Unknown: 3,
	Pass:    4,
}

// Severity returns the reporting rank of s. It panics on an unknown status,
// because that can only happen if a caller invented a value rather than using
// one of the constants - a defect in our own code, not bad input.
func (s Status) Severity() int {
	rank, ok := severity[s]
	if !ok {
		panic(fmt.Sprintf("status: severity requested for unknown status %q", string(s)))
	}
	return rank
}

// Valid reports whether s is one of the four. Use it on anything that crossed a
// boundary - a decoded report, a flag value - never on our own constants.
func (s Status) Valid() bool {
	_, ok := severity[s]
	return ok
}

// RequiresReason reports whether a result carrying s must also carry a reason.
//
// ONLY UNKNOWN DOES, AND THAT IS NARROWER THAN IT USED TO BE. The reason
// vocabulary answers one question - why this could NOT be assessed: a timeout,
// a refusal, output nobody could read, a budget spent. A layer that assessed
// something and found it wrong has no true value to put there, and the closed
// list is not the place to invent one.
//
// IT WAS MEASURED RATHER THAN NOTICED IN PASSING. With "anything but PASS"
// here, a layer answering WARN or FAIL broke the contract in resultOf and came
// out as UNKNOWN with probe_error - so the whole of D13's verdict half was
// unreachable in the shipped binary while the tests, which check the layer
// before the orchestrator sees it, stayed green. Running the binary against a
// name under .invalid is what showed it.
//
// WHAT REPLACES IT IS NOT NOTHING - see RequiresDetail. Every status that says
// something is wrong still has to say WHAT in words, which is the half of this
// rule a reader actually reads.
func (s Status) RequiresReason() bool {
	return s == Unknown
}

// RequiresDetail reports whether a result carrying s must also carry the
// sentence saying what happened.
//
// This is the half of the old RequiresReason that applies to every status but
// PASS: silence is forbidden. A warning or a failure with no sentence is a red
// mark on somebody's screen with nothing next to it, which is worse than no
// mark at all - the reader cannot even tell what was looked at.
func (s Status) RequiresDetail() bool {
	return s != Pass
}

// String makes Status printable without a conversion at every call site.
func (s Status) String() string { return string(s) }

// Worst returns the most severe status in the given set, or Pass for an empty
// set. It is how a layer folds its probes into one status and how the run folds
// its layers into a verdict.
func Worst(statuses ...Status) Status {
	worst := Pass
	for _, s := range statuses {
		if s.Severity() < worst.Severity() {
			worst = s
		}
	}
	return worst
}
