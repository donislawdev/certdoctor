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
// Silence is forbidden: a status that says something is wrong, or that we could
// not tell, is useless to the reader without the why.
func (s Status) RequiresReason() bool {
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
