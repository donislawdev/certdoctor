// Package report holds the structure certdoctor produces and the pure function
// that folds it into one verdict.
//
// Nothing here knows about a terminal, about JSON or about colour. The report is
// data. The renderers decide how it looks and the entry point decides where it
// goes. That split is what lets the assessment be tested on recorded evidence
// instead of against a broken machine, which is the whole reason a probe returns
// evidence rather than a verdict.
//
// WHAT THIS PACKAGE DELIBERATELY DOES NOT CARRY, and why the absence is the
// honest choice rather than an oversight: there is no findings list, no evidence
// object and no trust matrix here yet. No layer produces any of the three today.
// Declaring them now would put empty shapes into a public contract before
// anybody knows what belongs in them, and an empty array is a claim - it says
// "this was looked at and there was nothing". The rule this package follows is
// the other one: emit exactly what exists, and announce every absence in Notes.
package report

import (
	"time"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Report is one complete run of certdoctor.
type Report struct {
	// Tool identifies the binary that produced this, so a report found in a
	// ticket six months from now can be traced to a build.
	Tool Tool
	// Run is what was asked for and what the asking cost.
	Run Run
	// Verdict is the one sentence at the top. It has to agree with Layers.
	Verdict Verdict
	// Layers is one row per diagnostic layer, in report order.
	Layers []LayerResult
	// Notes is every way this run did less than it promised. An empty slice is
	// a claim that nothing was skipped, not an absence of information.
	Notes []Note
}

// Tool is the name and version of the binary that produced a report.
//
// The version is supplied by the entry point rather than declared here, because
// the core has no business knowing which build it was compiled into.
type Tool struct {
	Name    string
	Version string
}

// Run is the metadata of one invocation.
type Run struct {
	// StartedAt is supplied by the caller. Nothing in this package reads a
	// clock: assessment has to be reproducible from recorded input, and a core
	// that can ask the time is a core whose output depends on when it ran.
	StartedAt time.Time
	// Duration is how long the run took, measured by the caller.
	Duration time.Duration
	// Target is what the user pointed us at, in whatever form the caller
	// decided is safe to print. This package neither parses nor masks it.
	Target string
	// PrivilegeLevel is mandatory metadata. Comparing two reports taken at
	// different privilege levels produces false findings without it, because a
	// store that was unreadable looks exactly like a store that is absent.
	PrivilegeLevel PrivilegeLevel
	Platform       Platform
	// Redacted says whether host names, paths and user names were masked.
	// Credentials are masked either way and are not covered by this field.
	Redacted bool
	// BudgetExceeded says the run ran out of its overall time and dropped work.
	// Whatever it dropped also has a Note.
	BudgetExceeded bool
}

// PrivilegeLevel is how much of the machine this run was allowed to see.
//
// The list is closed and three-valued. "Unknown" is a real answer here and not
// a placeholder: until something detects it, claiming "user" would be a
// measurement we never took.
type PrivilegeLevel string

const (
	PrivilegeUnknown  PrivilegeLevel = "unknown"
	PrivilegeUser     PrivilegeLevel = "user"
	PrivilegeElevated PrivilegeLevel = "elevated"
)

// privilegeLevels is the closed set, used to reject anything that crossed a
// boundary.
var privilegeLevels = map[PrivilegeLevel]bool{
	PrivilegeUnknown:  true,
	PrivilegeUser:     true,
	PrivilegeElevated: true,
}

// Valid reports whether p is one of the three.
func (p PrivilegeLevel) Valid() bool { return privilegeLevels[p] }

// String makes PrivilegeLevel printable without a conversion at every call site.
func (p PrivilegeLevel) String() string { return string(p) }

// Platform is where the run happened.
type Platform struct {
	OS   string
	Arch string
	// Container is deliberately not a bool. See Tristate.
	Container Tristate
}

// Tristate is a yes or no that can also be "we have not established this".
//
// A plain bool cannot tell "we looked and the answer is no" apart from "nothing
// has looked yet", and its zero value would state the first while meaning the
// second. That is the rule about never reporting an unknown as an answer,
// applied to a metadata field - the same failure as a probe reporting success
// because it did not understand what it saw, only quieter.
type Tristate uint8

const (
	// NotDetermined is the zero value on purpose, so a field nobody filled in
	// says so instead of saying no.
	NotDetermined Tristate = iota
	DeterminedFalse
	DeterminedTrue
)

// Determined reports whether t carries an answer at all.
func (t Tristate) Determined() bool { return t == DeterminedFalse || t == DeterminedTrue }

// LayerResult is one row of the report, one diagnostic layer.
type LayerResult struct {
	ID     layer.ID
	Status status.Status
	// Reason is required whenever Status is not a plain success. It comes from
	// the closed list, so a consumer can branch on it.
	Reason status.Reason
	// Detail is one line of English specific to this result, and it is a
	// different thing from Reason.
	//
	// Reason answers "which of the five kinds of not-knowing is this" and comes
	// from a closed vocabulary. Detail answers "what actually happened here"
	// and is free text. Folding the two together would mean either a closed
	// list that grows a member per situation, or a free-text field a pipeline
	// cannot branch on. Concretely: today every layer reports the probe-error
	// reason, whose declared description reads "the probe itself failed to
	// run" - which is not true of a layer nobody has written yet. Detail is
	// where that difference gets told.
	Detail string
}

// Assessed reports whether this layer produced an answer about the machine, as
// opposed to an answer about our own ability to look.
func (r LayerResult) Assessed() bool { return r.Status != status.Unknown }
