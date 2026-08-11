package report

import (
	"errors"
	"fmt"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Validate checks a finished report against the invariants that make it
// trustworthy, and returns every violation it finds rather than the first.
//
// WHY THIS RUNS IN PRODUCTION AND NOT ONLY IN TESTS. The invariant that matters
// most - the verdict agrees with the rows beneath it - is the product's main
// promise. A test proves it holds for the cases the test thought of. This proves
// it holds for the report actually about to be printed, and a violation becomes
// a loud internal failure with no report on standard output, rather than a
// confident wrong answer in somebody's ticket. The cost is one pass over a
// structure with a handful of rows, once per run.
//
// The caller turns a non-nil error into the exit code that means certdoctor
// itself broke. It must never turn it into a report.
func Validate(r Report) error {
	var problems []error
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Errorf(format, args...))
	}

	validateTool(r, add)
	validateRun(r, add)
	validateLayers(r, add)
	validateVerdict(r, add)
	validateNotes(r, add)

	return errors.Join(problems...)
}

func validateTool(r Report, add func(string, ...any)) {
	if r.Tool.Name == "" {
		add("the report does not name the tool that produced it")
	}
	if r.Tool.Version == "" {
		add("the report does not carry a tool version, so a reader could not tell which build produced it")
	}
}

func validateRun(r Report, add func(string, ...any)) {
	if !r.Run.PrivilegeLevel.Valid() {
		add("privilege level %q is outside the declared set - comparing two reports needs it to mean something", r.Run.PrivilegeLevel)
	}
	if r.Run.Platform.OS == "" || r.Run.Platform.Arch == "" {
		add("the report does not say which platform it was taken on")
	}
	if r.Run.Target == "" {
		add("the report does not say what it was pointed at")
	}
	if !r.Run.Platform.Container.Valid() {
		add("the container field holds %d, which is not one of the three declared values - it would render as null and read as an answer nobody gave", r.Run.Platform.Container)
	}
	if r.Run.Duration < 0 {
		add("the run reports a negative duration of %s", r.Run.Duration)
	}
	if r.Run.StartedAt.IsZero() {
		add("the report does not say when the run started, so it would carry a timestamp from the year one")
	}
}

// validateLayers demands a row for every declared layer, in the declared order.
//
// A missing row is the ban on silence broken in the quietest possible way: a
// reader scanning the report sees nothing about that layer and has no way to
// tell "it passed and was uninteresting" from "it never ran".
func validateLayers(r Report, add func(string, ...any)) {
	if len(r.Layers) != len(layer.All) {
		add("the report has %d layer rows, there are %d declared layers - every layer needs a row even when it did nothing",
			len(r.Layers), len(layer.All))
		return
	}
	for i, want := range layer.All {
		got := r.Layers[i]
		if got.ID != want {
			add("layer row %d is %q, report order puts %q there", i, got.ID, want)
		}
		validateLayerResult(got, add)
	}
}

func validateLayerResult(l LayerResult, add func(string, ...any)) {
	if !l.ID.Valid() {
		add("layer row %q is not a declared layer", l.ID)
	}
	if !l.Status.Valid() {
		add("layer %s carries a status outside the vocabulary", l.ID)
		return
	}
	switch {
	case l.Status.RequiresReason() && l.Reason == "":
		add("layer %s reports a problem without a reason, which is useless to the reader", l.ID)
	case !l.Status.RequiresReason() && l.Reason != "":
		// THE WORDING STOPPED BEING "passed" WHEN THE RULE NARROWED. This branch
		// now catches WARN and FAIL as well, and telling somebody their failing
		// layer "passed" would send them looking for a defect in the wrong place.
		add("layer %s reports %s and still carries the reason %q, which belongs to a layer that could not "+
			"be assessed", l.ID, l.Status, l.Reason)
	case l.Reason != "" && !l.Reason.Valid():
		add("layer %s carries the reason %q, which is outside the closed list", l.ID, l.Reason)
	}
	if l.Status.RequiresDetail() && l.Detail == "" {
		add("layer %s reports a problem without a detail line saying what happened", l.ID)
	}
	// The findings are checked one by one rather than as a whole, because a
	// report carrying two malformed ones has two things to fix and a reader who
	// is told about one of them fixes it and runs again.
	for i, finding := range l.Findings {
		if breach := finding.Breach(); breach != "" {
			add("layer %s finding %d %s", l.ID, i, breach)
		}
	}
}

// validateVerdict recomputes the fold and compares. This is the main promise
// checked against the very rows about to be printed underneath it.
func validateVerdict(r Report, add func(string, ...any)) {
	if r.Verdict.Sentence == "" {
		add("the report has no verdict sentence")
	}
	if !r.Verdict.Status.Valid() {
		add("the verdict carries a status outside the vocabulary")
	}
	if !r.Verdict.ExitCode.Valid() {
		add("the verdict carries exit code %d, which is not in the frozen table", r.Verdict.ExitCode.Int())
	}

	want := Assess(r.Layers)
	if r.Verdict.Status != want.Status {
		add("the verdict says %s while the rows beneath it are worst %s", r.Verdict.Status, want.Status)
	}
	if r.Verdict.ExitCode != want.ExitCode {
		add("the verdict carries exit code %s while the rows beneath it call for %s",
			r.Verdict.ExitCode.Name(), want.ExitCode.Name())
	}
	// THE SENTENCE IS COMPARED TOO, and leaving it out was a hole in the one
	// check this project calls the product's main promise. Status and exit code
	// were checked, and the sentence - the line a person actually reads - was
	// not, so a report claiming failures over passing rows would have gone out
	// as long as the two machine-readable fields agreed. Nothing produces that
	// today because one function builds both sides; the first verdict that names
	// a cause will not be built by counting, and this is the check that will be
	// standing there when it arrives.
	if r.Verdict.Sentence != want.Sentence {
		add("the verdict reads %q while the rows beneath it call for %q", r.Verdict.Sentence, want.Sentence)
	}
	// Kept alongside the comparison above rather than folded into it. The two
	// fire together, and this one names the worst case in the words it deserves
	// instead of leaving a reader to diff two sentences.
	if r.Verdict.Sentence == everythingPassed && want.Status != status.Pass {
		add("the verdict reads as complete success over rows that are worst %s", want.Status)
	}
}

func validateNotes(r Report, add func(string, ...any)) {
	for i, n := range r.Notes {
		if !n.Kind.Valid() {
			add("note %d has kind %q, which is outside the closed list", i, n.Kind)
		}
		if n.Detail == "" {
			add("note %d says something is missing and not what", i)
		}
		if n.Layer != "" && !n.Layer.Valid() {
			add("note %d points at %q, which is not a declared layer", i, n.Layer)
		}
		if n.Reason != "" && !n.Reason.Valid() {
			add("note %d carries the reason %q, which is outside the closed list", i, n.Reason)
		}
	}
	if r.Run.BudgetExceeded && !hasNoteOfKind(r.Notes, NoteSkipped) {
		add("the run says it exceeded its budget and no note says what it dropped")
	}
}

func hasNoteOfKind(notes []Note, kind NoteKind) bool {
	for _, n := range notes {
		if n.Kind == kind {
			return true
		}
	}
	return false
}
