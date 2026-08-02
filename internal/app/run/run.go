// Package run walks the diagnostic layers once and assembles the report.
//
// It takes its ports as parameters - the clock, the layer functions, the
// metadata - and writes to no channel of its own. Nothing here prints, and
// nothing here reads an environment variable or a file. That is what makes a
// run reproducible from what the caller passed in.
//
// WHY THIS IS SEQUENTIAL, AND WHY THE CONCURRENCY GUARD'S ALLOWLIST IS STILL
// EMPTY. certdoctor is concurrent by nature and this walk will not stay
// single-threaded: thirteen probes, each starting a subprocess, will not fit in
// a sixty second budget one after another. But the parallelism does not belong
// at this level. L1 hands addresses to L3 and L3 hands a connection to L4, so
// the layers are a pipeline, and the fan-out lives inside a layer - one branch
// per address, one per probe. Putting this file on the allowlist today would
// take the guard off it permanently and buy a wait group around work that
// finishes in microseconds.
//
// What makes the later change an addition rather than a rewrite is one rule
// followed from the first line: results are assembled BY IDENTIFIER, in the
// order the registry declares, never in the order the work finished.
package run

import (
	"context"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Answer is what one layer hands back.
//
// It deliberately carries no identifier. The orchestrator attaches that from
// the registry, so a layer cannot report itself as a different layer and no
// check is needed to catch it doing so.
type Answer struct {
	Status status.Status
	Reason status.Reason
	Detail string
}

// Layer walks one diagnostic layer.
//
// It is synchronous by contract. It receives a context carrying a deadline, it
// does its work, and it returns. It must not start a goroutine and it must not
// outlive the call - a subprocess surviving the run is a leak the user finds in
// their task manager.
type Layer func(ctx context.Context) Answer

// Layers is the behaviour of every declared layer, keyed by identifier.
//
// A map rather than a slice on purpose: the order of the report comes from the
// registry and from nowhere else, so this collection cannot decide it. A layer
// missing from the map is a loud failure rather than a row that quietly does
// not appear.
type Layers map[layer.ID]Layer

// Options is everything one walk needs.
type Options struct {
	Tool      report.Tool
	Target    string
	Platform  report.Platform
	Privilege report.PrivilegeLevel
	Redacted  bool

	// Budget limits the whole walk. Zero or less means no limit, which is what
	// the flag documents.
	Budget time.Duration
	// LayerBudget limits one layer. It is capped by whatever is left of Budget,
	// because a layer allowed ten seconds inside a run with two seconds left
	// would spend the run's time and report a timeout of its own.
	LayerBudget time.Duration

	// Now is the clock, taken as a port so the budget is testable without
	// waiting for real time to pass.
	Now func() time.Time

	// Layers holds one function per declared layer.
	Layers Layers

	// Notes are the shortfalls the caller already knows about, before the walk
	// starts - an option accepted that does nothing, a field it could not
	// determine. The walk appends its own.
	Notes []report.Note
}

// Execute walks every declared layer in report order and returns the assembled
// report.
//
// It returns an error only for a defect on our side or for a cancelled run.
// Neither produces a report, because a partial report is indistinguishable from
// a complete one once it is in a file.
func Execute(ctx context.Context, o Options) (report.Report, error) {
	if o.Now == nil {
		return report.Report{}, fmt.Errorf("no clock was supplied to the run")
	}

	started := o.Now()
	results := make([]report.LayerResult, 0, len(layer.All))
	notes := append([]report.Note{}, o.Notes...)
	exceeded := false

	for _, id := range layer.All {
		walk, declared := o.Layers[id]
		if !declared {
			return report.Report{}, fmt.Errorf("layer %s has no function - every declared layer needs a row", id)
		}
		if err := ctx.Err(); err != nil {
			return report.Report{}, err
		}

		remaining := o.remaining(started)
		if o.Budget > 0 && remaining <= 0 {
			exceeded = true
			results = append(results, budgetSkipResult(id))
			notes = append(notes, budgetSkipNote(id))
			continue
		}
		results = append(results, o.walkOne(ctx, id, walk, remaining))
	}

	return o.assemble(started, results, notes, exceeded), nil
}

// remaining is how much of the overall budget is left, or a negative duration
// meaning "unlimited" when no budget was set.
func (o Options) remaining(started time.Time) time.Duration {
	if o.Budget <= 0 {
		return -1
	}
	return o.Budget - o.Now().Sub(started)
}

// walkOne runs one layer under the tighter of the two deadlines.
//
// The tighter one matters: a layer allowed ten seconds inside a run with two
// seconds left would spend the run's remaining time and then report a timeout
// of its own, which reads as a slow machine rather than as a budget we set.
func (o Options) walkOne(ctx context.Context, id layer.ID, walk Layer, remaining time.Duration) report.LayerResult {
	limit := effectiveLimit(o.LayerBudget, remaining)
	if limit <= 0 {
		return resultOf(id, walk(ctx))
	}

	layerCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	return resultOf(id, walk(layerCtx))
}

// effectiveLimit picks the deadline one layer actually gets.
//
// A negative remaining means the run has no overall budget. A limit of zero or
// less means no deadline at all, which is what both budgets being switched off
// produces. Everything else takes the smaller of the two.
//
// It is a separate function because it is the whole of the budget arithmetic,
// and arithmetic tested through a real clock is arithmetic tested loosely.
func effectiveLimit(layerBudget, remaining time.Duration) time.Duration {
	if remaining < 0 {
		return layerBudget
	}
	if layerBudget <= 0 || remaining < layerBudget {
		return remaining
	}
	return layerBudget
}

// resultOf attaches the identifier the registry declared. A layer never gets to
// say which layer it is.
func resultOf(id layer.ID, answer Answer) report.LayerResult {
	return report.LayerResult{
		ID:     id,
		Status: answer.Status,
		Reason: answer.Reason,
		Detail: answer.Detail,
	}
}

func (o Options) assemble(started time.Time, results []report.LayerResult, notes []report.Note, exceeded bool) report.Report {
	return report.Report{
		Tool: o.Tool,
		Run: report.Run{
			StartedAt:      started,
			Duration:       o.Now().Sub(started),
			Target:         o.Target,
			PrivilegeLevel: o.Privilege,
			Platform:       o.Platform,
			Redacted:       o.Redacted,
			BudgetExceeded: exceeded,
		},
		Verdict: report.Assess(results),
		Layers:  results,
		Notes:   notes,
	}
}

func budgetSkipResult(id layer.ID) report.LayerResult {
	return report.LayerResult{
		ID:     id,
		Status: status.Unknown,
		Reason: status.ReasonSkippedBudget,
		Detail: "the run was out of time before this layer started",
	}
}

func budgetSkipNote(id layer.ID) report.Note {
	return report.Note{
		Kind:   report.NoteSkipped,
		Layer:  id,
		Reason: status.ReasonSkippedBudget,
		Detail: "the run exceeded its overall time budget and did not walk this layer",
	}
}
