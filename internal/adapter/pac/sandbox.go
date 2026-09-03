package pac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dop251/goja"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// Entry is the function name every PAC file must define.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 - the file is a
// JavaScript source defining FindProxyForURL(url, host).
const Entry = "FindProxyForURL"

// Sandbox evaluates PAC files under the five conditions of docs/14 section 2.1.
//
// A ZERO SANDBOX IS USELESS RATHER THAN DANGEROUS: with a zero budget and a zero
// ceiling every evaluation is refused at once. The safe direction for a value
// nobody set is refusing, not running unbounded.
type Sandbox struct {
	// Ports are what the twelve helpers may reach. All-nil is legal and means
	// the helpers that need the world say so.
	Ports corepac.Ports

	// Budget is the wall clock the PAC file gets.
	Budget time.Duration

	// Ceiling is how much heap the evaluation may add before it is stopped.
	//
	// IT IS A PROCESS FIGURE AND NOT AN EVALUATION FIGURE, AND A CALLER HAS TO
	// KNOW THAT. The stopwatch subtracts a baseline taken when the evaluation
	// starts, so it measures a DELTA rather than the absolute heap - but the
	// delta still includes whatever every other goroutine allocated meanwhile.
	// Measured 2026-09-03: the same PAC file under the same 128 MiB ceiling
	// answered normally on its own and was stopped with memory_ceiling while
	// another goroutine allocated. A PAC file can therefore be blamed for
	// somebody else's allocation, which is the exact inversion of what this
	// program is for.
	//
	// WHY IT IS NOT SIMPLY FIXED: Go publishes no per-goroutine allocation
	// accounting. runtime/metrics does remove the stop-the-world cost of
	// ReadMemStats, but /gc/heap/allocs:bytes is process-wide too AND monotonic,
	// so somebody else's allocation would count for ever instead of momentarily.
	// This is the same wall ADR75 hit when condition 3 had to be rewritten,
	// reached from the other side.
	//
	// WHY IT IS KEPT ANYWAY, measured rather than assumed: with the ceiling
	// effectively removed, testbed/pac/files/bomb.pac ran to the TIME budget
	// instead - 351 ms and 513 MiB of cumulative allocation against 239 ms and
	// 256 MiB with the ceiling on, inside a 512 MiB container. The ceiling buys
	// a real bound on how far a hostile file gets before something stops it.
	//
	// WHAT A CALLER MUST DO ABOUT IT: do not evaluate a PAC file beside layers
	// that allocate, and do not report memory_ceiling to a user as a fact about
	// their file without that caveat. L2 arrives with P8-K3 and this is its
	// problem to place.
	Ceiling uint64

	// MaxSource is the largest PAC file accepted, checked BEFORE the bytes reach
	// the parser - docs/14 section 2.3, because after parsing it is too late.
	MaxSource int

	// MaxStack is the call stack limit.
	//
	// IT IS A CONDITION AND NOT TUNING - ADR75. Measured 2026-09-02: with
	// goja's default, unbounded recursion was still running after ten seconds
	// with a 213 MiB heap; with the limit set the same file ends in 1 ms.
	MaxStack int
}

// Evaluate runs source and asks it which proxy to use for rawURL on host.
//
// IT NEVER RETURNS AN ERROR, AND THAT IS THE POINT OF CONDITION 5. Every way
// this can fail - a file that will not parse, a missing entry point, a throw, a
// limit reached, a panic from code we do not own - comes back as a Result whose
// Outcome names what happened. A caller cannot accidentally treat a broken PAC
// as a working one, because there is no error to forget to check.
func (s Sandbox) Evaluate(source, rawURL, host string) (result corepac.Result) {
	// A PANIC FROM SOMEBODY ELSE'S ENGINE IS CAUGHT HERE AND NOWHERE ELSE -
	// ADR67 applied one layer along. The orchestrator's recover runs on the
	// goroutine that walks the layers, and probe S12 measured only that no panic
	// escaped ITS inputs, which is a statement about those inputs rather than
	// about goja. Without this, a panic under a PAC file would kill the process
	// with no report at all and an exit code from outside the table.
	//
	// IT IS THE FIRST STATEMENT OF THIS FUNCTION AND THAT POSITION IS THE RULE,
	// NOT TIDINESS. It used to stand three statements down, after goja.New,
	// SetMaxCallStackSize and makeDeterministic, so a panic in any of those left
	// through a promise that says NEVER. Measured 2026-09-03 while moving it:
	// none of the three panics on any input tried - a negative MaxStack answers
	// stack_limit, a zero one answers normally, and makeDeterministic never
	// passes nil to SetRandSource because fixedRandom cannot return one. THE GAP
	// WAS THEREFORE IN THE PROMISE RATHER THAN IN AN OBSERVED FAILURE, and that
	// is the reason to close it: condition 5 is a sentence about every future
	// input, and it cannot rest on nobody having found a trigger yet.
	defer func() {
		if cause := recover(); cause != nil {
			result = corepac.Result{
				Outcome: corepac.OutcomeMalformed,
				Detail:  fmt.Sprintf("the PAC evaluator fell over inside this program: %v", cause),
			}
		}
	}()

	if len(source) > s.MaxSource {
		return corepac.Result{
			Outcome: corepac.OutcomeTooLarge,
			Detail: fmt.Sprintf("the PAC file is %d bytes and this run accepts at most %d, so it was refused before it was parsed",
				len(source), s.MaxSource),
		}
	}

	vm := goja.New()
	vm.SetMaxCallStackSize(s.MaxStack)
	usedRandomness := s.makeDeterministic(vm)

	if failure := s.inject(vm); failure != nil {
		return corepac.Result{
			Outcome: corepac.OutcomeMalformed,
			Detail:  "the sandbox could not be built: " + failure.Error(),
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch(ctx, vm, s.Budget, s.Ceiling)

	if _, err := vm.RunString(source); err != nil {
		return outcomeOf(err, "the PAC file could not be loaded")
	}

	entry, ok := goja.AssertFunction(vm.Get(Entry))
	if !ok {
		return corepac.Result{
			Outcome: corepac.OutcomeMalformed,
			Detail:  "the PAC file defines no " + Entry + " function, so there is nothing to ask",
		}
	}

	answer, err := entry(goja.Undefined(), vm.ToValue(rawURL), vm.ToValue(host))
	if err != nil {
		return outcomeOf(err, "the PAC file failed while answering")
	}
	answered := s.read(answer)
	answered.UsedRandomness = usedRandomness()
	return answered
}

// read turns the value a PAC file returned into a Result.
//
// IT ASKS IsNull AND IsUndefined BEFORE IT ASKS String(), AND THAT ORDER IS
// THE WHOLE FUNCTION. Measured by probe S12 on 2026-09-02: goja exports null as
// the STRING "null" while goja.IsNull reports true. Reading with String() alone
// would turn "the PAC gave no answer" into "use a proxy whose host is called
// null" - a directive this program would then print, and somebody would go
// looking for a machine by that name. testbed/pac/files/null.pac exists to keep
// that measurement from being forgotten.
func (s Sandbox) read(answer goja.Value) corepac.Result {
	if answer == nil || goja.IsNull(answer) || goja.IsUndefined(answer) {
		return corepac.Result{
			Outcome: corepac.OutcomeNoAnswer,
			Detail:  "the PAC file returned no answer for this URL",
		}
	}

	raw := answer.String()
	directives := corepac.ParseDirectives(raw)
	if len(directives) == 0 {
		return corepac.Result{
			Outcome: corepac.OutcomeNoAnswer,
			Raw:     raw,
			Detail:  "the PAC file returned an empty answer for this URL",
		}
	}
	return corepac.Result{Outcome: corepac.OutcomeAnswered, Directives: directives, Raw: raw}
}

// outcomeOf sorts an error from the engine into the outcome that describes it.
//
// THE THREE LIMITS ARRIVE AS THREE DIFFERENT THINGS, measured 2026-09-02: the
// time and memory ceilings come back as *goja.InterruptedError carrying the
// Limit the stopwatch passed to Interrupt, while the stack limit is goja's own
// *goja.StackOverflowError and never reaches the stopwatch at all.
func outcomeOf(err error, context string) corepac.Result {
	var interrupted *goja.InterruptedError
	if errors.As(err, &interrupted) {
		if limit, ok := interrupted.Value().(Limit); ok && limit == LimitMemory {
			return corepac.Result{
				Outcome: corepac.OutcomeMemoryCeiling,
				Detail:  context + ": it was stopped for allocating past the ceiling this run allows",
			}
		}
		return corepac.Result{
			Outcome: corepac.OutcomeTimeLimit,
			Detail:  context + ": it was stopped for running past the time this run allows",
		}
	}

	var overflow *goja.StackOverflowError
	if errors.As(err, &overflow) {
		return corepac.Result{
			Outcome: corepac.OutcomeStackLimit,
			Detail:  context + ": it recursed past the call stack limit this run allows",
		}
	}

	return corepac.Result{Outcome: corepac.OutcomeMalformed, Detail: context + ": " + err.Error()}
}
