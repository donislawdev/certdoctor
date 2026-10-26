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
	// their file without that caveat.
	//
	// L2 HAS NOW PLACED IT, AND THE PLACEMENT WAS MEASURED RATHER THAN ARGUED.
	// Instrumented on 2026-09-06 at the point in the walk where that layer runs,
	// on Windows and in a container, three runs each: four goroutines, and the
	// heap moving by 96 to 160 BYTES across a 300 millisecond window. The
	// neighbour noise this ceiling could mistake for a PAC file is six orders of
	// magnitude below it. THAT IS A FACT ABOUT WHERE THE EVALUATION SITS, not
	// about the ceiling: move it beside anything that allocates - a parallel
	// walk, a layer running alongside - and the measurement is void with nothing
	// to notice.
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

	// MaxLookups is how many DISTINCT hosts one evaluation may send to a
	// resolver. It does nothing when Ports.Resolve is nil, because then nothing
	// is asked at all.
	//
	// IT IS THE ONE BOUND THE STOPWATCH CANNOT PROVIDE, and probe S16 measured
	// which half is missing rather than assuming both were. Three runs of three
	// on 2026-09-07: a native call already running is NOT interrupted - ADR78
	// again - but the next one is stopped from starting, so a slow resolver
	// overruns Budget by exactly one query. Time is held. In the same 300
	// millisecond budget, however, a file got 214 to 222 questions away at one
	// millisecond each and 629 837 to 645 003 when they were free. Every one of
	// those is a name somebody else chose, sent to a resolver the allowed set
	// already permits, so no guard in this program sees the channel. This
	// number is what bounds it.
	//
	// IT COUNTS NAMES AND NOT CALLS BECAUSE THE EVALUATION CACHES. A file
	// testing one host against ten subnets calls isInNet ten times about one
	// name; nine of those never leave this machine, so counting calls would
	// refuse an honest file for traffic it did not generate.
	//
	// A ZERO REFUSES EVERY LOOKUP, which follows this type's rule that an unset
	// field is useless rather than unbounded. A caller that wires a resolver and
	// forgets this number gets a run that says it could not ask, not one that
	// asks without limit.
	MaxLookups int

	// MaxAnswer is the longest answer read, in bytes, and MaxDirectives the most
	// entries one answer may name - ADR114.
	//
	// THEY BOUND WHAT RUNS AFTER THE ENGINE, WHICH NO STOPWATCH WATCHES. MaxSource
	// limits the file, and a file of one line can return "DIRECT;" repeated a
	// million times: seven megabytes the memory ceiling may never notice, then a
	// million entries split, carried into rows, masked and written out by our own
	// code. A zero refuses every answer, by this type's rule for an unset field.
	MaxAnswer     int
	MaxDirectives int
}

// Evaluate runs source and asks it which proxy to use for rawURL on host.
//
// IT NEVER RETURNS AN ERROR, AND THAT IS THE POINT OF CONDITION 5. Every way
// this can fail - a file that will not parse, a missing entry point, a throw, a
// limit reached, a panic from code we do not own - comes back as a Result whose
// Outcome names what happened. A caller cannot accidentally treat a broken PAC
// as a working one, because there is no error to forget to check.
//
// ctx is the layer's: its deadline caps Budget and its cancellation stops the
// file - ADR114. Until then an evaluation started with little of the layer left
// got its whole budget again.
func (s Sandbox) Evaluate(ctx context.Context, source, rawURL, host string) (result corepac.Result) {
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

	// ONE CLOCK FOR THE STOPWATCH AND FOR shExpMatch - ADR114. The stopwatch
	// cannot interrupt native code, so the one helper whose work grows with its
	// input asks the same question between its steps, and both answer to this
	// file's budget and to the layer: ctx.Err() turns non-nil at the layer's
	// deadline as well as at a cancelled run, so the deadline needs no copying.
	deadline := time.Now().Add(s.Budget)
	expired := func() bool { return ctx.Err() != nil || time.Now().After(deadline) }

	vm := goja.New()
	vm.SetMaxCallStackSize(s.MaxStack)
	usedRandomness, readClock := s.makeDeterministic(vm)

	record, failure := s.inject(vm, expired)
	if failure != nil {
		return corepac.Result{
			Outcome: corepac.OutcomeMalformed,
			Detail:  "the sandbox could not be built: " + failure.Error(),
		}
	}

	// finish attaches what the file asked for and could not be told, to every
	// path that got as far as running it.
	//
	// IT IS A WRAPPER RATHER THAN A SECOND defer BECAUSE THE FIRST ONE'S
	// POSITION IS A RULE. The recover above has to be this function's first
	// statement, and defers run last-registered-first, so a second defer added
	// after it would run BEFORE the recover replaced the result and would be
	// overwritten on the path that matters least. Three call sites are cheaper
	// than moving a guard whose position is written down as load-bearing.
	finish := func(result corepac.Result) corepac.Result {
		seen := record()
		result.Unanswered = seen.unanswered
		result.Asked = seen.asked
		result.LookupsExhausted = seen.exhausted
		result.LookupsFailed = seen.failed
		// EITHER ROUTE COUNTS. seen.usedClock is our three helpers taking the
		// pinned instant; readClock is the file calling Date itself. The caveat
		// is about the ANSWER having a date on it, not about which door was used.
		result.UsedClock = seen.usedClock || readClock()
		return result
	}

	watching, stop := context.WithCancel(context.Background())
	defer stop()
	watch(watching, vm, expired, s.Ceiling)

	if _, err := vm.RunString(source); err != nil {
		return finish(outcomeOf(err, "the PAC file could not be loaded"))
	}

	entry, ok := goja.AssertFunction(vm.Get(Entry))
	if !ok {
		// WRAPPED TOO, THOUGH NOTHING WAS ASKED YET. RunString has already run
		// the file's top level, and a PAC file may legally call a helper there -
		// caching dnsResolve into a variable is a real idiom. A path that
		// dropped the list would report "no entry point" about a file that had
		// already gone looking for a resolver.
		return finish(corepac.Result{
			Outcome: corepac.OutcomeMalformed,
			Detail:  "the PAC file defines no " + Entry + " function, so there is nothing to ask",
		})
	}

	answer, err := entry(goja.Undefined(), vm.ToValue(rawURL), vm.ToValue(host))
	if err != nil {
		return finish(outcomeOf(err, "the PAC file failed while answering"))
	}
	answered := finish(s.read(answer))
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

	// THE LIMITS COME AFTER String() AND THAT IS WHERE THEY HAVE TO BE. For an
	// object String() runs the file's own toString - still inside the budget and
	// the ceiling, because the stopwatch stops only when Evaluate returns - so the
	// length of what it built is known only here, and everything from here on is
	// our code with nothing watching it - ADR114.
	raw := answer.String()
	if len(raw) > s.MaxAnswer {
		return corepac.Result{
			Outcome: corepac.OutcomeTooLarge,
			Detail: fmt.Sprintf("the PAC file returned an answer of %d bytes and this run reads at most %d",
				len(raw), s.MaxAnswer),
		}
	}
	directives := corepac.ParseDirectives(raw)
	if len(directives) > s.MaxDirectives {
		return corepac.Result{
			Outcome: corepac.OutcomeTooLarge,
			Detail: fmt.Sprintf("the PAC file returned %d entries and this run reads at most %d",
				len(directives), s.MaxDirectives),
		}
	}
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

	return corepac.Result{Outcome: corepac.OutcomeMalformed, Detail: context + ": " + describe(err)}
}

// describe renders an engine error for the report - the thrown value, and the
// place in the SCRIPT it was thrown from.
//
// WHY NOT err.Error(), AND IT IS MEASURED (S19, 2026-09-21). goja's Exception
// formats itself as the thrown value followed by ONE frame, the innermost. When
// a script's own code throws, that frame is the script's - "at FindProxyForURL
// (<eval>:1:38)" - and it is exactly what a reader wants. When one of OUR
// helpers refuses a shape it cannot read, the innermost frame is the helper,
// and the message carries the path of a package inside this program -
// "at github.com/donislawdev/certdoctor/internal/adapter/pac.Sandbox.timeHelper.func1
// (native)" - while the script's own position, one frame up, is DROPPED. That
// is OBS136: an internal symbol on a public surface, and the one useful
// coordinate missing. Cutting the stack would fix the first and not the second.
// So the frames are walked and the first one that is not native is the one
// printed, in goja's own shape minus the program counter it appends.
//
// Anything that is not an Exception - a syntax error at load time, which goja
// reports as a different type - keeps its own text, which names no frames.
func describe(err error) string {
	var thrown *goja.Exception
	if !errors.As(err, &thrown) || thrown.Value() == nil {
		return err.Error()
	}
	said := thrown.Value().String()
	for _, frame := range thrown.Stack() {
		if frame.SrcName() == "<native>" {
			continue
		}
		where := frame.SrcName()
		if where == "" {
			where = "<eval>"
		}
		position := frame.Position()
		if frame.FuncName() == "" {
			return fmt.Sprintf("%s at %s:%d:%d", said, where, position.Line, position.Column)
		}
		return fmt.Sprintf("%s at %s (%s:%d:%d)", said, frame.FuncName(), where, position.Line, position.Column)
	}
	return said
}
