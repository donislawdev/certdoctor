package guard

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// THERE ARE THREE LISTS BELOW AND THEY GET NARROWER, WHICH IS THE POINT. The
// first switches this guard off for a whole file. The second and third switch
// off a single question each, and everything they do NOT excuse stays reported
// for ever by the same walk that covers every other file. Each has a canary of
// its own, because a list nobody checks is a hole rather than an exemption.
//
// concurrencyAllowlist names the files allowed to hold ANY concurrency
// primitive.
//
// IT IS EMPTY AND HAS STAYED EMPTY THROUGH THREE OCCASIONS THAT WERE MEANT TO
// FILL IT - the orchestrator (ADR15), the system view's dialler (ADR35) and now
// L3's fan-out (ADR43). Each time the answer was a narrower exemption instead,
// for the reason ADR15 gives: an entry here switches the guard off for that file
// for ever, and in practice nobody ever takes one off again. Anything that can
// be expressed as "this file may do exactly one more thing" belongs on a list
// below, not here.
var concurrencyAllowlist = map[string]bool{}

// lockOnlyAllowlist names files allowed to HOLD A LOCK and nothing else.
//
// IT IS A NARROWER EXEMPTION THAN THE LIST ABOVE, AND THAT IS ITS WHOLE REASON.
// A file here may import sync. It still may not start a goroutine, open a
// channel, send on one, receive from one, or select - those stay reported, for
// ever, by the same walk that covers every other file. The list above switches
// the guard off for a file; this one switches off a single question.
//
// WHY IT EXISTS AT ALL, MEASURED RATHER THAN ARGUED. The system view has to ask
// net.Resolver, and net.Resolver calls the dialler we hand it FROM ITS OWN
// GOROUTINES - measured in alpine, three runs of three, with the A and AAAA
// queries overlapping in time by tens of microseconds. The one fact that
// dialler has to report outward, whether it was called at all, is what decides
// detected against derived (ADR28). So the state is written by somebody else's
// goroutines and read by ours, which is a lock whether or not we like it.
//
// THIS IS A THIRD CATEGORY THAT docs/22 SECTION 2 DID NOT ANTICIPATE. Rule 1
// there says concurrency lives in the orchestrator alone, and it is about work
// WE run in parallel. Nothing in this program starts a goroutine for the system
// view. The parallelism is the standard library's, arriving through a callback,
// and the only thing we own is the lock that makes reading it safe. Writing that
// distinction down is the point of this list: the next reader must not conclude
// that the core has started parallelising itself.
var lockOnlyAllowlist = map[string]bool{
	// The system view's dialler. It holds one mutex over two fields and starts
	// nothing - and if it ever does start something, the walk below still says so.
	"internal/adapter/dns/system.go": true,
}

// fanOutAllowlist names files allowed to START GOROUTINES over a work set fixed
// before they start, and nothing else.
//
// IT IS THE NARROWEST OF THE THREE. A file here may import sync and may write a
// go statement. It may NOT open a channel, send on one, receive from one, select,
// or import sync/atomic - all of those stay reported. The lock-only list above
// excuses both halves of sync; this one excuses a single package, and the
// difference is deliberate: a counter shared between goroutines is exactly the
// shape this list was drawn narrow to keep out.
//
// WHY THE CHANNEL STAYS FORBIDDEN, AND THE ARGUMENT IS STRUCTURAL RATHER THAN
// STYLISTIC - ADR43. The fan-out that needs the narrowest exemption is the same
// one whose results CANNOT be assembled in completion order: a WaitGroup plus a
// write to each goroutine's own index in a ready-made slice needs one import and
// one go statement, and no channel at all. The variant that collects results
// through a channel needs a WIDER exemption and invites assembling them in the
// order they finish - which breaks rule 2 of docs 22 section 2, and would make
// this layer report rows in an order that changes between runs. So the narrow
// list does not merely permit the right shape, it forces it.
//
// THIS IS THE FOURTH CATEGORY docs 22 section 2 NOW CARRIES. Rule 1 there says
// concurrency lives in the orchestrator alone; ADR15 point 3 says the parallelism
// belongs INSIDE a layer, one branch per address in L3. L3 is the core, so the
// two could not both be followed. The document changed rather than the decision -
// what stays true of rule 1 is that Connect and tryOne are still synchronous
// functions that do not know anybody runs them in parallel.
var fanOutAllowlist = map[string]bool{
	// THE ONE FILE IN THIS PROGRAM THAT STARTS A GOROUTINE. One WaitGroup per
	// wave, one write per index, no channel.
	//
	// IT IS SHARED BY L3 AND L4 RATHER THAN COPIED INTO EACH - ADR45. That keeps
	// this list one entry long, which is the number worth defending: a second
	// entry here would mean a second place where the same promise is made, and
	// the first thing to notice would be the mutation register reporting SKIP
	// rather than anybody reading the code (OBS50).
	"internal/core/fanout/fanout.go": true,
}

// TestALockOnlyFileMayHoldALockAndNothingElse is the canary for the narrow
// exemption, and without it that list is a hole nobody checks.
//
// An allowlist entry is only worth having if the thing it does NOT excuse is
// still enforced. This plants a file on the lock-only list and hands the scanner
// a fixture that holds a mutex AND starts a goroutine, opens a channel, sends,
// receives and selects. The import must stop being reported; every one of the
// others must still be, and the test names them rather than counting, because a
// count passes just as well when the wrong half survives.
func TestALockOnlyFileMayHoldALockAndNothingElse(t *testing.T) {
	const planted = "internal/adapter/probe/planted.go"
	lockOnlyAllowlist[planted] = true
	defer delete(lockOnlyAllowlist, planted)

	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "concurrency_violation.go", planted)},
	}
	violations := checkConcurrencyContainment(tr)

	var said string
	for _, v := range violations {
		said += v.Detail + "\n"
		if strings.Contains(v.Detail, "import of") {
			t.Errorf("a lock-only file was still reported for holding a lock: %s", v.Detail)
		}
	}
	for _, structural := range []string{"go statement", "channel type", "channel send", "channel receive", "select statement"} {
		if !strings.Contains(said, structural) {
			t.Errorf("a lock-only file got away with a %s, and the exemption was meant to cover the import alone.\nreported:\n%s",
				structural, said)
		}
	}
}

// TestAFanOutFileMayStartGoroutinesAndNothingElse is the canary for the third
// and narrowest exemption. Without it that list is a hole nobody checks.
//
// It plants a file on the fan-out list and hands the scanner a fixture that
// imports both halves of sync, starts a goroutine, opens a channel, sends,
// receives and selects. Two things must stop being reported and five must still
// be - and the test NAMES all seven rather than counting, because a count passes
// just as well when the wrong half survives.
//
// THE sync/atomic ASSERTION IS THE ONE THAT EARNS THIS TEST. It is the single
// difference between this list and the lock-only list above, so it is the one a
// tidying edit would collapse by accident, leaving two lists that look different
// and behave identically.
func TestAFanOutFileMayStartGoroutinesAndNothingElse(t *testing.T) {
	const planted = "internal/adapter/probe/planted.go"
	fanOutAllowlist[planted] = true
	defer delete(fanOutAllowlist, planted)

	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "concurrency_violation.go", planted)},
	}
	violations := checkConcurrencyContainment(tr)

	var said string
	for _, v := range violations {
		said += v.Detail + "\n"
	}
	for _, excused := range []string{`import of "sync"`, "go statement"} {
		if strings.Contains(said, excused) {
			t.Errorf("a fan-out file was still reported for a %s, which is what this list exists to permit.\nreported:\n%s",
				excused, said)
		}
	}
	for _, kept := range []string{
		// The whole reason this list is narrower than the lock-only one.
		`import of "sync/atomic"`,
		"channel type", "channel send", "channel receive", "select statement",
	} {
		if !strings.Contains(said, kept) {
			t.Errorf("a fan-out file got away with a %s, and the exemption was meant to cover a WaitGroup alone.\nreported:\n%s",
				kept, said)
		}
	}
}

// TestEveryConcurrencyExemptionNamesAFileThatExists keeps the three lists from
// rotting.
//
// AN ENTRY POINTING AT A FILE NOBODY WROTE YET, OR AT ONE SINCE RENAMED, IS AN
// EXEMPTION LYING IN WAIT. It costs nothing while the path is empty and starts
// excusing whatever turns up there later - under a name somebody chose for other
// reasons, with nobody re-reading the decision that granted it. The lists are
// short enough to check by eye, which is exactly why this went unchecked.
//
// It is also what makes a new exemption RED BEFORE the code it excuses exists,
// so the list has to be written first and the file second - the order docs 22
// section 6a asks for everywhere else.
func TestEveryConcurrencyExemptionNamesAFileThatExists(t *testing.T) {
	tr := mustLoadModule(t)

	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}

	for _, list := range []struct {
		name    string
		entries map[string]bool
	}{
		{"concurrencyAllowlist", concurrencyAllowlist},
		{"lockOnlyAllowlist", lockOnlyAllowlist},
		{"fanOutAllowlist", fanOutAllowlist},
	} {
		for entry := range list.entries {
			if !present[entry] {
				t.Errorf("%s excuses %q, and there is no such file in this module - an exemption with no code under it excuses whatever lands there next",
					list.name, entry)
			}
		}
	}
}

// TestConcurrencyIsContained is the guard from docs 22 position 2. It stands
// before the first goroutine on purpose: written afterwards it would find the
// rule already broken and would be something to repair rather than something
// that protects.
func TestConcurrencyIsContained(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkConcurrencyContainment(tr), "concurrency outside the orchestrator")
}

// TestConcurrencyGuardDetectsPlantedViolations is the canary. With zero
// goroutines in the tree the guard above cannot tell "contained" from "blind".
func TestConcurrencyGuardDetectsPlantedViolations(t *testing.T) {
	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "concurrency_violation.go", "internal/adapter/probe/planted.go")},
	}
	violations := checkConcurrencyContainment(planted)

	for _, want := range []string{
		"go statement",
		"select statement",
		"channel send",
		"channel type",
		"channel receive",
		`import of "sync"`,
		`import of "sync/atomic"`,
	} {
		requireViolation(t, violations, want)
	}
}

// TestConcurrencyAllowsWaitingForCancellation is the other half of the guard,
// and it exists so the exemption cannot quietly widen. Waiting for a context to
// be cancelled must not be reported - otherwise the first probe ever written
// trips the guard and the fix would be to weaken it.
func TestConcurrencyAllowsWaitingForCancellation(t *testing.T) {
	allowed := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "concurrency_cancellation.go", "internal/adapter/probe/waiting.go")},
	}
	requireNoViolations(t, checkConcurrencyContainment(allowed),
		"waiting for cancellation must not count as concurrency")
}

// TestMixedSelectIsStillReported pins the edge of the exemption: a select that
// waits for cancellation AND for a real channel is concurrency.
//
// Its fixture holds that one shape and nothing else, because the same assertion
// made against a file with several selects would pass on the wrong one.
func TestMixedSelectIsStillReported(t *testing.T) {
	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "concurrency_mixed.go", "internal/adapter/probe/planted.go")},
	}
	violations := checkConcurrencyContainment(planted)

	requireViolation(t, violations, "select statement")
	requireViolation(t, violations, "channel receive")
	requireViolation(t, violations, "channel type")

	// The fixture has two receives and only one of them is real work, so the
	// count is the assertion. A line number would go stale the moment the
	// fixture's comment changes, and the test would then pass by violation
	// nothing rather than by checking anything.
	receives := 0
	for _, f := range violations {
		if strings.Contains(f.Detail, "channel receive") {
			receives++
		}
	}
	if receives != 1 {
		t.Errorf("reported %d channel receives, want 1 - the cancellation clause must stay exempt: %v", receives, violations)
	}
}

// checkConcurrencyContainment reports every concurrency primitive outside the
// allowlist, except waiting for a context to be cancelled.
//
// What it does not see:
//
//   - test files, which are skipped. A concurrency test needs goroutines.
//   - waiting for cancellation, exempted deliberately - see cancellationWaits.
//   - time.After and time.Tick, which schedule work without naming any of the
//     primitives below. A probe that wants one of those lands on the allowlist,
//     which is the intended outcome: a decision rather than a habit.
//   - a package that hides a goroutine behind a helper of its own, once such a
//     helper exists inside the allowlist.
func checkConcurrencyContainment(tr tree) []Violation {
	var violations []Violation

	for _, sf := range tr.files {
		if sf.isTest || concurrencyAllowlist[sf.rel] {
			continue
		}
		exempt := cancellationWaits(sf.file)
		report := func(pos token.Pos, what string) {
			violations = append(violations, Violation{
				File:   sf.rel,
				Line:   sf.fset.Position(pos).Line,
				Detail: what + " - concurrency lives in the orchestrator alone, so that the core never learns anything runs in parallel",
			})
		}

		// A narrowly exempted file is excused ONE question and no other. Everything
		// below still runs against it, so the day somebody adds a channel here the
		// guard says so - which is the difference between a narrow exemption and
		// switching the guard off for a file.
		for _, imp := range importsOf(sf) {
			if imp.path != "sync" && imp.path != "sync/atomic" {
				continue
			}
			// A lock needs both halves of the standard library's answer; a fan-out
			// needs a WaitGroup and nothing else, so sync/atomic stays reported
			// there - ADR43.
			if lockOnlyAllowlist[sf.rel] || (fanOutAllowlist[sf.rel] && imp.path == "sync") {
				continue
			}
			violations = append(violations, Violation{
				File:   sf.rel,
				Line:   imp.line,
				Detail: "import of \"" + imp.path + "\" - concurrency lives in the orchestrator alone",
			})
		}

		ast.Inspect(sf.file, func(n ast.Node) bool {
			if exempt[n] {
				return true
			}
			switch node := n.(type) {
			case *ast.GoStmt:
				// The one primitive the fan-out list excuses. The walk keeps
				// descending, so a channel INSIDE the goroutine is still reported.
				if fanOutAllowlist[sf.rel] {
					return true
				}
				report(node.Pos(), "go statement")
			case *ast.SelectStmt:
				report(node.Pos(), "select statement")
			case *ast.SendStmt:
				report(node.Pos(), "channel send")
			case *ast.ChanType:
				report(node.Pos(), "channel type")
			case *ast.UnaryExpr:
				if node.Op == token.ARROW {
					report(node.Pos(), "channel receive")
				}
			}
			return true
		})
	}
	return sortViolations(violations)
}

// cancellationWaits marks the receives and selects that do nothing but wait for
// a context to be cancelled.
//
// WHY THE EXEMPTION EXISTS. Every probe carries a context with a deadline,
// because a subprocess outliving the run is a leak the user sees in their task
// manager. So every probe will contain a receive from ctx.Done(). Counting those
// would fire this guard on the first probe ever written, and the pressure would
// then be to add files to the allowlist - dissolving the rule at exactly the
// moment it starts to matter. A guard that goes off on correct code is switched
// off within a week.
//
// WHY IT IS NARROW. It matches a call to a method named Done taking no
// arguments, and a select whose every clause is either such a receive or a
// default. A select that mixes cancellation with a real channel is still
// reported, and so is the real channel inside it. A type of our own with a
// method called Done returning a channel would slip through - that is a
// deliberate act, not an accident, and no guard here defends against those.
func cancellationWaits(f *ast.File) map[ast.Node]bool {
	exempt := map[ast.Node]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.UnaryExpr:
			if node.Op == token.ARROW && isDoneCall(node.X) {
				exempt[node] = true
			}
		case *ast.SelectStmt:
			if selectOnlyWaitsForCancellation(node) {
				exempt[node] = true
			}
		}
		return true
	})
	return exempt
}

func isDoneCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Done"
}

// selectOnlyWaitsForCancellation requires at least one cancellation receive, so
// that "select {}" - which blocks forever and is unambiguously concurrency - is
// not swept in by a rule about empty clause lists.
func selectOnlyWaitsForCancellation(s *ast.SelectStmt) bool {
	waits := 0
	for _, stmt := range s.Body.List {
		clause, ok := stmt.(*ast.CommClause)
		if !ok {
			return false
		}
		if clause.Comm == nil {
			continue
		}
		if !isCancellationReceive(clause.Comm) {
			return false
		}
		waits++
	}
	return waits > 0
}

func isCancellationReceive(comm ast.Stmt) bool {
	var expr ast.Expr
	switch s := comm.(type) {
	case *ast.ExprStmt:
		expr = s.X
	case *ast.AssignStmt:
		if len(s.Rhs) != 1 {
			return false
		}
		expr = s.Rhs[0]
	default:
		return false
	}
	unary, ok := expr.(*ast.UnaryExpr)
	return ok && unary.Op == token.ARROW && isDoneCall(unary.X)
}
