package guard

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// concurrencyAllowlist names the files allowed to hold a concurrency primitive.
//
// It is empty, and that is the correct state today: there is no orchestrator, so
// the rule "no concurrency anywhere" is both true and checkable. The
// orchestrator's file is the first entry it ever gets, and adding that entry is
// the moment to re-read docs 22 section 2 - a probe is a synchronous function,
// and the core must not learn that anything runs in parallel.
var concurrencyAllowlist = map[string]bool{}

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

		for _, imp := range importsOf(sf) {
			if imp.path == "sync" || imp.path == "sync/atomic" {
				violations = append(violations, Violation{
					File:   sf.rel,
					Line:   imp.line,
					Detail: "import of \"" + imp.path + "\" - concurrency lives in the orchestrator alone",
				})
			}
		}

		ast.Inspect(sf.file, func(n ast.Node) bool {
			if exempt[n] {
				return true
			}
			switch node := n.(type) {
			case *ast.GoStmt:
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
