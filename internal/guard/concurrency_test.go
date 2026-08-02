package guard

import (
	"go/ast"
	"go/token"
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
	requireNoFindings(t, checkConcurrencyContainment(tr), "concurrency outside the orchestrator")
}

// TestConcurrencyGuardDetectsPlantedViolations is the canary. With zero
// goroutines in the tree the guard above cannot tell "contained" from "blind".
func TestConcurrencyGuardDetectsPlantedViolations(t *testing.T) {
	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "concurrency_violation.go", "internal/adapter/probe/planted.go")},
	}
	findings := checkConcurrencyContainment(planted)

	for _, want := range []string{
		"go statement",
		"select statement",
		"channel send",
		"channel type",
		"channel receive",
		`import of "sync"`,
		`import of "sync/atomic"`,
	} {
		requireFinding(t, findings, want)
	}
}

// checkConcurrencyContainment reports every concurrency primitive outside the
// allowlist.
//
// What it does not see:
//
//   - test files, which are skipped. A concurrency test needs goroutines.
//   - time.After, time.Tick and context cancellation, which schedule work
//     without naming any of the primitives below.
//   - a package that hides a goroutine behind a helper of its own, once such a
//     helper exists inside the allowlist.
func checkConcurrencyContainment(tr tree) []Finding {
	var findings []Finding

	for _, sf := range tr.files {
		if sf.isTest || concurrencyAllowlist[sf.rel] {
			continue
		}
		report := func(pos token.Pos, what string) {
			findings = append(findings, Finding{
				File:   sf.rel,
				Line:   sf.fset.Position(pos).Line,
				Detail: what + " - concurrency lives in the orchestrator alone, so that the core never learns anything runs in parallel",
			})
		}

		for _, imp := range importsOf(sf) {
			if imp.path == "sync" || imp.path == "sync/atomic" {
				findings = append(findings, Finding{
					File:   sf.rel,
					Line:   imp.line,
					Detail: "import of \"" + imp.path + "\" - concurrency lives in the orchestrator alone",
				})
			}
		}

		ast.Inspect(sf.file, func(n ast.Node) bool {
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
	return sortFindings(findings)
}
