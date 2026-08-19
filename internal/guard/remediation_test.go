package guard

import (
	"fmt"
	"go/ast"
	"testing"
)

// remediationAllowlist names the files allowed to build a remediation command.
//
// WHY THIS LIST EXISTS, AND WHY THE NUMBER WORTH DEFENDING IS ONE. A fix is the
// one thing this program produces that a person RUNS on their own machine, and
// whether it is safe to produce depends on three facts checked together: the
// store is a file we opened, the chain the server sent was structurally
// complete, and the reason this store refused it was an unknown authority. A
// second place building a Fix is a second place where two of those three could
// be checked - and the row would look identical.
//
// IT IS THE MEASURED SHAPE OF OBS50 RATHER THAN A PRECAUTION. Four times in this
// tree a rule got a second home while somebody was tidying up, and every time
// the mutation register reported it as a SKIP: entries that still passed and had
// stopped proving anything. This list makes the second home a red test instead.
//
// IT SKIPS TEST FILES, unlike the certificate-verification scanner and for the
// reason OBS5 records: a test of a renderer legitimately needs a Fix to render,
// and a fixture is not a second rule. What it must never skip is the product.
var remediationAllowlist = map[string]bool{
	// The one place, added 2026-08-19 with the code it covers. The templates and
	// the three conditions that gate them live together, so that reading one is
	// reading the other.
	"internal/core/trust/fix.go": true,
}

// TestNothingOutsideTheAllowlistBuildsARemediationCommand is the rule turned
// into something a machine can check.
func TestNothingOutsideTheAllowlistBuildsARemediationCommand(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkRemediation(tr), "a remediation command built outside the allowlist")
}

// TestTheRemediationGuardCanFail is the canary.
//
// Without it this check would look identical whether it read every file in the
// tree or none of them, and it passes today partly BECAUSE the allowlist says
// so - the shape that hides a scanner having quietly stopped scanning.
//
// It names BOTH shapes rather than counting them. A count passes just as well
// when the wrong half survives, and a scanner that recognised only a qualified
// report.Fix would walk past a package that had declared its own.
func TestTheRemediationGuardCanFail(t *testing.T) {
	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "builds_a_fix.go", "internal/core/trust/planted.go")},
	}
	violations := checkRemediation(tr)
	requireViolation(t, violations, "may not build a remediation command")

	if len(violations) != 2 {
		t.Errorf("reported %d violations and the fixture plants two - a qualified type and a bare one: %v",
			len(violations), violations)
	}
}

// TestTheRemediationAllowlistNamesFilesThatExist is the shape this tree already
// carries for five other lists, applied to a sixth - OBS63.
//
// An entry pointing at a file that does not exist is an exemption lying in
// ambush: it costs nothing while the path is empty and starts excusing whatever
// appears there later, under a name chosen for entirely different reasons, by
// somebody who never read the decision that granted it.
func TestTheRemediationAllowlistNamesFilesThatExist(t *testing.T) {
	tr := mustLoadModule(t)
	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for named := range remediationAllowlist {
		if !present[named] {
			t.Errorf("the remediation allowlist names %q, and no such file is in this module - "+
				"an exemption for a file that does not exist excuses whatever takes that name next", named)
		}
	}
}

// checkRemediation reports every product file outside the allowlist that builds
// a value whose type is named Fix.
//
// IT READS THE NAME RATHER THAN RESOLVING THE TYPE, which is what makes it cheap
// and total. A package that declared its own Fix in order to write a second set
// of templates is exactly the case worth catching, and it would type check
// perfectly.
//
// WHAT IT DOES NOT SEE, said here rather than discovered later: a command
// assembled into a plain string and handed on. This guard defends the ONE
// decision that remediation is built in one place, not the general property that
// nothing else prints a command - and the general property has no scanner.
func checkRemediation(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || remediationAllowlist[sf.rel] {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !namesFix(lit.Type) {
				return true
			}
			violations = append(violations, Violation{sf.rel, sf.fset.Position(lit.Pos()).Line, fmt.Sprintf(
				"%s may not build a remediation command - it is the one thing this program produces that somebody "+
					"RUNS, and the three conditions that make it safe to produce live in one file so that they "+
					"cannot be checked two out of three anywhere else", sf.rel)})
			return true
		})
	}
	return sortViolations(violations)
}

// namesFix reports whether a composite literal's type is spelled Fix, qualified
// by a package or not.
func namesFix(expr ast.Expr) bool {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name == "Fix"
	case *ast.SelectorExpr:
		return typed.Sel != nil && typed.Sel.Name == "Fix"
	case *ast.StarExpr:
		return namesFix(typed.X)
	}
	return false
}
