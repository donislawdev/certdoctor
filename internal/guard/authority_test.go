package guard

import (
	"fmt"
	"go/ast"
	"testing"
)

// authorityAllowlist names the files allowed to decide who signed a chain and
// how widely this machine holds that signer.
//
// WHY THIS LIST EXISTS, AND WHY THE NUMBER WORTH DEFENDING IS ONE. This is the
// judgement inviolable rule 21 calls harm when it is wrong: telling somebody
// their traffic is being intercepted when it is not. It is safe to make only
// when several facts are weighed TOGETHER - which stores were actually
// assessed, which of them hold an anchor that closes this chain, and which
// refused it for the one reason that says anything about the signer. A second
// place weighing them is a second place where three of the four could be
// weighed, and the sentence it produced would read identically.
//
// IT IS THE MEASURED SHAPE OF OBS50 RATHER THAN A PRECAUTION. Four times in
// this tree a rule got a second home while somebody was tidying up, and every
// time the mutation register reported it as a SKIP: entries that still passed
// and had stopped proving anything. This list makes the second home a red test.
//
// THE ENTRY WAS WRITTEN BEFORE THE FILE EXISTED - the same order execAllowlist
// and remediationAllowlist were built in, and for the same reason: a guard
// added after the code it covers arrives to find the rule already broken, and
// the only moment it can be seen to bite is while the path is still empty.
//
// IT SKIPS TEST FILES, unlike the certificate-verification scanner and for the
// reason OBS5 records: a test of a renderer legitimately needs one of these to
// render, and a fixture is not a second rule.
var authorityAllowlist = map[string]bool{
	// The one place. The counting rule, the three holdings it can answer and
	// the careful sentence attached to each live together, so that reading one
	// is reading the others.
	"internal/core/trust/authority.go": true,
}

// TestNothingOutsideTheAllowlistJudgesASigningAuthority is the rule turned into
// something a machine can check.
func TestNothingOutsideTheAllowlistJudgesASigningAuthority(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkAuthority(tr), "a signing authority judged outside the allowlist")
}

// TestTheAuthorityGuardCanFail is the canary.
//
// Without it this check would look identical whether it read every file in the
// tree or none of them, and it passes today partly BECAUSE the allowlist says
// so - the shape that hides a scanner having quietly stopped scanning.
//
// It names BOTH shapes rather than counting them. A count passes just as well
// when the wrong half survives, and a scanner that recognised only a qualified
// report.SigningAuthority would walk past a package that had declared its own.
func TestTheAuthorityGuardCanFail(t *testing.T) {
	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "judges_an_authority.go", "internal/core/trust/planted.go")},
	}
	violations := checkAuthority(tr)
	requireViolation(t, violations, "may not judge who signed a chain")

	if len(violations) != 2 {
		t.Errorf("reported %d violations and the fixture plants two - a qualified type and a bare one: %v",
			len(violations), violations)
	}
}

// TestTheAuthorityAllowlistNamesFilesThatExist is the shape this tree already
// carries for six other lists, applied to a seventh - OBS63.
//
// An entry pointing at a file that does not exist is an exemption lying in
// ambush: it costs nothing while the path is empty and starts excusing whatever
// appears there later, under a name chosen for entirely different reasons, by
// somebody who never read the decision that granted it.
func TestTheAuthorityAllowlistNamesFilesThatExist(t *testing.T) {
	tr := mustLoadModule(t)
	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for named := range authorityAllowlist {
		if !present[named] {
			t.Errorf("the authority allowlist names %q, and no such file is in this module - "+
				"an exemption for a file that does not exist excuses whatever takes that name next", named)
		}
	}
}

// checkAuthority reports every product file outside the allowlist that builds a
// value whose type is named SigningAuthority.
//
// IT READS THE NAME RATHER THAN RESOLVING THE TYPE, which is what makes it
// cheap and total. A package that declared its own SigningAuthority in order to
// write a second counting rule is exactly the case worth catching, and it would
// type check perfectly.
//
// WHAT IT DOES NOT SEE, said here rather than discovered later: a sentence
// about interception assembled into a plain string and printed. This guard
// defends the ONE decision that the judgement is made in one place, not the
// general property that nothing else can word an accusation - and the general
// property has no scanner. What does defend it is the contract in report, which
// refuses a finding whose holding and whose store lists disagree.
func checkAuthority(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || authorityAllowlist[sf.rel] {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !namesSigningAuthority(lit.Type) {
				return true
			}
			violations = append(violations, Violation{sf.rel, sf.fset.Position(lit.Pos()).Line, fmt.Sprintf(
				"%s may not judge who signed a chain - saying that an authority is local to this machine is the "+
					"claim inviolable rule 21 calls harm when it is wrong, and the facts that make it safe to "+
					"make live in one file so that they cannot be weighed three out of four anywhere else", sf.rel)})
			return true
		})
	}
	return sortViolations(violations)
}

// namesSigningAuthority reports whether a composite literal's type is spelled
// SigningAuthority, qualified by a package or not.
func namesSigningAuthority(expr ast.Expr) bool {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name == "SigningAuthority"
	case *ast.SelectorExpr:
		return typed.Sel != nil && typed.Sel.Name == "SigningAuthority"
	case *ast.StarExpr:
		return namesSigningAuthority(typed.X)
	}
	return false
}
