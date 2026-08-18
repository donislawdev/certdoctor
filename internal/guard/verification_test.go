package guard

import (
	"fmt"
	"go/ast"
	"testing"
)

// verificationAllowlist names the files allowed to switch certificate
// verification off.
//
// WHY THIS LIST EXISTS AT ALL, AND WHY IT IS ONE ENTRY LONG. InsecureSkipVerify
// in a security tool is the single line most likely to be read as a defect and
// "fixed" by somebody being helpful - at which point L4 stops producing evidence
// in exactly the scenario it was built for, and every test stays green because
// nothing else asserts on a broken chain. ADR46 decided the flag belongs here;
// this list is what keeps that decision from spreading and from being reversed
// by accident.
//
// AN ENTRY HERE IS NOT A FORMALITY. It means one more place in this program that
// will accept any certificate at all. The number worth defending is one.
//
// IT COVERS TEST FILES TOO, unlike the concurrency, appearance and layer
// scanners. Those skip tests because a test legitimately needs the primitive it
// is testing; nothing here does. A test wanting this flag would be a test
// arranging the exact state the product is not allowed to be in, and it should
// arrive as a decision on this list rather than as a file the scanner never read
// - which is the blind spot OBS5 records about the other three.
var verificationAllowlist = map[string]bool{
	// The one place, added 2026-08-17 with the code it covers - ADR46. Ordinary
	// verification aborts the handshake on a broken chain and leaves NOT ONE
	// certificate to show, and the evidence is what this product sells. The
	// verdict L4 reaches from those bytes is structural and consults no trust
	// store, so nothing here is trusted merely because it was accepted.
	"internal/adapter/handshake/handshake.go": true,
}

// TestNothingOutsideTheAllowlistSkipsCertificateVerification is ADR46 turned into
// something a machine can check.
func TestNothingOutsideTheAllowlistSkipsCertificateVerification(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkCertificateVerification(tr), "certificate verification switched off outside the allowlist")
}

// TestTheVerificationGuardCanFail is the canary.
//
// Without it the check above would look identical whether it read every file in
// the tree or none of them - and it passes today partly BECAUSE the allowlist
// says so, which is exactly the shape that hides a scanner having quietly
// stopped scanning.
//
// It names BOTH shapes rather than counting, because a count passes just as well
// when the wrong half survives: a scanner reading composite literals and not
// assignments would leave a hole the size of one line of setup code.
func TestTheVerificationGuardCanFail(t *testing.T) {
	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "skips_verification.go", "internal/adapter/probe/planted.go")},
	}
	violations := checkCertificateVerification(tr)
	requireViolation(t, violations, "may not switch certificate verification off")

	if len(violations) != 2 {
		t.Errorf("reported %d violations and the fixture plants two - a literal and an assignment: %v",
			len(violations), violations)
	}
}

// TestTheVerificationAllowlistNamesFilesThatExist is the shape this tree already
// carries for its other lists, applied to a fourth family - OBS63.
//
// An entry pointing at a file that does not exist is an exemption lying in
// ambush: it costs nothing while the path is empty and starts excusing whatever
// appears there later, under a name chosen for entirely different reasons, by
// somebody who never read the decision that granted it.
func TestTheVerificationAllowlistNamesFilesThatExist(t *testing.T) {
	tr := mustLoadModule(t)
	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for named := range verificationAllowlist {
		if !present[named] {
			t.Errorf("the verification allowlist names %q, and no such file is in this module - "+
				"an exemption for a file that does not exist excuses whatever takes that name next", named)
		}
	}
}

// checkCertificateVerification reports every file outside the allowlist that
// names InsecureSkipVerify.
//
// IT READS THE IDENTIFIER RATHER THAN THE TYPE, which is deliberate and is what
// makes it cheap and total. Anything spelling that name is either setting the
// field, reading it, or defining something confusable with it, and all three are
// worth a line in a review of this program.
//
// WHAT IT DOES NOT SEE, said here rather than discovered later: every OTHER way
// to accept a certificate nobody should. A VerifyPeerCertificate that returns
// nil, a RootCAs pool built from somewhere odd, or a Config assembled in a
// package that never names the field - all pass. This guard defends ONE decision
// (ADR46) rather than the general property, and the general property has no
// scanner. It has L5, which is a layer rather than a guard.
func checkCertificateVerification(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if verificationAllowlist[sf.rel] {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok || ident.Name != "InsecureSkipVerify" {
				return true
			}
			violations = append(violations, Violation{sf.rel, sf.fset.Position(ident.Pos()).Line, fmt.Sprintf(
				"%s may not switch certificate verification off - ADR46 puts that in one file so that L4 can keep "+
					"showing a broken chain as evidence, and every other file accepting any certificate would be a "+
					"security tool quietly trusting anything", sf.rel)})
			return true
		})
	}
	return sortViolations(violations)
}
