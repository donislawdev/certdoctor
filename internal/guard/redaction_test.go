package guard

import (
	"fmt"
	"strings"
	"testing"
)

// redactionPackage is the import path this guard is about.
const redactionPackage = "github.com/donislawdev/certdoctor/internal/core/redact"

// redactionCallers are the packages allowed to reach the masking function.
//
// ADR18. Masking runs on the assembly path and nowhere else: probes hand back
// RAW evidence and the orchestrator masks it once, in order, after the work is
// collected. A layer never masks its own output.
//
// WHY THAT IS A RULE AND NOT A PREFERENCE. A Redaction holds three maps and no
// lock. The fan-out this program is heading for lives INSIDE a layer - one
// branch per resolved address in L3, one per probe in L5 - so two branches
// calling it would write to the same map at the same time. A racing map in Go is
// not a wrong value, it is `fatal error: concurrent map writes`, which recover
// cannot catch: the process dies with no report and with a status that is not in
// the exit code table. It would land on machines with many addresses and many
// runtimes, which are exactly the machines L5 exists for.
//
// The alternative was a mutex, and it was rejected: it needs this file on the
// concurrency allowlist, which takes that guard off it permanently and spends
// ADR15's first entry somewhere it did not intend.
var redactionCallers = map[string]bool{
	"github.com/donislawdev/certdoctor/internal/app/run":     true,
	"github.com/donislawdev/certdoctor/cmd/certdoctor":       true,
	"github.com/donislawdev/certdoctor/internal/core/redact": true,
}

// TestOnlyTheAssemblyPathImportsRedaction is written BEFORE the wiring exists.
//
// That is the whole point and it is the one moment at which it can be written
// without first finding the rule already broken. Nothing imports the masking
// package today, so this passes over an empty set - which is why the canary
// below matters more than the pass does.
func TestOnlyTheAssemblyPathImportsRedaction(t *testing.T) {
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("the module could not be read: %v", err)
	}
	requireNoViolations(t, checkRedactionCallers(tr), "an import of the masking package")
}

// TestTheRedactionGuardCanFail is the canary, and on this tree it carries more
// weight than the pass above.
//
// Nothing imports the masking package yet, so the check runs over an empty set
// and would look identical if it read nothing at all. The fixture stands in for
// a layer that decided to mask its own evidence.
func TestTheRedactionGuardCanFail(t *testing.T) {
	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "imports_redaction.go", "internal/adapter/probe/planted.go")},
	}
	requireViolation(t, checkRedactionCallers(planted), "may not import the masking package")

	// The other side of the rule: the assembly path is allowed to, and a guard
	// that refused everything would pass the check above while being useless.
	allowed := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "imports_redaction.go", "internal/app/run/planted.go")},
	}
	requireNoViolations(t, checkRedactionCallers(allowed), "the orchestrator importing the masking package")
}

// checkRedactionCallers reports every package outside the list that declares an
// import of the masking package.
//
// It reads what a file DECLARES rather than what the build links, for the same
// reason the layer guard does: the rule erodes one innocent looking import at a
// time, each of them unused on the day it was added.
func checkRedactionCallers(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest {
			continue
		}
		owner := packageOf(tr, sf)
		if redactionCallers[owner] {
			continue
		}
		for _, declared := range importsOf(sf) {
			if declared.path != redactionPackage {
				continue
			}
			violations = append(violations, Violation{sf.rel, declared.line, fmt.Sprintf(
				"%s may not import the masking package - ADR18 puts masking on the assembly path, "+
					"because a Redaction holds unsynchronised maps and a layer is where the fan-out will be", owner)})
		}
	}
	return sortViolations(violations)
}

// packageOf is the import path of the package a file belongs to.
func packageOf(tr tree, sf sourceFile) string {
	dir := strings.TrimSuffix(sf.rel, "/"+lastSegment(sf.rel))
	if dir == sf.rel {
		return tr.modulePath
	}
	return tr.modulePath + "/" + dir
}

func lastSegment(rel string) string {
	if at := strings.LastIndex(rel, "/"); at >= 0 {
		return rel[at+1:]
	}
	return rel
}
