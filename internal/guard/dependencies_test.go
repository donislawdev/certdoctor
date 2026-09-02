package guard

import (
	"strings"
	"testing"
)

// externalImportAllowlist names the files allowed to import a module from
// outside this repository.
//
// WHY THIS GUARD EXISTS, AND WHY IT ARRIVED ONLY NOW. Until 2026-09-02 this
// program had no dependency at all, so "the core is a pure function of evidence"
// was held up by there being nothing to import. Measured that day while adding
// the first one: the layer guard sorts imports into the module root, our own
// packages and the standard library, and anything else FALLS THROUGH EVERY CHECK
// - a third-party import is legal in every layer, including internal/core.
//
// WHAT tools/expected-modules.txt DOES AND DOES NOT COVER. That gate answers
// WHETHER a module may be in this build. It cannot answer WHERE it may be
// imported, because it reads go list rather than our source. So a future session
// could import goja into the core and every gate in the repository would stay
// green while the layer that must stay testable on recorded evidence started
// carrying a JavaScript engine.
//
// THE LIST IS FILES RATHER THAN A LAYER RULE, deliberately. "The adapter may"
// would permit the next dependency in any adapter without anybody deciding,
// which is exactly how a dependency arrives - as somebody else's transitive
// import in a diff that looks like it only touched go.sum.
var externalImportAllowlist = map[string]bool{
	// The PAC sandbox, and the only place in this program that executes
	// somebody else's code - ADR8. goja is the engine; nothing else here
	// touches it, and internal/core/pac holds the twelve helper functions
	// precisely so they can be checked with no engine in sight.
	"internal/adapter/pac/sandbox.go":   true,
	"internal/adapter/pac/inject.go":    true,
	"internal/adapter/pac/stopwatch.go": true,
}

// TestOnlyAllowlistedFilesImportSomebodyElsesModule is the guard.
func TestOnlyAllowlistedFilesImportSomebodyElsesModule(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkExternalImports(tr), "a dependency imported outside the files that declare it")
}

// TestTheExternalImportGuardCanFail is the canary. With one dependency in a tree
// of thirty packages, the guard above cannot tell "contained" from "blind".
func TestTheExternalImportGuardCanFail(t *testing.T) {
	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "imports_outside.go", "internal/core/planted.go")},
	}
	violations := checkExternalImports(planted)

	// Both are named, because a guard that catches one dependency and misses
	// another is worse than none: it reads as coverage.
	requireViolation(t, violations, "github.com/dop251/goja")
	requireViolation(t, violations, "golang.org/x/text/language")

	// The standard library import in the same fixture must NOT be reported.
	// Without this the test would pass just as well for a guard that flags
	// every import there is.
	for _, v := range violations {
		if strings.Contains(v.Detail, "strings") {
			t.Errorf("the standard library was reported as an outside dependency: %s", v.Detail)
		}
	}
}

// TestAnAllowlistedFileMayImportSomebodyElsesModule pins the other side, so the
// exemption cannot quietly stop working and leave the list decorative.
func TestAnAllowlistedFileMayImportSomebodyElsesModule(t *testing.T) {
	const planted = "internal/adapter/pac/planted.go"
	externalImportAllowlist[planted] = true
	defer delete(externalImportAllowlist, planted)

	allowed := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "imports_outside.go", planted)},
	}
	requireNoViolations(t, checkExternalImports(allowed), "an allowlisted file must be allowed to import its dependency")
}

// TestTheExternalImportAllowlistNamesFilesThatExist keeps the list from rotting,
// the same shape the concurrency lists carry: an entry pointing at a file nobody
// wrote is an exemption lying in wait.
func TestTheExternalImportAllowlistNamesFilesThatExist(t *testing.T) {
	tr := mustLoadModule(t)

	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for entry := range externalImportAllowlist {
		if !present[entry] {
			t.Errorf("externalImportAllowlist excuses %q, and there is no such file in this module", entry)
		}
	}
}

// checkExternalImports reports every import of a module outside this repository
// from a file that is not on the allowlist.
//
// HOW AN OUTSIDE MODULE IS RECOGNISED: the first segment of its import path
// carries a dot. That is the rule the go command itself uses - a standard
// library path never has one, because a dot there would make it a domain. It is
// worth stating rather than reading off, because "contains a dot anywhere" would
// also match our own paths and every stdlib path with a version suffix.
//
// Test files are skipped. A test may reach for a dependency to check what this
// program does with it, which is what the tests beside the sandbox do.
func checkExternalImports(tr tree) []Violation {
	var violations []Violation
	internalPrefix := tr.modulePath + "/"

	for _, sf := range tr.files {
		if sf.isTest || externalImportAllowlist[sf.rel] {
			continue
		}
		for _, imp := range importsOf(sf) {
			if imp.path == tr.modulePath || strings.HasPrefix(imp.path, internalPrefix) {
				continue
			}
			first, _, _ := strings.Cut(imp.path, "/")
			if !strings.Contains(first, ".") {
				continue
			}
			violations = append(violations, Violation{
				File: sf.rel,
				Line: imp.line,
				Detail: "import of " + imp.path +
					" - a module from outside this repository may only be imported by a file on externalImportAllowlist, so that adding one is a decision rather than a diff that looks like it touched go.sum",
			})
		}
	}
	return sortViolations(violations)
}
