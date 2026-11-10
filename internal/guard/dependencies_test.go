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
	// The system dialog of a window the toolkit could not open (ADR125 point
	// 1), through golang.org/x/sys/windows - a typed MessageBox loading
	// user32.dll from the system directory, so the file holds no unsafe. The
	// toolkit already links the module into the window. The owner's decision
	// (ADR127).
	"cmd/certdoctor-gui/dialog_windows.go": true,
	// The dark title bar of the window on Windows, through the same module's
	// typed DwmSetWindowAttribute, which loads dwmapi.dll from the system
	// directory - a file of its own because it is on unsafeAllowlist too. The
	// owner's decision (2026-11-10, ADR122).
	"cmd/certdoctor-gui/titlebar_windows.go": true,
}

// externalImportPlaces names the one module allowed under a directory rather
// than file by file - the window's toolkit - and the directories it may be
// imported under.
//
// WHY A SECOND RULE NEXT TO THE LIST, decided by the owner on 2026-11-03
// (ADR124 (h)). The toolkit is imported by most files of the window, so on the
// list each new file of the window would be an edit to this guard, and an
// edit made that often is one people learn to approve without reading. A pair
// keeps what the list is for: the module is named, the place is named, and
// the same module anywhere else, or any other module here, is still reported.
// It is not a layer rule - "the window may import anything" is exactly the
// rule the comment above the list turns down.
var externalImportPlaces = []struct {
	module string
	under  []string
}{
	{module: "fyne.io/fyne/v2", under: []string{"internal/gui/", "cmd/certdoctor-gui/"}},
}

// placeAllows says whether this file may import this path by the rule above.
func placeAllows(rel, importPath string) bool {
	for _, p := range externalImportPlaces {
		if importPath != p.module && !strings.HasPrefix(importPath, p.module+"/") {
			continue
		}
		for _, dir := range p.under {
			if strings.HasPrefix(rel, dir) {
				return true
			}
		}
	}
	return false
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

// TestTheToolkitIsAllowedOnlyWhereItsPairSays holds the pair to both of its
// halves: the toolkit is reported outside the window's directories, accepted
// inside them, and another module inside them is still reported.
func TestTheToolkitIsAllowedOnlyWhereItsPairSays(t *testing.T) {
	const module = "github.com/donislawdev/certdoctor"
	inCore := tree{modulePath: module, files: []sourceFile{loadFixture(t, "imports_toolkit.go", "internal/core/planted.go")}}
	requireViolation(t, checkExternalImports(inCore), "fyne.io/fyne/v2/widget")

	for _, rel := range []string{"internal/gui/planted.go", "cmd/certdoctor-gui/planted.go"} {
		inWindow := tree{modulePath: module, files: []sourceFile{loadFixture(t, "imports_toolkit.go", rel)}}
		requireNoViolations(t, checkExternalImports(inWindow), "the toolkit under "+rel)
	}

	// A directory whose name only begins like the window's is not the window.
	beside := tree{modulePath: module, files: []sourceFile{loadFixture(t, "imports_toolkit.go", "internal/guiplanted/planted.go")}}
	requireViolation(t, checkExternalImports(beside), "fyne.io/fyne/v2")

	other := tree{modulePath: module, files: []sourceFile{loadFixture(t, "imports_outside.go", "internal/gui/planted.go")}}
	requireViolation(t, checkExternalImports(other), "github.com/dop251/goja")
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
			if !strings.Contains(first, ".") || placeAllows(sf.rel, imp.path) {
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
