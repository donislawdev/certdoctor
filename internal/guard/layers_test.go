package guard

import (
	"fmt"
	"path"
	"strings"
	"testing"
)

// The layer map. Nothing points upwards: the core knows neither the orchestrator
// nor any adapter, and the orchestrator takes its ports as parameters rather
// than importing the things that implement them.
//
// A package that matches no prefix here is itself a finding. Without that the
// map would quietly stop covering the tree as new directories appear, and a
// guard covering less than it claims is worse than no guard.
var layerMap = []layerRule{
	{
		// The innermost layer. Nothing of ours sits below it.
		location:        "internal/core/",
		mayImportBelow:  nil,
		forbiddenStdlib: coreForbiddenStdlib,
	},
	{
		location:       "internal/app/",
		mayImportBelow: []string{"internal/core/"},
	},
	{
		location:       "internal/adapter/",
		mayImportBelow: []string{"internal/core/", "internal/app/"},
	},
	{
		// The guards check the repository, so they depend on nothing in it.
		location:       "internal/guard/",
		mayImportBelow: nil,
	},
	{
		// Wiring. It is allowed to see every layer because that is its job, and
		// it is the only thing allowed to reach the module root package.
		location:       "cmd/",
		mayImportBelow: []string{"internal/core/", "internal/app/", "internal/adapter/"},
		mayImportRoot:  true,
	},
}

// rootRule covers the package sitting directly in the module root.
//
// It is not in layerMap because it cannot be described by a path prefix: an
// empty prefix matches every file in the tree, which would turn the "outside
// the declared layer map" finding into something that can never fire.
//
// Why such a package exists at all: Go's embed directive cannot reach a parent
// directory, so the licence text at the repository root can only be embedded by
// a package beside it. That package carries the licence and the version and
// must stay a leaf - it imports nothing of ours, and only the entry point
// imports it.
var rootRule = layerRule{location: "", mayImportBelow: nil}

// intraLayerEdges lists the imports allowed BETWEEN packages of the same layer.
//
// 🔴 Sideways edges are forbidden by default, and this is the list of exceptions.
// It is empty, which is the correct state for four packages.
//
// Why the default is a ban rather than a permission. Two adapters importing each
// other is "the core does not know the interface" broken one floor down: a probe
// that reaches for the renderer decides how it will look, and the renderer stops
// being the single place that knows. The layer test would not see it, because
// the direction is technically not upwards.
//
// The exception list lives here rather than in prose, so that adding an edge in
// code without declaring it is visible. A sideways edge is sometimes right - it
// is never accidental.
var intraLayerEdges = map[string][]string{
	// The report is the structure assembled out of the core's three closed
	// vocabularies, so the arrow runs from it to them and can never run back:
	// none of the three knows a report exists.
	//
	// The alternative was one flat core package holding vocabularies and
	// structure together, which needs no declaration and gives up the thing the
	// declaration buys - the day somebody makes status depend on report, that
	// is a cycle the compiler catches, and the day somebody makes exitcode
	// depend on layer, this list is what catches it.
	"internal/core/report": {
		"internal/core/status",
		"internal/core/layer",
		"internal/core/exitcode",
	},
}

// coreForbiddenStdlib keeps the core a pure function of evidence: no network, no
// subprocess, no filesystem, no environment. Assessment has to be testable on
// recorded evidence, without a broken machine to reproduce.
//
// Deliberately NOT on this list: net/url and crypto/x509 parse without touching
// anything, and time carries durations that belong in evidence.
//
// This list is deliberately strict now. Relaxing it later is a visible act with
// a written reason, while a loose list never tightens on its own.
var coreForbiddenStdlib = []string{
	"net",
	"net/http",
	"os",
	"os/exec",
	"os/signal",
	"os/user",
	"syscall",
}

type layerRule struct {
	location        string
	mayImportBelow  []string
	forbiddenStdlib []string
	// mayImportRoot allows the module root package. It is a separate flag
	// rather than an entry in mayImportBelow because that list is matched by
	// prefix, and the root package's path is the module path itself - an empty
	// prefix, which would match everything and silence the whole check.
	mayImportRoot bool
}

// describe names a layer in a finding. The module root has no path prefix to
// name it by.
func (r layerRule) describe() string {
	if r.location == "" {
		return "the module root package"
	}
	return r.location
}

// TestLayerImportDirection is the guard for "nothing points upwards".
func TestLayerImportDirection(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoFindings(t, checkLayerDirection(tr), "layer direction")
}

// TestLayerGuardDetectsPlantedViolations is the canary. The tree is small enough
// today that the guard above would pass on an empty rule set, so the scanner is
// proved separately against violations that are known to be there.
func TestLayerGuardDetectsPlantedViolations(t *testing.T) {
	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files: []sourceFile{
			loadFixture(t, "layer_violation.go", "internal/core/status/planted.go"),
			loadFixture(t, "layer_violation.go", "internal/unmapped/planted.go"),
		},
	}
	findings := checkLayerDirection(tr)

	requireFinding(t, findings, "may not import github.com/donislawdev/certdoctor/internal/adapter/render")
	requireFinding(t, findings, `may not import "os/exec"`)
	requireFinding(t, findings, "outside the declared layer map")
}

// TestSidewaysImportsAreReportedUnlessDeclared covers the edge the direction
// rule cannot see: two packages of the same layer importing each other points
// neither up nor down.
func TestSidewaysImportsAreReportedUnlessDeclared(t *testing.T) {
	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "layer_sideways.go", "internal/adapter/probe/planted.go")},
	}
	requireFinding(t, checkLayerDirection(tr),
		"sideways import internal/adapter/probe -> internal/adapter/render")
}

// TestDeclaringASidewaysEdgeSilencesIt proves the exception list is the thing
// doing the silencing. Without this, the test above would still pass if the
// check ignored intraLayerEdges entirely and simply reported every same-layer
// import - and then a declared edge could never be made.
func TestDeclaringASidewaysEdgeSilencesIt(t *testing.T) {
	intraLayerEdges["internal/adapter/probe"] = []string{"internal/adapter/render"}
	defer delete(intraLayerEdges, "internal/adapter/probe")

	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "layer_sideways.go", "internal/adapter/probe/planted.go")},
	}
	requireNoFindings(t, checkLayerDirection(tr), "a declared sideways edge")
}

// TestTheModuleRootPackageMayNotReachIntoTheTree covers the leaf rule. The
// package beside LICENSE exists because embed cannot reach a parent directory,
// and for no other reason - the moment it imports part of the tree it becomes a
// wiring layer that no rule describes and that sits below every other one.
func TestTheModuleRootPackageMayNotReachIntoTheTree(t *testing.T) {
	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "root_reaches_in.go", "license.go")},
	}
	requireFinding(t, checkLayerDirection(tr), "the module root package may not import")
}

// TestOnlyTheEntryPointMayImportTheModuleRootPackage covers the branch that is
// invisible to the prefix test: the root package's import path is the module
// path itself, so without a case of its own it reads as somebody else's library
// and passes every check silently.
func TestOnlyTheEntryPointMayImportTheModuleRootPackage(t *testing.T) {
	forbidden := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "imports_the_module_root.go", "internal/core/status/planted.go")},
	}
	requireFinding(t, checkLayerDirection(forbidden), "may not import the module root package")

	allowed := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "imports_the_module_root.go", "cmd/certdoctor/planted.go")},
	}
	requireNoFindings(t, checkLayerDirection(allowed), "the entry point importing the module root package")
}

// TestAFileInTheModuleRootIsNotReportedAsUnmapped is the other half of the root
// rule. Without it the rule could be written to cover nothing and the guard
// would look identical from the outside.
func TestAFileInTheModuleRootIsNotReportedAsUnmapped(t *testing.T) {
	tr := mustLoadModule(t)
	seen := false
	for _, sf := range tr.files {
		if !strings.Contains(sf.rel, "/") {
			seen = true
		}
	}
	if !seen {
		t.Fatal("no file sits in the module root, so this test proves nothing about the rule that covers them")
	}
	requireNoFindings(t, checkLayerDirection(tr), "the module root")
}

// checkLayerDirection reports every declared import that crosses a layer
// boundary in the wrong direction, plus every package the layer map does not
// cover.
//
// What it does not see: an upward dependency expressed without an import - a
// build tag, a generated file, or agreement on a string constant. Direction of
// the import graph is what erodes one innocent line at a time, and that is what
// this catches.
func checkLayerDirection(tr tree) []Finding {
	var findings []Finding
	for _, sf := range tr.files {
		rule, ok := ruleFor(sf.rel)
		if !ok {
			findings = append(findings, Finding{
				File:   sf.rel,
				Line:   1,
				Detail: "this package sits outside the declared layer map - add it to layerMap or move the file",
			})
			continue
		}
		findings = append(findings, checkImportsOf(tr, sf, rule)...)
	}
	return sortFindings(findings)
}

// checkImportsOf sorts one file's imports into the three cases that need
// different rules: the module root package, something else of ours, and the
// standard library.
func checkImportsOf(tr tree, sf sourceFile, rule layerRule) []Finding {
	var findings []Finding
	internalPrefix := tr.modulePath + "/"

	for _, imp := range importsOf(sf) {
		// The module root package's import path is the module path itself, with
		// no trailing slash, so the prefix test below cannot see it. Left
		// unhandled it would be mistaken for a third party import and pass
		// every check.
		if imp.path == tr.modulePath {
			if !rule.mayImportRoot {
				findings = append(findings, Finding{
					File: sf.rel,
					Line: imp.line,
					Detail: fmt.Sprintf(
						"%s may not import the module root package - that package carries the embedded licence and the version, and only the entry point wires it in",
						rule.describe()),
				})
			}
			continue
		}
		if inside, isOurs := strings.CutPrefix(imp.path, internalPrefix); isOurs {
			findings = append(findings, checkOurImport(sf, rule, inside, imp)...)
			continue
		}
		for _, forbidden := range rule.forbiddenStdlib {
			if imp.path == forbidden {
				findings = append(findings, Finding{
					File:   sf.rel,
					Line:   imp.line,
					Detail: fmt.Sprintf("%s may not import %q - the core is a pure function of evidence", rule.location, imp.path),
				})
			}
		}
	}
	return findings
}

// checkOurImport judges one import of another package in this module: sideways,
// downwards, or upwards.
func checkOurImport(sf sourceFile, rule layerRule, inside string, imp declaredImport) []Finding {
	if rule.location == "" {
		return []Finding{{
			File: sf.rel,
			Line: imp.line,
			Detail: fmt.Sprintf(
				"the module root package may not import %s - it carries the embedded licence and nothing else, and a leaf that reaches into the tree is a second wiring layer nobody declared",
				imp.path),
		}}
	}

	fromPackage := path.Dir(sf.rel)
	if strings.HasPrefix(inside, rule.location) {
		if !edgeAllowed(fromPackage, inside) {
			return []Finding{{
				File: sf.rel,
				Line: imp.line,
				Detail: fmt.Sprintf(
					"sideways import %s -> %s inside %s - declare it in intraLayerEdges or do not make it",
					fromPackage, inside, rule.location),
			}}
		}
		return nil
	}
	if !hasAnyPrefix(inside, rule.mayImportBelow) {
		return []Finding{{
			File:   sf.rel,
			Line:   imp.line,
			Detail: fmt.Sprintf("%s may not import %s - that points upwards", rule.describe(), imp.path),
		}}
	}
	return nil
}

// ruleFor returns the most specific rule covering a file.
func ruleFor(rel string) (layerRule, bool) {
	// A file with no directory component sits in the module root. It is matched
	// here rather than by prefix, because the prefix that would match it is the
	// empty one and that matches everything.
	if !strings.Contains(rel, "/") {
		return rootRule, true
	}
	var best layerRule
	found := false
	for _, rule := range layerMap {
		if strings.HasPrefix(rel, rule.location) && len(rule.location) > len(best.location) {
			best, found = rule, true
		}
	}
	return best, found
}

// edgeAllowed reports whether a same-layer import was declared.
func edgeAllowed(fromPackage, toPackage string) bool {
	for _, allowed := range intraLayerEdges[fromPackage] {
		if allowed == toPackage {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
