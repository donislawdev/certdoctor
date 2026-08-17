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
// A package that matches no prefix here is itself a violation. Without that the
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
// the declared layer map" violation into something that can never fire.
//
// Why such a package exists at all: Go's embed directive cannot reach a parent
// directory, so the licence text at the repository root can only be embedded by
// a package beside it. That package carries the licence and the version and
// must stay a leaf - it imports nothing of ours, and only the entry point
// imports it.
var rootRule = layerRule{location: "", mayImportBelow: nil}

// intraLayerEdges lists the imports allowed BETWEEN packages of the same layer.
//
// Sideways edges are forbidden by default, and this is the list of exceptions.
// It had two entries when this sentence was last true of it and said it was
// empty - corrected 2026-08-05. A comment counting the thing below it is a
// comment that goes stale on the next edit, so this one no longer counts.
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
	// L0 builds findings and grades itself, so it needs the shape of a finding
	// and the vocabulary of statuses. The arrow runs one way and cannot run
	// back: neither report nor status knows a machine context exists.
	//
	// Why the assessment lives here at all, rather than in the orchestrator
	// where no edge would be needed. Working a verdict out of evidence is the
	// core's job - ADR7 - precisely so it can be tested on recorded evidence
	// instead of on a broken machine. Moving it one floor up would buy a shorter
	// list here and pay for it with the one rule that makes assessment testable.
	//
	// The alternative was for this package to declare its own variable type and
	// let the orchestrator turn it into a finding. That needs no declaration and
	// gives up more than it saves: a second description of a shape that is a
	// frozen public contract, and the choice of source moved to a layer that
	// never looked at the machine.
	"internal/core/machine": {
		"internal/core/report",
		"internal/core/status",
	},
	// L1 asks resolvers and grades what came back, so it needs the same two as
	// L0 plus the packet codec. The arrow runs one way and cannot run back: none
	// of the three knows a layer exists.
	//
	// WHY dnsmsg IS A SEPARATE PACKAGE AND THEREFORE A DECLARED EDGE, rather
	// than a file inside this one. It is the only code in this program that
	// parses bytes arriving from the network, and a boundary buys it a coverage
	// floor of its own, a fuzz target of its own, and the property that nothing
	// else in the tree can quietly grow a second way of reading a packet. The
	// alternative - folding it in here - needs no declaration and gives all three
	// of those up.
	"internal/core/resolve": {
		"internal/core/dnsmsg",
		"internal/core/report",
		"internal/core/status",
	},
	// L3 opens a connection per address and grades what came back, so it needs
	// the same two as L0 and L1 and nothing else. The arrow runs one way and
	// cannot run back.
	//
	// WHAT IS DELIBERATELY NOT HERE IS THE INTERESTING PART: this layer does
	// NOT import internal/core/resolve, although the addresses it connects to are
	// the ones L1 found. A layer importing the layer before it would turn a
	// pipeline into a chain welded at both ends - L3 would know how DNS answers
	// are shaped, and moving either would move both. The addresses arrive instead
	// as a function in this layer's own Input, which the entry point supplies, so
	// the two layers share a list of strings and no types at all.
	"internal/core/tcp": {
		"internal/core/report",
		"internal/core/status",
		// The shared fan-out. L3 and L4 make the same promise about the same
		// addresses - results placed by position, at most eight at a time, every
		// goroutine waited for - and ADR45 says that promise lives in ONE place
		// rather than being written out twice. A copy of a rule that already has
		// mutation entries disarms them and reports SKIP, which is the measured
		// shape of OBS50.
		"internal/core/fanout",
	},
	// The DNS plumbing takes a dialler and the dialler carries the rule about
	// where this program may connect, so the arrow runs from the thing that uses
	// a socket to the thing that decides whether it may have one. It cannot run
	// back: dial knows nothing about DNS and holds no net import of its own.
	//
	// The alternative was for the entry point to hand Exchange a bare function
	// instead of dial.Dialer. That needs no declaration and gives up the type
	// that says "this dialler has been through the guard" - and a bare func is
	// exactly what an unguarded one would look like too.
	//
	// The file port is the second edge and it is there for ONE call: on a
	// unix-like system this machine's resolvers are read out of /etc/resolv.conf,
	// and that path has to go through the port that judges it before anything
	// opens it. It is not an optional convenience - resolv.conf is a symbolic
	// link on WSL and on any systemd machine, and a link into a mount from
	// another host is a remote path wearing a local name.
	"internal/adapter/dns": {"internal/adapter/dial", "internal/adapter/file"},
}

// coreForbiddenStdlib keeps the core a pure function of evidence: no network, no
// subprocess, no filesystem, no environment. Assessment has to be testable on
// recorded evidence, without a broken machine to reproduce.
//
// Deliberately NOT on this list: net/url and crypto/x509 parse without touching
// anything, and time carries durations that belong in evidence.
//
// net/netip JOINED THAT SENTENCE ON 2026-08-05 AND IT WAS A DECISION, NOT AN
// OVERSIGHT. The check below compares import paths exactly, so "net" has never
// covered "net/netip" and the core could always have imported it - which is
// precisely why it is written down here now rather than used quietly. The package
// is address VALUES: parsing and formatting, no sockets, no name lookups, nothing
// that can block. The alternative was writing IPv6 text formatting by hand, with
// its zero-compression rules, inside the one package that reads hostile bytes off
// the network.
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

// describe names a layer in a violation. The module root has no path prefix to
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
	requireNoViolations(t, checkLayerDirection(tr), "layer direction")
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
	violations := checkLayerDirection(tr)

	requireViolation(t, violations, "may not import github.com/donislawdev/certdoctor/internal/adapter/render")
	requireViolation(t, violations, `may not import "os/exec"`)
	requireViolation(t, violations, "outside the declared layer map")
}

// TestSidewaysImportsAreReportedUnlessDeclared covers the edge the direction
// rule cannot see: two packages of the same layer importing each other points
// neither up nor down.
func TestSidewaysImportsAreReportedUnlessDeclared(t *testing.T) {
	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "layer_sideways.go", "internal/adapter/probe/planted.go")},
	}
	requireViolation(t, checkLayerDirection(tr),
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
	requireNoViolations(t, checkLayerDirection(tr), "a declared sideways edge")
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
	requireViolation(t, checkLayerDirection(tr), "the module root package may not import")
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
	requireViolation(t, checkLayerDirection(forbidden), "may not import the module root package")

	allowed := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "imports_the_module_root.go", "cmd/certdoctor/planted.go")},
	}
	requireNoViolations(t, checkLayerDirection(allowed), "the entry point importing the module root package")
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
	requireNoViolations(t, checkLayerDirection(tr), "the module root")
}

// checkLayerDirection reports every declared import that crosses a layer
// boundary in the wrong direction, plus every package the layer map does not
// cover.
//
// What it does not see: an upward dependency expressed without an import - a
// build tag, a generated file, or agreement on a string constant. Direction of
// the import graph is what erodes one innocent line at a time, and that is what
// this catches.
func checkLayerDirection(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		rule, ok := ruleFor(sf.rel)
		if !ok {
			violations = append(violations, Violation{
				File:   sf.rel,
				Line:   1,
				Detail: "this package sits outside the declared layer map - add it to layerMap or move the file",
			})
			continue
		}
		violations = append(violations, checkImportsOf(tr, sf, rule)...)
	}
	return sortViolations(violations)
}

// checkImportsOf sorts one file's imports into the three cases that need
// different rules: the module root package, something else of ours, and the
// standard library.
func checkImportsOf(tr tree, sf sourceFile, rule layerRule) []Violation {
	var violations []Violation
	internalPrefix := tr.modulePath + "/"

	for _, imp := range importsOf(sf) {
		// The module root package's import path is the module path itself, with
		// no trailing slash, so the prefix test below cannot see it. Left
		// unhandled it would be mistaken for a third party import and pass
		// every check.
		if imp.path == tr.modulePath {
			if !rule.mayImportRoot {
				violations = append(violations, Violation{
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
			violations = append(violations, checkOurImport(sf, rule, inside, imp)...)
			continue
		}
		for _, forbidden := range rule.forbiddenStdlib {
			if imp.path == forbidden {
				violations = append(violations, Violation{
					File:   sf.rel,
					Line:   imp.line,
					Detail: fmt.Sprintf("%s may not import %q - the core is a pure function of evidence", rule.location, imp.path),
				})
			}
		}
	}
	return violations
}

// checkOurImport judges one import of another package in this module: sideways,
// downwards, or upwards.
func checkOurImport(sf sourceFile, rule layerRule, inside string, imp declaredImport) []Violation {
	if rule.location == "" {
		return []Violation{{
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
			return []Violation{{
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
		return []Violation{{
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
