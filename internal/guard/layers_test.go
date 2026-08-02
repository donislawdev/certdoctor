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
		// Wiring. It is allowed to see every layer because that is its job.
		location:       "cmd/",
		mayImportBelow: []string{"internal/core/", "internal/app/", "internal/adapter/"},
	},
}

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
var intraLayerEdges = map[string][]string{}

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
	internalPrefix := tr.modulePath + "/"

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

		fromPackage := path.Dir(sf.rel)
		for _, imp := range importsOf(sf) {
			if inside, isOurs := strings.CutPrefix(imp.path, internalPrefix); isOurs {
				if strings.HasPrefix(inside, rule.location) {
					if !edgeAllowed(fromPackage, inside) {
						findings = append(findings, Finding{
							File: sf.rel,
							Line: imp.line,
							Detail: fmt.Sprintf(
								"sideways import %s -> %s inside %s - declare it in intraLayerEdges or do not make it",
								fromPackage, inside, rule.location),
						})
					}
					continue
				}
				if !hasAnyPrefix(inside, rule.mayImportBelow) {
					findings = append(findings, Finding{
						File:   sf.rel,
						Line:   imp.line,
						Detail: fmt.Sprintf("%s may not import %s - that points upwards", rule.location, imp.path),
					})
				}
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
	}
	return sortFindings(findings)
}

// ruleFor returns the most specific rule covering a file.
func ruleFor(rel string) (layerRule, bool) {
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
