package guard

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"testing"
)

// TestEveryDoorInTheLayerMapIsUsed holds the architecture map to what the code
// does, in both directions - the rule the shape ratchet holds its numbers to
// (ADR132), applied to permissions. The direction guards say nothing may go
// through a wall. This one says no door may stand open that nothing goes
// through: a rule naming a directory with no file in it, a layer allowed to
// import another and never doing it, a sideways edge nobody uses, a standard
// library package on a closed list nobody imports, a place for the toolkit
// that draws nothing.
//
// WHY AN UNUSED DOOR IS A FAULT AND NOT SLACK. A permission is a decision, and
// one that nothing uses is a decision nobody is holding any more. It lets the
// next import through without anybody deciding it - and the comment beside it,
// written for an import that has gone, then explains an import that is not
// what it was about. Measured on the day this guard came: adapters were
// allowed the orchestrator and none of them ever imported it.
//
// What it does not see: whether a door that IS used should be. That is the
// reason written beside it, and only a person reads that.
func TestEveryDoorInTheLayerMapIsUsed(t *testing.T) {
	for _, door := range unusedDoors(mustLoadModule(t)) {
		t.Errorf("%s - close it: a permission nothing uses lets the next import through without anybody deciding it", door)
	}
}

// TestAnUnusedDoorIsReportedAndAUsedOneIsNot plants a tree that goes through
// some doors of every kind and leaves the others shut, and expects exactly the
// shut ones named. Without the second half the test would pass as well for a
// check that named every door there is.
func TestAnUnusedDoorIsReportedAndAUsedOneIsNot(t *testing.T) {
	planted := tree{modulePath: "github.com/donislawdev/certdoctor", files: []sourceFile{
		loadFixture(t, "uses_some_doors.go", "internal/core/report/planted.go"),
		loadFixture(t, "uses_some_doors.go", "cmd/certdoctor-gui/planted.go"),
		loadFixture(t, "uses_some_doors.go", "internal/gui/parts/doors.go"),
		loadFixture(t, "imports_toolkit.go", "internal/gui/parts/planted.go"),
	}}
	unused := strings.Join(unusedDoors(planted), "\n")

	for _, shut := range []string{
		"intraLayerEdges lets internal/core/report import internal/core/layer",
		"layerMap has a rule for internal/gui/fonts/ and no file stands under it",
		"internal/gui/parts/ may import internal/gui/model/ and no file under it does",
		"cmd/certdoctor-gui/ may import assets/icon/ and no file under it does",
		"cmd/certdoctor-gui/ may import the module root package and no file under it does",
		`closedStdlib lets internal/core/ import "regexp"`,
		"externalImportPlaces lets internal/gui/look/ import fyne.io/fyne/v2",
	} {
		if !strings.Contains(unused, shut) {
			t.Errorf("a door nothing uses was not named: %q. Named:\n%s", shut, unused)
		}
	}
	for _, open := range []string{
		"internal/core/report import internal/core/status",
		"layerMap has a rule for internal/core/ ",
		"may import internal/gui/ ",
		// One package named with its closing slash, matched with a slash added.
		"internal/gui/parts/ may import internal/gui/look/",
		`internal/core/ import "strings"`,
		"externalImportPlaces lets internal/gui/parts/",
	} {
		if strings.Contains(unused, open) {
			t.Errorf("a door the planted tree goes through was named as unused: %q", open)
		}
	}
}

// unusedDoors lists every permission in the layer map, the sideways edges, the
// closed standard library lists and the toolkit's places that no file of the
// tree goes through. Tests count as going through: the direction guards police
// them too.
func unusedDoors(tr tree) []string {
	byRule := map[string]map[string]bool{}
	byPackage := map[string]map[string]bool{}
	for _, sf := range tr.files {
		rule, mapped := ruleFor(sf.rel)
		if !mapped {
			continue // the direction guard reports it
		}
		addImports(byRule, rule.location, sf)
		addImports(byPackage, path.Dir(sf.rel), sf)
	}
	var unused []string
	unused = append(unused, unusedRules(tr.modulePath, byRule)...)
	unused = append(unused, unusedEdges(tr.modulePath, byPackage)...)
	unused = append(unused, unusedStdlib(byRule)...)
	unused = append(unused, unusedPlaces(tr)...)
	sort.Strings(unused)
	return unused
}

func addImports(into map[string]map[string]bool, key string, sf sourceFile) {
	if into[key] == nil {
		into[key] = map[string]bool{}
	}
	for _, imp := range importsOf(sf) {
		into[key][imp.path] = true
	}
}

// unusedRules names the rules that cover no file and the permissions of a rule
// that no file it covers uses.
func unusedRules(module string, byRule map[string]map[string]bool) []string {
	var unused []string
	for _, rule := range layerMap {
		imports, covers := byRule[rule.location]
		if !covers {
			unused = append(unused, fmt.Sprintf("layerMap has a rule for %s and no file stands under it", rule.location))
			continue
		}
		for _, below := range rule.mayImportBelow {
			if !importsUnder(imports, module, below) {
				unused = append(unused, fmt.Sprintf("%s may import %s and no file under it does", rule.location, below))
			}
		}
		if rule.mayImportRoot && !imports[module] {
			unused = append(unused, fmt.Sprintf("%s may import the module root package and no file under it does", rule.location))
		}
	}
	return unused
}

// importsUnder says whether one of these imports is a package of ours that a
// permission matches - with a slash added, the way checkOurImport matches it.
func importsUnder(imports map[string]bool, module, permission string) bool {
	for imp := range imports {
		if inside, isOurs := strings.CutPrefix(imp, module+"/"); isOurs && strings.HasPrefix(inside+"/", permission) {
			return true
		}
	}
	return false
}

// unusedEdges names the declared sideways edges no file of the importing
// package uses.
func unusedEdges(module string, byPackage map[string]map[string]bool) []string {
	var unused []string
	for from, tos := range intraLayerEdges {
		for _, to := range tos {
			if !byPackage[from][module+"/"+to] {
				unused = append(unused, fmt.Sprintf("intraLayerEdges lets %s import %s and no file there does", from, to))
			}
		}
	}
	return unused
}

// unusedStdlib names the packages on a closed list that no file of the layer
// imports.
func unusedStdlib(byRule map[string]map[string]bool) []string {
	var unused []string
	for location, closed := range closedStdlib {
		for _, pkg := range closed.packages {
			if !byRule[location][pkg] {
				unused = append(unused, fmt.Sprintf("closedStdlib lets %s import %q and no file there does", location, pkg))
			}
		}
	}
	return unused
}

// unusedPlaces names the places of the toolkit pair where no production file
// imports the toolkit. Tests do not count here, because the pair does not
// police them.
func unusedPlaces(tr tree) []string {
	var unused []string
	for _, p := range externalImportPlaces {
		for _, dir := range p.under {
			if !anyFileImports(tr, dir, p.module) {
				unused = append(unused, fmt.Sprintf("externalImportPlaces lets %s import %s and no file there does", dir, p.module))
			}
		}
	}
	return unused
}

func anyFileImports(tr tree, dir, module string) bool {
	for _, sf := range tr.files {
		if sf.isTest || !strings.HasPrefix(sf.rel, dir) {
			continue
		}
		for _, imp := range importsOf(sf) {
			if imp.path == module || strings.HasPrefix(imp.path, module+"/") {
				return true
			}
		}
	}
	return false
}
