package guard

import (
	"fmt"
	"go/ast"
	"path"
	"strings"
	"testing"
)

// junkDrawerNames are package names that say where code was put rather than
// what it does. A package called util is the one place every later piece of
// code fits, so it is the one that grows without anybody deciding it should,
// and the layer map can say nothing about it because its name says nothing.
var junkDrawerNames = map[string]bool{
	"util": true, "utils": true, "common": true, "helper": true, "helpers": true,
	"misc": true, "shared": true, "base": true, "lib": true, "generic": true,
}

// TestEveryPackageKeepsItsHouseInOrder holds five rules, each of which every
// package of this tree met on the day it came (2026-11-11), so it costs nothing
// today and is what keeps a tree growing for decades readable to whoever comes
// next:
//
//   - every package says what it owns, in a package comment. A piece of code
//     that does not fit the sentence is the moment to make a new package, and
//     without the sentence that moment is invisible.
//   - importing a package does nothing by itself: no func init, and no blank
//     import outside a test except embed. What runs is wired by an entry point,
//     where it can be read.
//   - no dot import, so every name says which package it comes from - the
//     layer map is read off those names.
//   - a package is named after its directory, and only an entry point is main.
//   - no junk drawer names.
func TestEveryPackageKeepsItsHouseInOrder(t *testing.T) {
	requireNoViolations(t, checkPackageHygiene(mustLoadModule(t)), "package hygiene")
}

// TestPackageHygieneCanFail plants a package breaking every rule but the
// drawer, and a package breaking only the drawer - documented, named after its
// directory and embedding a file - so each rule is shown to fire and the
// drawer is shown not to drag the others along.
func TestPackageHygieneCanFail(t *testing.T) {
	untidy := checkPackageHygiene(plantedTree(t, "untidy_package.go", "internal/core/planted/planted.go"))
	for _, want := range []string{
		"package internal/core/planted has no package comment",
		"package wrongname stands in directory planted",
		`dot import of "strings"`,
		`blank import of "os"`,
		"func init runs when the package is imported",
	} {
		requireViolation(t, untidy, want)
	}

	drawer := checkPackageHygiene(plantedTree(t, "junk_drawer.go", "internal/core/util/util.go"))
	requireViolation(t, drawer, "package util is named like a drawer")
	if len(drawer) != 1 {
		t.Errorf("a documented package named after its directory and embedding a file broke more than its name: %v", drawer)
	}
}

// checkPackageHygiene reports every breach of the five rules above.
func checkPackageHygiene(tr tree) []Violation {
	var violations []Violation
	firstFile := map[string]sourceFile{}
	documented := map[string]bool{}
	for _, sf := range tr.files {
		violations = append(violations, checkInertImports(sf)...)
		if sf.isTest {
			continue
		}
		dir := path.Dir(sf.rel)
		if _, seen := firstFile[dir]; !seen {
			firstFile[dir] = sf
		}
		documented[dir] = documented[dir] || sf.file.Doc != nil
		violations = append(violations, checkPackageName(tr.modulePath, sf)...)
		violations = append(violations, checkNoInit(sf)...)
	}
	for dir, sf := range firstFile {
		if !documented[dir] {
			violations = append(violations, Violation{File: sf.rel, Line: 1, Detail: fmt.Sprintf(
				"package %s has no package comment - say in one sentence what it owns, right above the package clause of one of its files", dir)})
		}
	}
	return sortViolations(violations)
}

// checkInertImports reports a dot import anywhere and a blank import outside a
// test, except embed, whose blank import is how a file is embedded.
func checkInertImports(sf sourceFile) []Violation {
	var violations []Violation
	for _, spec := range sf.file.Imports {
		if spec.Name == nil {
			continue
		}
		imported := literalValue(spec.Path)
		line := sf.fset.Position(spec.Pos()).Line
		switch {
		case spec.Name.Name == ".":
			violations = append(violations, Violation{File: sf.rel, Line: line, Detail: fmt.Sprintf(
				"dot import of %q - every name says which package it comes from, so the layer map can be read off it", imported)})
		case spec.Name.Name == "_" && !sf.isTest && imported != "embed":
			violations = append(violations, Violation{File: sf.rel, Line: line, Detail: fmt.Sprintf(
				"blank import of %q runs that package for its side effects - wire what has to run from an entry point", imported)})
		}
	}
	return violations
}

// checkPackageName reports a package named unlike its directory, a main package
// outside cmd/ and a junk drawer name. The package in the module root is named
// after the module.
func checkPackageName(module string, sf sourceFile) []Violation {
	name := sf.file.Name.Name
	dir := path.Base(path.Dir(sf.rel))
	if dir == "." {
		dir = path.Base(module)
	}
	var detail string
	switch {
	case name == "main" && strings.HasPrefix(sf.rel, "cmd/"):
		return nil
	case junkDrawerNames[name]:
		detail = fmt.Sprintf("package %s is named like a drawer - name it after what it does, so the layer map can say where it belongs", name)
	case name != dir:
		detail = fmt.Sprintf("package %s stands in directory %s - a package is named after its directory, and only an entry point under cmd/ is main", name, dir)
	default:
		return nil
	}
	return []Violation{{File: sf.rel, Line: sf.fset.Position(sf.file.Name.Pos()).Line, Detail: detail}}
}

// checkNoInit reports a func init in a production file.
func checkNoInit(sf sourceFile) []Violation {
	var violations []Violation
	for _, decl := range sf.file.Decls {
		if fd, isFunc := decl.(*ast.FuncDecl); isFunc && fd.Recv == nil && fd.Name.Name == "init" {
			violations = append(violations, Violation{File: sf.rel, Line: sf.fset.Position(fd.Pos()).Line,
				Detail: "func init runs when the package is imported - wire it from an entry point, where it can be read"})
		}
	}
	return violations
}
