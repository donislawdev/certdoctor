package guard

import (
	"fmt"
	"go/ast"
	"path"
	"sort"
	"strings"
	"testing"
)

// toolLayer is where the tools live (ADR141 point 7).
const toolLayer = "internal/tool/"

// TestEveryToolPackageIsFuzzed holds ADR141 point 9: every package of the tools
// - each tool, each helper they share, and the contract, which reads the
// request document - has a fuzz test of its own.
//
// WHY A FUZZ TEST AND NOT A LONGER TABLE. A tool's whole input is somebody
// else's bytes, pasted from a ticket or read from a file, and a table holds the
// cases its writer thought of. A fuzz target holds a promise - no panic, an
// answer or a refusal, nothing else - against inputs nobody thought of, and the
// tools will be dozens, written over years by whoever comes next. The rule is
// on the package rather than on a list of names, so a new tool is held to it
// from its first commit, without anybody remembering to add it here.
//
// What it does not check: that the fuzz target asserts anything. A target that
// only calls the code still finds every panic, which is the failure this is
// mostly about, and what it promises beyond that is the test's own reviewer's
// question.
func TestEveryToolPackageIsFuzzed(t *testing.T) {
	requireNoViolations(t, checkToolFuzz(mustLoadModule(t)), "a package of the tools without a fuzz test")
}

// TestTheToolFuzzGuardCanFail plants two tool packages, one fuzzed and one
// tested by a table alone, and a fuzz test outside the layer that must not
// count for anything in it.
func TestTheToolFuzzGuardCanFail(t *testing.T) {
	tr := tree{files: []sourceFile{
		plantedSource(t, "internal/tool/tabled/tabled.go", "package tabled\n"),
		plantedSource(t, "internal/tool/tabled/tabled_test.go",
			"package tabled\nimport \"testing\"\nfunc TestTable(t *testing.T) {}\nfunc FuzzLike(t *testing.T) {}\n"),
		plantedSource(t, "internal/tool/fuzzed/fuzzed.go", "package fuzzed\n"),
		plantedSource(t, "internal/tool/fuzzed/fuzzed_test.go",
			"package fuzzed\nimport \"testing\"\nfunc FuzzRead(f *testing.F) {}\n"),
		plantedSource(t, "internal/core/other/other_test.go",
			"package other\nimport \"testing\"\nfunc FuzzOther(f *testing.F) {}\n"),
	}}
	violations := checkToolFuzz(tr)
	requireViolation(t, violations, "internal/tool/tabled has no fuzz test")
	if len(violations) != 1 {
		t.Errorf("want only the package tested by a table alone, got %v", violations)
	}
}

// checkToolFuzz names every package of the tools whose tests declare no fuzz
// target - a function called Fuzz<Something> taking *testing.F.
func checkToolFuzz(tr tree) []Violation {
	packages := map[string]bool{}
	for _, sf := range tr.files {
		if !strings.HasPrefix(sf.rel, toolLayer) {
			continue
		}
		dir := path.Dir(sf.rel)
		packages[dir] = packages[dir] || sf.isTest && declaresFuzzTarget(sf.file)
	}
	var dirs []string
	for dir, fuzzed := range packages {
		if !fuzzed {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	var violations []Violation
	for _, dir := range dirs {
		violations = append(violations, Violation{File: dir, Line: 1, Detail: fmt.Sprintf(
			"%s has no fuzz test - every package of the tools reads bytes from outside and holds its promise "+
				"against inputs nobody listed (ADR141 point 9)", dir)})
	}
	return violations
}

// declaresFuzzTarget says the file declares func FuzzX(f *testing.F).
func declaresFuzzTarget(file *ast.File) bool {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") || len(fn.Type.Params.List) != 1 {
			continue
		}
		star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if sel, ok := star.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "F" {
			return true
		}
	}
	return false
}

// plantedSource is sourceFrom with the file marked as a test when its name
// says it is one, which this guard reads and sourceFrom leaves unset.
func plantedSource(t *testing.T, rel, src string) sourceFile {
	t.Helper()
	sf := sourceFrom(t, rel, src)
	sf.isTest = strings.HasSuffix(rel, "_test.go")
	return sf
}
