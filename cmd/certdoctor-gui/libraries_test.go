package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestTheWindowNarrowsTheSearchBeforeAnythingElse reads run_cgo.go: the first
// statement of run has to be the call to searchSystemOnly (OBS214, ADR152).
// Everything the toolkit asks for by name it asks for after run starts, so a
// call made first covers all of it. A call made later, or none, is the window
// as every other test of it would still pass it.
func TestTheWindowNarrowsTheSearchBeforeAnythingElse(t *testing.T) {
	src, err := os.ReadFile("run_cgo.go")
	if err != nil {
		t.Fatal(err)
	}
	if problem := searchNotFirst(src); problem != "" {
		t.Error(problem)
	}
}

// TestTheSearchCheckCanFail plants the shapes the check above exists for.
func TestTheSearchCheckCanFail(t *testing.T) {
	const head = "package main\n\nfunc run(args []string) int {\n"
	const call = "\tif err := searchSystemOnly(); err != nil {\n\t\tsay(err)\n\t}\n"
	for _, c := range []struct {
		label, src, want string
	}{
		{"called first", head + call + "\treadLaunch(args)\n\treturn 0\n}\n", ""},
		{"called second", head + "\treadLaunch(args)\n" + call + "\treturn 0\n}\n", "is not the call"},
		{"another call first in the same shape", head + "\tif err := speakEnglish(); err != nil {\n\t\tsay(err)\n\t}\n" +
			call + "\treturn 0\n}\n", "is not the call"},
		{"not called", head + "\treadLaunch(args)\n\treturn 0\n}\n", "is not the call"},
		{"its answer dropped", head + "\t_ = searchSystemOnly()\n\treturn 0\n}\n", "is not the call"},
		{"no run", "package main\n\nfunc other() {}\n", "has no func run"},
	} {
		got := searchNotFirst([]byte(c.src))
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: the check said %q, want %q", c.label, got, c.want)
		}
	}
}

// searchNotFirst says what is wrong with run in the source given, or nothing.
func searchNotFirst(src []byte) string {
	f, err := parser.ParseFile(token.NewFileSet(), "run_cgo.go", src, 0)
	if err != nil {
		return "run_cgo.go does not parse: " + err.Error()
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "run" {
			continue
		}
		if len(fn.Body.List) > 0 && callsSearch(fn.Body.List[0]) {
			return ""
		}
		return "the first statement of run in run_cgo.go is not the call `if err := searchSystemOnly(); err != nil` - " +
			"a library the toolkit asks for by name before it can be taken from beside the window (OBS214, ADR152)"
	}
	return "run_cgo.go has no func run - the check reads the wrong file"
}

// callsSearch answers whether the statement is an if whose init calls
// searchSystemOnly and keeps its answer.
func callsSearch(s ast.Stmt) bool {
	is, ok := s.(*ast.IfStmt)
	if !ok {
		return false
	}
	as, ok := is.Init.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "searchSystemOnly"
}
