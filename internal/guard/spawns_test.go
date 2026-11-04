package guard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"strconv"
	"strings"
	"testing"
)

// WHICH PROGRAM a file allowed to start one actually starts (ADR125 point 7).
// execAllowlist answers whether a file may import os/exec at all, and for
// internal/adapter/probe/exec.go that is the whole question, because the path
// it runs arrives from its callers and the four narrowing rules of ADR49 are
// checked by its own tests. The window is different: what it starts is decided
// in the file itself, so the file is held to the operations it is registered
// for - what is called, and what answered the call's first argument. Both,
// because each alone forgives too much: the approved call handed a path worked
// out somewhere else, or the approved path handed to another call. The shape
// comes from TestingFilesGenerator (approvedOperation), where the first version
// matched the kind and counted one, and an outside review pointed out that a
// spawn of curl in the registered file would then have been the one forgiven.
//
// The calls are spelled with the path of the package they come from, so a file
// that imports os/exec under another name is read the same way.

// approvedSpawn is the one spawn an entry forgives.
type approvedSpawn struct {
	call string // os/exec.Command - the call, with the path of its package
	from string // os.Executable - what answers its first argument, spelled the same way
	why  string
}

// spawnsAllowed names, for each window file on execAllowlist, the spawns it is
// allowed - one entry per spawn, so a second copy of an approved one is not
// forgiven for being identical. The command line the window is to run
// (ADR121) arrives here as the second entry of the same file, never as a
// second file.
var spawnsAllowed = map[string][]approvedSpawn{
	"cmd/certdoctor-gui/processes.go": {
		{call: "os/exec.Command", from: "os.Executable",
			why: "the window started again by the path os.Executable answers, for the software renderer (ADR125 point 2) - see ourselves there"},
	},
}

// spawnCalls are the calls able to start another program. The ones outside
// os/exec need no os/exec import at all, which is the hole checkExec has by
// reading imports - so they are looked for in every file.
var spawnCalls = map[string]bool{
	"os/exec.Command":                              true,
	"os/exec.CommandContext":                       true,
	"os.StartProcess":                              true,
	"syscall.StartProcess":                         true,
	"syscall.ForkExec":                             true,
	"syscall.Exec":                                 true,
	"syscall.CreateProcess":                        true,
	"syscall.CreateProcessAsUser":                  true,
	"golang.org/x/sys/windows.CreateProcess":       true,
	"golang.org/x/sys/windows.CreateProcessAsUser": true,
	"golang.org/x/sys/windows.ShellExecute":        true,
	"golang.org/x/sys/unix.Exec":                   true,
}

// commandType is os/exec's command, which a file can build without calling
// exec.Command - a literal or new - and then start. Never forgiven, because
// nothing follows where its path came from.
const commandType = "os/exec.Cmd"

// spawnPackages are the packages a spawn can come from, for the dot import that
// would hide one behind a bare name.
var spawnPackages = map[string]bool{
	"os/exec": true, "os": true, "syscall": true, "golang.org/x/sys/windows": true, "golang.org/x/sys/unix": true,
}

// spawnFinding is one spawn in a file: what is called, what answered its first
// argument (nothing when this guard cannot follow it), and where.
type spawnFinding struct {
	call, from string
	line       int
}

// TestEveryProgramTheWindowStartsIsNamed is the guard on the tree: every spawn
// outside execAllowlist is a finding wherever it is spelled, every spawn in a
// file of spawnsAllowed is one of its entries, and every entry is used - an
// entry naming a spawn that is not there forgives whatever arrives later.
func TestEveryProgramTheWindowStartsIsNamed(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkSpawnCalls(tr), "a program started outside what the exec lists name")
	for _, sf := range tr.files {
		if approved, ok := spawnsAllowed[sf.rel]; ok {
			_, unused := settle(spawnFindings(sf), approved)
			for _, op := range unused {
				t.Errorf("spawnsAllowed forgives %s %s handed what %s answers, and the file has no such spawn",
					sf.rel, op.call, op.from)
			}
		}
	}
}

// TestAnEntryWithNoSpawnBehindItIsReported is the canary of the last check
// above, which on the real tree has nothing to find: the entry of the window
// file against a file that starts nothing, and against one that starts what it
// names.
func TestAnEntryWithNoSpawnBehindItIsReported(t *testing.T) {
	const window = "cmd/certdoctor-gui/processes.go"
	empty := sourceFrom(t, window, "package main\n\nfunc f() {}\n")
	if _, unused := settle(spawnFindings(empty), spawnsAllowed[window]); len(unused) != len(spawnsAllowed[window]) {
		t.Errorf("a file that starts nothing left %d of %d entries unused", len(unused), len(spawnsAllowed[window]))
	}
	starts := sourceFrom(t, window, "package main\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\nfunc f() {\n\texe, _ := os.Executable()\n\t_ = exec.Command(exe)\n}\n")
	if _, unused := settle(spawnFindings(starts), spawnsAllowed[window][:1]); len(unused) != 0 {
		t.Errorf("a file that starts what the first entry names left it unused: %v", unused)
	}
}

// TestEveryWindowFileOnTheExecListNamesItsSpawns - a window file allowed to
// import os/exec without an entry here would be allowed to start anything, and
// an entry for a file the exec list does not name forgives nothing. Asked of
// the real lists, then of two planted ones, because the real ones agree and a
// check that cannot disagree looks exactly like one that works.
func TestEveryWindowFileOnTheExecListNamesItsSpawns(t *testing.T) {
	for _, problem := range unpaired(execAllowlist, spawnsAllowed) {
		t.Error(problem)
	}
	planted := map[string]bool{"cmd/certdoctor-gui/planted.go": true, "internal/adapter/probe/exec.go": true}
	if got := unpaired(planted, nil); len(got) != 1 {
		t.Errorf("a window file on the exec list with no spawns named gave %q, want one finding", got)
	}
	if got := unpaired(nil, map[string][]approvedSpawn{"cmd/certdoctor-gui/planted.go": {{}}}); len(got) != 1 {
		t.Errorf("spawns named for a file off the exec list gave %q, want one finding", got)
	}
}

// TestARegisteredFileIsForgivenOneSpawnAndNoMore is the canary of the two
// checks above, and the reason it is a table: a registered file is forgiven
// the one operation its entry names and nothing beside it - a second of the
// same, the same call handed something else, another call handed the same
// thing - and a spawn outside os/exec is a finding in any file.
func TestARegisteredFileIsForgivenOneSpawnAndNoMore(t *testing.T) {
	const window = "cmd/certdoctor-gui/processes.go"
	header := "package main\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n\t\"syscall\"\n)\n\n"
	approved := "func f() {\n\texe, _ := os.Executable()\n\t_ = exec.Command(exe)\n}\n"
	for _, c := range []struct {
		label, src, rel string
		left            int
	}{
		{"the approved spawn", header + approved, window, 0},
		{"the approved spawn and a second one", header + approved + "\nfunc g() { _ = exec.Command(\"curl\") }\n", window, 1},
		{"the approved spawn twice", header + approved + "\nfunc g() {\n\texe, _ := os.Executable()\n\t_ = exec.Command(exe)\n}\n", window, 1},
		{"the approved call handed another program", header + "func f() { _ = exec.Command(os.Args[0]) }\n", window, 1},
		{"another call handed the approved program", header + "func f() {\n\texe, _ := os.Executable()\n\t_, _ = os.StartProcess(exe, nil, nil)\n}\n", window, 1},
		{"the approved program bound twice on the way", header + "func f() {\n\texe, _ := os.Executable()\n\texe = os.Args[0]\n\t_ = exec.Command(exe)\n}\n", window, 1},
		{"the approved program shadowing a parameter", header + "func f(exe string) {\n\texe, _ = os.Executable()\n\t_ = exec.Command(exe)\n}\n", window, 1},
		{"the approved program as a declared variable", header + "func f() {\n\tvar exe string\n\t_ = exec.Command(exe)\n}\n", window, 1},
		{"a command built as a literal", header + "func f() {\n\texe, _ := os.Executable()\n\t_ = &exec.Cmd{Path: exe}\n}\n", window, 1},
		{"a command built with new", header + "func f() { _ = new(exec.Cmd) }\n", window, 1},
		{"the approved spawn under another name", "package main\n\nimport (\n\t\"os\"\n\trun \"os/exec\"\n)\n\nfunc f() {\n\texe, _ := os.Executable()\n\t_ = run.Command(exe)\n}\n", window, 0},
		{"another program under another name", "package main\n\nimport run \"os/exec\"\n\nfunc f() { _ = run.Command(\"curl\") }\n", window, 1},
		{"a spawn behind a dot import", "package main\n\nimport . \"os/exec\"\n\nfunc f() { _ = Command(\"curl\") }\n", window, 1},
		// Outside the lists. A file importing os/exec is checkExec's finding,
		// and the calls that need no os/exec are this guard's in every file.
		{"the approved spawn in a file not registered for it", header + approved, "internal/adapter/dns/planted.go", 1},
		{"a system call spawn in a file not registered for it", "package dns\n\nimport \"syscall\"\n\nfunc f() { _, _ = syscall.ForkExec(\"curl\", nil, nil) }\n", "internal/adapter/dns/planted.go", 1},
		{"a process started without os/exec", "package dns\n\nimport \"os\"\n\nfunc f() { _, _ = os.StartProcess(\"curl\", nil, nil) }\n", "internal/adapter/dns/planted.go", 1},
	} {
		planted := tree{modulePath: "github.com/donislawdev/certdoctor", files: []sourceFile{sourceFrom(t, c.rel, c.src)}}
		if left := len(checkExec(planted)) + len(checkSpawnCalls(planted)); left != c.left {
			t.Errorf("%s in %s left %d finding(s), and %d had to be left", c.label, c.rel, left, c.left)
		}
	}
}

// checkSpawnCalls reports every spawn this guard is not told to forgive: in a
// file of spawnsAllowed, what its entries do not name, and anywhere else off
// execAllowlist, every spawn that is not os/exec's - those are checkExec's
// finding already, by the import, and are not said twice.
func checkSpawnCalls(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		approved, registered := spawnsAllowed[sf.rel]
		if sf.isTest || (execAllowlist[sf.rel] && !registered) {
			continue
		}
		found := spawnFindings(sf)
		if registered {
			found, _ = settle(found, approved)
		}
		for _, f := range found {
			if !registered && strings.HasPrefix(f.call, "os/exec.") {
				continue
			}
			violations = append(violations, Violation{sf.rel, f.line, fmt.Sprintf(
				"%s starts a program with %s handed %s - a file may start only what spawnsAllowed in spawns_test.go "+
					"names for it (ADR125 point 7)", sf.rel, f.call, describeSource(f.from))})
		}
	}
	return sortViolations(violations)
}

// forgives reports whether the entry is the spawn found: the same call, handed
// an argument answered by the same function.
func (op approvedSpawn) forgives(f spawnFinding) bool {
	return f.call == op.call && f.from == op.from
}

// settle pairs found with approved, one spawn per entry: left are the spawns no
// entry forgives, and unused the entries no spawn answers to.
func settle(found []spawnFinding, approved []approvedSpawn) (left []spawnFinding, unused []approvedSpawn) {
	left = append([]spawnFinding{}, found...)
	for _, op := range approved {
		matched := false
		for i, f := range left {
			if op.forgives(f) {
				left, matched = append(left[:i], left[i+1:]...), true
				break
			}
		}
		if !matched {
			unused = append(unused, op)
		}
	}
	return left, unused
}

// unpaired are the window files on execList that spawns names nothing for, and
// the files spawns names that execList does not let import os/exec at all.
func unpaired(execList map[string]bool, spawns map[string][]approvedSpawn) []string {
	var out []string
	for rel := range execList {
		if path.Dir(rel) == "cmd/certdoctor-gui" && len(spawns[rel]) == 0 {
			out = append(out, rel+" is on execAllowlist and spawnsAllowed names nothing it may start")
		}
	}
	for rel := range spawns {
		if !execList[rel] {
			out = append(out, "spawnsAllowed names "+rel+", which is not on execAllowlist and may not import os/exec at all")
		}
	}
	return out
}

// dotImported stands in for the source of a spawn package imported with a dot,
// whose calls are bare names this guard cannot tell apart from the file's own.
const dotImported = "a dot import"

// spawnFindings are the spawns in one file, with the function each first
// argument is bound to in the enclosing function.
func spawnFindings(sf sourceFile) []spawnFinding {
	paths, dots := importPaths(sf.file)
	var found []spawnFinding
	for _, p := range dots {
		found = append(found, spawnFinding{call: p, from: dotImported, line: sf.fset.Position(sf.file.Package).Line})
	}
	for _, decl := range sf.file.Decls {
		fn, _ := decl.(*ast.FuncDecl)
		ast.Inspect(decl, func(n ast.Node) bool {
			if f, ok := spawnIn(n, fn, paths); ok {
				f.line = sf.fset.Position(n.Pos()).Line
				found = append(found, f)
			}
			return true
		})
	}
	return found
}

// spawnIn is the spawn n is, if it is one: a call from spawnCalls, or a command
// built without one.
func spawnIn(n ast.Node, fn *ast.FuncDecl, paths map[string]string) (spawnFinding, bool) {
	switch e := n.(type) {
	case *ast.CallExpr:
		if name, ok := e.Fun.(*ast.Ident); ok && name.Name == "new" && len(e.Args) == 1 && spelled(e.Args[0], paths) == commandType {
			return spawnFinding{call: commandType}, true
		}
		if call := spelled(e.Fun, paths); spawnCalls[call] {
			return spawnFinding{call: call, from: firstArgumentSource(e, fn, paths)}, true
		}
	case *ast.CompositeLit:
		if spelled(e.Type, paths) == commandType {
			return spawnFinding{call: commandType}, true
		}
	}
	return spawnFinding{}, false
}

// importPaths maps the names a file imports packages under to their paths, and
// lists the spawn packages it imports with a dot.
func importPaths(f *ast.File) (map[string]string, []string) {
	paths := map[string]string{}
	var dots []string
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		switch name {
		case "_":
		case ".":
			if spawnPackages[p] {
				dots = append(dots, p)
			}
		default:
			paths[name] = p
		}
	}
	return paths, dots
}

// spelled is the function or type an expression names, with the path of its
// package: os/exec.Command for a selector on an imported name, the bare name
// for one of the file's own package, and nothing for a method on a value.
func spelled(e ast.Expr, paths map[string]string) string {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		if pkg, ok := x.X.(*ast.Ident); ok {
			if p, imported := paths[pkg.Name]; imported {
				return p + "." + x.Sel.Name
			}
		}
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// firstArgumentSource is what a call's first argument is bound to, or nothing
// when the call has none.
func firstArgumentSource(call *ast.CallExpr, fn *ast.FuncDecl, paths map[string]string) string {
	if len(call.Args) == 0 {
		return ""
	}
	return boundTo(fn, call.Args[0], paths)
}

// boundTo is the call an argument was answered by: the argument itself when it
// is a call, or - when it is a name - the one binding of that name in the
// enclosing function, when that binding is a call. Nothing when the argument is
// anything else, or the name is bound more than once - a parameter, a result
// and a declaration each count as a binding to nothing - because a guard that
// cannot follow an argument has to say so rather than guess. Names are compared
// as text, so a second binding in an inner scope counts too: stricter than the
// language, never looser.
func boundTo(fn *ast.FuncDecl, arg ast.Expr, paths map[string]string) string {
	if call, ok := arg.(*ast.CallExpr); ok {
		return spelled(call.Fun, paths)
	}
	name, ok := arg.(*ast.Ident)
	if !ok || fn == nil || fn.Body == nil {
		return ""
	}
	sources := fieldBindings(fn.Type, name.Name)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sources = append(sources, bindingsOf(n, name.Name, paths)...)
		return true
	})
	if len(sources) != 1 {
		return ""
	}
	return sources[0]
}

// bindingsOf are the sources n binds name to: an assignment, a range, a
// declaration, or the parameters of a function literal.
func bindingsOf(n ast.Node, name string, paths map[string]string) []string {
	var sources []string
	switch s := n.(type) {
	case *ast.AssignStmt:
		for i, lhs := range s.Lhs {
			if isName(lhs, name) {
				sources = append(sources, valueSource(s.Rhs, i, len(s.Lhs), paths))
			}
		}
	case *ast.RangeStmt:
		if isName(s.Key, name) || isName(s.Value, name) {
			sources = append(sources, valueSource([]ast.Expr{s.X}, 0, 1, paths))
		}
	case *ast.ValueSpec:
		for i, id := range s.Names {
			if id.Name == name {
				sources = append(sources, valueSource(s.Values, i, len(s.Names), paths))
			}
		}
	case *ast.FuncLit:
		sources = append(sources, fieldBindings(s.Type, name)...)
	}
	return sources
}

// valueSource is the call the i-th of n names is bound to by values: the one
// call when a single call answers them all, the i-th value when there is one
// per name, and nothing otherwise.
func valueSource(values []ast.Expr, i, n int, paths map[string]string) string {
	var value ast.Expr
	switch len(values) {
	case 1:
		value = values[0]
	case n:
		value = values[i]
	default:
		return ""
	}
	call, ok := value.(*ast.CallExpr)
	if !ok {
		return ""
	}
	return spelled(call.Fun, paths)
}

// fieldBindings is a binding to nothing for each parameter or named result of
// a function that carries name.
func fieldBindings(ft *ast.FuncType, name string) []string {
	var sources []string
	for _, list := range []*ast.FieldList{ft.Params, ft.Results} {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			for _, id := range field.Names {
				if id.Name == name {
					sources = append(sources, "")
				}
			}
		}
	}
	return sources
}

// isName reports whether e is the plain name name.
func isName(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// describeSource is the words for where an argument came from, for a message.
func describeSource(from string) string {
	switch from {
	case "":
		return "an argument this guard cannot follow"
	case dotImported:
		return "a name a dot import hides"
	}
	return "what " + from + " answers"
}

// sourceFrom parses src as the file rel, for a canary that plants a file
// rather than reading one from testdata.
func sourceFrom(t *testing.T, rel, src string) sourceFile {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing the planted %s: %v", rel, err)
	}
	return sourceFile{rel: rel, fset: fset, file: parsed}
}
