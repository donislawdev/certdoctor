package guard

import (
	"fmt"
	"go/ast"
	"strconv"
	"strings"
	"testing"
)

// WHERE A LIBRARY THIS PROGRAM LOADS COMES FROM (ADR125 point 8, the owner's
// decision of 2026-11-09). A library asked for by a bare name goes through the
// loader's search order, whose first directory is the one holding the
// executable - so a file of that name planted beside certdoctor.exe or
// certdoctor-gui.exe would be loaded instead of the system's. The one exception
// is a Known DLL, which the loader takes from the section the system mapped at
// boot and never searches for (the search order, read 2026-11-04:
// https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order).
//
// So the rule has two halves. By name, only a library on knownDLLs below. Every
// other load hands the loader a path, and a path is worked out in one reviewed
// function: the system directory asked of GetSystemDirectoryW (dns, proxyconf),
// or the software renderer's files under the window's own folder. Those loads
// are named in libraryLoadsAllowed the way a spawn of the window is named in
// spawnsAllowed: the call, the function it stands in, and what answered its
// first argument when this guard can follow it.
//
// What it does not see: a load through a procedure found by hand (LoadLibraryW
// asked of GetProcAddress), and C code. The OpenGL binding in third_party asks
// for opengl32.dll by name from C (its own go.mod keeps it out of this scan),
// and so does the toolkit's GLFW - that is how a program finds the system's
// OpenGL driver, and a name planted beside the window is the same exposure
// every OpenGL program on Windows has. Written down rather than hidden.

// knownDLLs are the libraries this program may load by bare name, each with why
// the loader never searches for it.
var knownDLLs = map[string]string{
	"kernel32.dll": "a Known DLL on every Windows - read from this machine's registry 2026-08-27, " +
		`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs, 37 entries with kernel32.dll among them ` +
		"- and mapped into every process before its own code runs, so asking for it by name finds the copy already there",
}

// libraryLoaders are the calls that load a library by the name or path they
// are handed.
var libraryLoaders = map[string]bool{
	"syscall.LoadDLL":                           true,
	"syscall.MustLoadDLL":                       true,
	"syscall.NewLazyDLL":                        true,
	"syscall.LoadLibrary":                       true,
	"golang.org/x/sys/windows.LoadDLL":          true,
	"golang.org/x/sys/windows.MustLoadDLL":      true,
	"golang.org/x/sys/windows.NewLazyDLL":       true,
	"golang.org/x/sys/windows.LoadLibrary":      true,
	"golang.org/x/sys/windows.LoadLibraryEx":    true,
	"golang.org/x/sys/windows.NewLazySystemDLL": true,
}

// systemDirectoryLoader looks a bare name up in the system directory and
// nowhere else - "will only search Windows System directory for the DLL if
// name is a base name" (golang.org/x/sys/windows, dll_windows.go, read
// 2026-11-09). So a base name handed to it is a load from the system
// directory, and only a path handed to it needs to be named below.
const systemDirectoryLoader = "golang.org/x/sys/windows.NewLazySystemDLL"

// loaderPackages are the packages a load can come from, for the dot import that
// would hide one behind a bare name.
var loaderPackages = map[string]bool{"syscall": true, "golang.org/x/sys/windows": true}

// approvedLoad is the one load by path an entry forgives.
type approvedLoad struct {
	call string // syscall.NewLazyDLL - the call, with the path of its package
	in   string // systemLibrary - the function of the file the call stands in
	from string // what answered its first argument, or nothing when this guard cannot follow it
	why  string
}

// libraryLoadsAllowed names, for each file that loads a library by path, the
// loads it is allowed - one entry per load, so a second copy of an approved one
// is not forgiven for being identical.
var libraryLoadsAllowed = map[string][]approvedLoad{
	"internal/adapter/dns/nameservers_windows.go": {
		{call: "syscall.NewLazyDLL", in: "systemLibrary", from: "",
			why: "iphlpapi.dll under the directory GetSystemDirectoryW answers - the path is joined in that function, which this guard does not follow"},
	},
	"internal/adapter/proxyconf/proxyconf_windows.go": {
		{call: "syscall.NewLazyDLL", in: "systemLibrary", from: "",
			why: "winhttp.dll under the directory GetSystemDirectoryW answers - the second copy of the dns function (OBS116)"},
	},
	"cmd/certdoctor-gui/software_windows.go": {
		{call: "syscall.LoadDLL", in: "loadSoftwareRenderer", from: "softwareFiles",
			why: "the software renderer's two files in the opengl folder under the window's own (ADR125 points 2 and 8)"},
	},
}

// loadFinding is one load in a file: the call, the function it stands in, what
// answered its first argument, and - when that argument is a literal - the
// name it asks for.
type loadFinding struct {
	call, in, from string
	literal        string
	isLiteral      bool
	line           int
}

// TestEveryLibraryIsLoadedFromAKnownPlace is the guard on the tree: every load
// is a Known DLL by name or one of its file's entries, and every entry is used
// - an entry naming a load that is not there forgives whatever arrives later.
func TestEveryLibraryIsLoadedFromAKnownPlace(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkLibraryLoads(tr), "a library loaded from a place nobody named")
	for _, sf := range tr.files {
		if approved, ok := libraryLoadsAllowed[sf.rel]; ok {
			_, unused := settleLoads(loadFindings(sf), approved)
			for _, op := range unused {
				t.Errorf("libraryLoadsAllowed forgives %s %s in %s, and the file has no such load", sf.rel, op.call, op.in)
			}
		}
	}
	for rel := range libraryLoadsAllowed {
		if _, ok := fileOf(tr, rel); !ok {
			t.Errorf("libraryLoadsAllowed names %s, which is not in the tree", rel)
		}
	}
}

// TestEveryKnownDLLSaysWhy - a name on the list with no reason is a name
// somebody added to make a red guard green.
func TestEveryKnownDLLSaysWhy(t *testing.T) {
	for name, why := range knownDLLs {
		if strings.TrimSpace(why) == "" || name != strings.ToLower(name) {
			t.Errorf("knownDLLs: %q has to be written in lower case and say why the loader never searches for it", name)
		}
	}
}

// TestALoadIsForgivenOnlyWhereItsEntrySaysSo is the canary of the guard above,
// and the reason it is a table: a Known DLL by name passes anywhere, any other
// name does not, and a load by path passes only as the one its file's entry
// names - in that function, from that source, once.
func TestALoadIsForgivenOnlyWhereItsEntrySaysSo(t *testing.T) {
	const renderer = "cmd/certdoctor-gui/software_windows.go"
	const elsewhere = "internal/adapter/render/planted.go"
	header := "package main\n\nimport \"syscall\"\n\n"
	approved := "func loadSoftwareRenderer(exeDir string) {\n\tfor _, path := range softwareFiles(exeDir) {\n\t\t_, _ = syscall.LoadDLL(path)\n\t}\n}\n"
	for _, c := range []struct {
		label, src, rel string
		left            int
	}{
		{"a Known DLL by name", header + "func f() { _ = syscall.NewLazyDLL(\"kernel32.dll\") }\n", elsewhere, 0},
		{"another library by name", header + "func f() { _ = syscall.NewLazyDLL(\"winhttp.dll\") }\n", elsewhere, 1},
		{"a Known DLL spelled another way", header + "func f() { _ = syscall.NewLazyDLL(\"KERNEL32.dll\") }\n", elsewhere, 1},
		{"a library by name through LoadLibrary", header + "func f() { _, _ = syscall.LoadLibrary(\"opengl32.dll\") }\n", elsewhere, 1},
		{"a library by name under another import name", "package main\n\nimport sys \"syscall\"\n\nfunc f() { _, _ = sys.LoadDLL(\"user32.dll\") }\n", elsewhere, 1},
		{"a loader behind a dot import", "package main\n\nimport . \"syscall\"\n\nfunc f() { _, _ = LoadDLL(\"kernel32.dll\") }\n", elsewhere, 1},
		{"a base name from the system directory", "package main\n\nimport \"golang.org/x/sys/windows\"\n\nfunc f() { _ = windows.NewLazySystemDLL(\"user32.dll\") }\n", elsewhere, 0},
		{"a path handed to the system directory loader", "package main\n\nimport \"golang.org/x/sys/windows\"\n\nfunc f() { _ = windows.NewLazySystemDLL(\"C:/x/user32.dll\") }\n", elsewhere, 1},
		{"a library by name through the other package", "package main\n\nimport \"golang.org/x/sys/windows\"\n\nfunc f() { _, _ = windows.LoadLibraryEx(\"winhttp.dll\", 0, 0) }\n", elsewhere, 1},
		{"the approved load", header + approved, renderer, 0},
		{"the approved load and one by path more", header + approved + "\nfunc g(p string) { _, _ = syscall.LoadDLL(p) }\n", renderer, 1},
		{"the approved load twice", header + approved + "\nfunc h(exeDir string) {\n\tfor _, path := range softwareFiles(exeDir) {\n\t\t_, _ = syscall.LoadDLL(path)\n\t}\n}\n", renderer, 1},
		{"the approved load in another function", header + "func other(exeDir string) {\n\tfor _, path := range softwareFiles(exeDir) {\n\t\t_, _ = syscall.LoadDLL(path)\n\t}\n}\n", renderer, 1},
		{"the approved function loading another path", header + "func loadSoftwareRenderer(exeDir string) { _, _ = syscall.LoadDLL(exeDir) }\n", renderer, 1},
		{"the approved function with another call", header + "func loadSoftwareRenderer(exeDir string) {\n\tfor _, path := range softwareFiles(exeDir) {\n\t\t_ = syscall.NewLazyDLL(path)\n\t}\n}\n", renderer, 1},
		{"the approved load in a file not registered for it", header + approved, elsewhere, 1},
		{"a Known DLL by name in a registered file", header + approved + "\nfunc k() { _ = syscall.NewLazyDLL(\"kernel32.dll\") }\n", renderer, 0},
	} {
		planted := tree{modulePath: "github.com/donislawdev/certdoctor", files: []sourceFile{sourceFrom(t, c.rel, c.src)}}
		if left := len(checkLibraryLoads(planted)); left != c.left {
			t.Errorf("%s in %s left %d finding(s), and %d had to be left", c.label, c.rel, left, c.left)
		}
	}
}

// TestALoadEntryWithNoLoadBehindItIsReported is the canary of the last check of
// the guard on the tree, which on the real tree has nothing to find.
func TestALoadEntryWithNoLoadBehindItIsReported(t *testing.T) {
	const renderer = "cmd/certdoctor-gui/software_windows.go"
	empty := sourceFrom(t, renderer, "package main\n\nfunc f() {}\n")
	if _, unused := settleLoads(loadFindings(empty), libraryLoadsAllowed[renderer]); len(unused) != len(libraryLoadsAllowed[renderer]) {
		t.Errorf("a file that loads nothing left %d of %d entries unused", len(unused), len(libraryLoadsAllowed[renderer]))
	}
}

// checkLibraryLoads reports every load that is neither a Known DLL by name, a
// base name handed to the system directory loader, nor one its file's entries
// forgive.
func checkLibraryLoads(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest {
			continue
		}
		var byPath []loadFinding
		for _, f := range loadFindings(sf) {
			switch {
			case f.isLiteral && f.call == systemDirectoryLoader && !strings.ContainsAny(f.literal, `/\`):
			case f.isLiteral && f.call != systemDirectoryLoader && knownDLLs[f.literal] != "":
			default:
				byPath = append(byPath, f)
			}
		}
		left, _ := settleLoads(byPath, libraryLoadsAllowed[sf.rel])
		for _, f := range left {
			violations = append(violations, Violation{sf.rel, f.line, describeLoad(sf.rel, f)})
		}
	}
	return sortViolations(violations)
}

// describeLoad is the words of one finding.
func describeLoad(rel string, f loadFinding) string {
	if f.from == dotImported {
		return fmt.Sprintf("%s imports %s with a dot, which hides which library its calls load - import it by name "+
			"(ADR125 point 8)", rel, f.call)
	}
	if f.isLiteral {
		return fmt.Sprintf("%s loads %q by name with %s - by name only a library on knownDLLs in libraries_test.go "+
			"(ADR125 point 8), anything else by a path from the system directory or beside the window", rel, f.literal, f.call)
	}
	return fmt.Sprintf("%s loads a library with %s in %s handed %s - a load by path is allowed only as "+
		"libraryLoadsAllowed in libraries_test.go names it (ADR125 point 8)", rel, f.call, f.in, describeSource(f.from))
}

// settleLoads pairs found with approved, one load per entry: left are the
// loads no entry forgives, and unused the entries no load answers to.
func settleLoads(found []loadFinding, approved []approvedLoad) (left []loadFinding, unused []approvedLoad) {
	left = append([]loadFinding{}, found...)
	for _, op := range approved {
		matched := false
		for i, f := range left {
			if !f.isLiteral && f.call == op.call && f.in == op.in && f.from == op.from {
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

// loadFindings are the loads in one file. A loader package imported with a
// dot is a finding of its own, because its calls are bare names this guard
// cannot tell apart from the file's own.
func loadFindings(sf sourceFile) []loadFinding {
	paths, _ := importPaths(sf.file)
	var found []loadFinding
	for _, spec := range sf.file.Imports {
		if spec.Name != nil && spec.Name.Name == "." {
			if p, err := strconv.Unquote(spec.Path.Value); err == nil && loaderPackages[p] {
				found = append(found, loadFinding{call: p, from: dotImported, line: sf.fset.Position(spec.Pos()).Line})
			}
		}
	}
	for _, decl := range sf.file.Decls {
		fn, _ := decl.(*ast.FuncDecl)
		in := ""
		if fn != nil {
			in = fn.Name.Name
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			name := spelled(call.Fun, paths)
			if !libraryLoaders[name] {
				return true
			}
			f := loadFinding{call: name, in: in, line: sf.fset.Position(call.Pos()).Line}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					f.literal, f.isLiteral = s, true
				}
			}
			if !f.isLiteral {
				f.from = boundTo(fn, call.Args[0], paths)
			}
			found = append(found, f)
			return true
		})
	}
	return found
}
