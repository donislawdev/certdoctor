package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestOnlyAGatedAcceptanceCheckReachesForARealName keeps OBS150 closed rather
// than fixed once.
//
// THE DEFECT WAS A HABIT, NOT A LINE. Seventeen acceptance checks used the real
// name because it was the constant at the top of the file, and none of them
// asked whether a network was there. Red at the boundary then meant "the
// network blinked" as often as "the program broke", which costs more than the
// checks are worth. The next check written against the real name by the same
// habit would bring it back, and nothing else here would notice.
//
// IT LIVES OUTSIDE THE acceptance BUILD TAG ON PURPOSE. The files it reads are
// behind that tag, but reading them needs no binary, so this runs with every
// plain go test - a check that only ran at the boundary would meet the mistake
// after it was made.
//
// THE GATE HAS TO COME FIRST. A call to needsTheInternet after the program has
// already run against the real name would skip a check that had already failed.
//
// WHAT IT DOES NOT CATCH: a real host written out as a literal instead of
// through aRealName, or a helper reached through a function value. It reads
// names, as the write guard reads imports.
func TestOnlyAGatedAcceptanceCheckReachesForARealName(t *testing.T) {
	files, err := filepath.Glob("acceptance*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no acceptance file was found to read (%v), so nothing here was checked", err)
	}

	reaching := 0
	fset := token.NewFileSet()
	for _, name := range files {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			use, gate := firstUseAndGate(function.Body)
			if !use.IsValid() {
				continue
			}
			reaching++
			if !gate.IsValid() || gate > use {
				t.Errorf("%s reaches for aRealName without asking needsTheInternet first (%s), so a blink of the "+
					"network turns it red - OBS150", function.Name.Name, fset.Position(use))
			}
		}
	}

	// THE CANARY. A reader that saw nothing would find no offender and pass,
	// and the four checks that do need the internet are known to be there.
	if reaching == 0 {
		t.Fatal("no function in the acceptance files reaches for aRealName, so this read nothing - " +
			"the four checks that need a real server were expected to be found")
	}
}

// firstUseAndGate returns where body first names aRealName and where it first
// calls needsTheInternet, each token.NoPos when it does not.
func firstUseAndGate(body *ast.BlockStmt) (use, gate token.Pos) {
	ast.Inspect(body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CallExpr:
			if called, ok := typed.Fun.(*ast.Ident); ok && called.Name == "needsTheInternet" && !gate.IsValid() {
				gate = typed.Pos()
			}
		case *ast.Ident:
			if typed.Name == "aRealName" && !use.IsValid() {
				use = typed.Pos()
			}
		}
		return true
	})
	return use, gate
}
