package guard

import (
	"fmt"
	"go/ast"
	"testing"
)

// writeAllowlist names the files allowed to write to the filesystem.
//
// It is empty, and that is the correct state: certdoctor diagnoses and does not
// repair. The one file it will ever create is a report at a path the user named
// explicitly, and that renderer is the first and probably only entry this list
// ever gets. Adding one is a decision, which is the point.
var writeAllowlist = map[string]bool{}

// writeFunctions are the standard library calls that create, modify or delete
// something on disk.
//
// Reads are deliberately absent. Reading is what this tool does for a living.
var writeFunctions = map[string]bool{
	"Create":     true,
	"CreateTemp": true,
	"WriteFile":  true,
	"OpenFile":   true,
	"Mkdir":      true,
	"MkdirAll":   true,
	"MkdirTemp":  true,
	"Remove":     true,
	"RemoveAll":  true,
	"Rename":     true,
	"Truncate":   true,
	"Chmod":      true,
	"Chown":      true,
	"Symlink":    true,
	"Link":       true,
}

// TestNothingOutsideTheAllowlistWrites is the first executable slice of the
// promise on the first line of the README: certdoctor diagnoses, it never
// repairs. Until now that promise lived in prose, and prose is guarded by
// nothing.
func TestNothingOutsideTheAllowlistWrites(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoFindings(t, checkWrites(tr), "writes outside the allowlist")
}

// TestWriteGuardDetectsPlantedViolations is the canary. Nothing in the tree
// writes today, so the guard above would pass while blind.
func TestWriteGuardDetectsPlantedViolations(t *testing.T) {
	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files: []sourceFile{
			loadFixture(t, "writes_production.go", "internal/adapter/store/planted.go"),
			loadFixture(t, "writes_loose.go", "internal/adapter/store/planted_test.go"),
		},
	}
	findings := checkWrites(planted)

	requireFinding(t, findings, `"os.WriteFile" writes to disk`)
	requireFinding(t, findings, "writes without taking a temporary directory")
}

// TestATestThatTakesATemporaryDirectoryMayWrite keeps the guard usable. Without
// this half it would forbid the only correct way to write in a test, and would
// be switched off the first time somebody needed a fixture on disk.
func TestATestThatTakesATemporaryDirectoryMayWrite(t *testing.T) {
	allowed := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "writes_tempdir.go", "internal/adapter/store/planted_test.go")},
	}
	requireNoFindings(t, checkWrites(allowed), "a test writing under its own temporary directory")
}

// checkWrites reports filesystem writes: any in production code outside the
// allowlist, and any in a test that did not take a temporary directory.
//
// What it does not see:
//
//   - a write through a value obtained earlier, for example a *os.File handed
//     in as a parameter. The guard watches the calls that OBTAIN the ability to
//     write, which is where it enters a package.
//   - whether the path handed to a write in a test actually derives from
//     t.TempDir(). It checks that the file asks for one at all. A test could
//     take a temporary directory and then write somewhere else entirely.
//   - anything a dependency does. There are none today, and the module gate in
//     CI is what keeps that true.
//   - os/exec, which can run a program that writes. The layer guard keeps that
//     out of the core, and nothing keeps it out of an adapter yet.
func checkWrites(tr tree) []Finding {
	var findings []Finding

	for _, sf := range tr.files {
		if writeAllowlist[sf.rel] {
			continue
		}
		takesTempDir := callsTempDir(sf.file)

		ast.Inspect(sf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := osCallName(call)
			if !ok || !writeFunctions[name] {
				return true
			}
			line := sf.fset.Position(call.Pos()).Line

			if !sf.isTest {
				findings = append(findings, Finding{sf.rel, line, fmt.Sprintf(
					"%q writes to disk - certdoctor diagnoses and never repairs, so the only file it creates is a report at a path the user named",
					"os."+name)})
				return true
			}
			if !takesTempDir {
				findings = append(findings, Finding{sf.rel, line, fmt.Sprintf(
					"%q writes without taking a temporary directory - a test suite is the likeliest source of litter in the working tree",
					"os."+name)})
			}
			return true
		})
	}
	return sortFindings(findings)
}

// osCallName returns the function name of a call of the form os.Something.
func osCallName(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "os" {
		return "", false
	}
	return sel.Sel.Name, true
}

func callsTempDir(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && sel.Sel.Name == "TempDir" {
			found = true
		}
		return !found
	})
	return found
}
