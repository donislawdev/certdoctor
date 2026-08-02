package guard

import (
	"fmt"
	"go/ast"
	"testing"
)

// writeAllowlist names the files allowed to write to the filesystem.
//
// It holds exactly one entry and is meant to keep holding exactly one.
// certdoctor diagnoses and does not repair, so the only file it ever creates is
// a report at a path a person named on the command line, and this is the file
// that creates it.
//
// The entry was added deliberately, together with the code it covers, and the
// narrowness is what the promise rests on. A second entry is not a formality:
// it means there is a second place in this program where writing is possible,
// and the guard can no longer answer "one" to the question of how many there
// are. Everything else - every renderer, every future probe, the entry point
// itself - still cannot obtain a handle to write with.
//
// What this does NOT cover is written beside the check below: a write through a
// handle passed in as a parameter, and anything a subprocess does.
var writeAllowlist = map[string]bool{
	"internal/adapter/output/atomic.go": true,
}

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

// TestTheWriteAllowlistIsStillOneFileLong restates the size of the list on
// purpose, the same way the exit code table is restated.
//
// The promise on the first line of the README is that this tool never repairs,
// and what stands behind it is that there is exactly one place in the program
// where writing is possible at all. A second entry is a real decision and has to
// be made twice - once in the list and once here - rather than appearing in a
// diff that looks like it only touched a map.
func TestTheWriteAllowlistIsStillOneFileLong(t *testing.T) {
	const frozen = 1
	if len(writeAllowlist) != frozen {
		t.Errorf("%d files may write, the frozen count is %d - if that is intended, change both", len(writeAllowlist), frozen)
	}
	if !writeAllowlist["internal/adapter/output/atomic.go"] {
		t.Error("the one file allowed to write is not the one that writes")
	}
}

// TestTheWriteAllowlistNamesFilesThatExist stops the list from going stale.
//
// An entry naming a file that has been renamed or deleted still reads as a
// deliberate exemption, so the next person weighing a second entry sees a list
// of two. Worse, the exemption then covers nothing while the list says it
// covers something - which is the shape of every guard that has quietly stopped
// working.
func TestTheWriteAllowlistNamesFilesThatExist(t *testing.T) {
	tr := mustLoadModule(t)
	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for name := range writeAllowlist {
		if !present[name] {
			t.Errorf("%s is on the write allowlist and is not in the tree", name)
		}
	}
}

// TestWriteGuardDetectsPlantedViolations is the canary. Exactly one file in the
// tree writes and it is exempt, so the guard above would pass just as happily
// while blind to everything else.
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
