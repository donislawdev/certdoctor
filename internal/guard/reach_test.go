package guard

import (
	"fmt"
	"go/ast"
	"testing"
)

// dialAllowlist names the files allowed to reach the network.
//
// IT IS EMPTY, AND THAT IS THE CORRECT STATE TODAY. Nothing in this program
// connects to anything yet. The guard is written now, before L1, for the reason
// the whole ordering of this project rests on: a guard written afterwards
// arrives to find the rule already broken, and then it is something to repair
// rather than something that protects.
//
// An entry here is not a formality. It means there is one more place in this
// program where a connection can begin, and the promise of inviolable rule 16 -
// that certdoctor connects only to what it derived from the user's own question
// - rests on how few such places there are. The entry goes in together with the
// code it covers, never ahead of it.
var dialAllowlist = map[string]bool{}

// networkPackages are the standard library imports that can open a connection.
//
// net/url is deliberately absent: it parses and reaches nothing. So is crypto/
// tls, which cannot connect on its own - it needs a connection handed to it,
// and that connection comes from one of these.
var networkPackages = map[string]bool{
	"net":                    true,
	"net/http":               true,
	"net/smtp":               true,
	"net/rpc":                true,
	"golang.org/x/net/proxy": true,
}

// fileReadAllowlist names the files allowed to open something on disk for
// reading.
//
// WHY READING NEEDS A LIST AT ALL, WHEN THE WRITE GUARD SAYS READING IS WHAT
// THIS TOOL DOES FOR A LIVING. Because a path is not always a disk. On Windows
// a UNC path opened like an ordinary file is a connection to a host the user
// never named, authenticated with their own token - and the network guard above
// CANNOT SEE IT, because nothing passes through a network package on the way.
// That is docs/14 section 3a, and it is not our reasoning: it comes from a
// measured review of a neighbouring project, where checking for a file under a
// UNC path to an unreachable host answered after 21 seconds against 1.2 ms for
// a local one.
//
// So the file layer is a second route out, and it needs a second list.
//
// UNLIKE THE DIAL LIST ABOVE, THIS ONE WAS NOT EMPTY ON THE DAY IT WAS WRITTEN,
// and finding that out took one run. Two places in this tree already turn a
// path into something readable, and both are correct - but "correct" is a thing
// somebody decided, not a thing the code says on its own, so both are named
// here with the decision beside them.
var fileReadAllowlist = map[string]bool{
	// The report destination, and the path came FROM THE USER on the command
	// line - which is the one origin inviolable rule 16 never had a problem
	// with. This file is also the single entry on the write allowlist, so the
	// one place allowed to create a file is the one place allowed to ask about
	// it first.
	"internal/adapter/output/atomic.go": true,

	// The guards read the repository they guard. This is the scanner every one
	// of them is built on, it never sees a path from anybody's configuration,
	// and it is not shipped. It is named here rather than excluded by directory
	// on purpose: an exclusion would silently cover every guard file written
	// from now on, and this list is meant to be read.
	"internal/guard/scan.go": true,
}

// fileOpeningFunctions are the standard library calls that turn a path into
// something readable.
//
// os.Stat and friends are here too, and that is deliberate: a UNC path is
// reached by ASKING ABOUT IT, not only by opening it. The 21 seconds measured
// in that neighbouring project were spent on an existence check.
var fileOpeningFunctions = map[string]bool{
	"Open":     true,
	"ReadFile": true,
	"ReadDir":  true,
	"Stat":     true,
	"Lstat":    true,
	"OpenFile": true,
}

// TestNothingOutsideTheAllowlistReachesTheNetwork is inviolable rule 16 turned
// into something a machine can check.
//
// The promise it defends is the one a user cannot verify for themselves - that
// a diagnostic tool reading their trust stores does not phone home - and at a
// tool like this one it decides whether it is allowed to run inside a company.
func TestNothingOutsideTheAllowlistReachesTheNetwork(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkDialing(tr), "network access outside the allowlist")
}

// TestNothingOutsideTheAllowlistOpensAPath is the second half, and it exists
// because the first half is blind to it by construction.
func TestNothingOutsideTheAllowlistOpensAPath(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkFileOpening(tr), "path opening outside the allowlist")
}

// TestTheReachGuardsCanFail is the canary, and on this tree it carries the
// whole weight.
//
// Both lists are empty and nothing in the module dials or opens anything, so
// both checks above run over a set with nothing in it and would look exactly
// the same if they read no files at all.
func TestTheReachGuardsCanFail(t *testing.T) {
	dialing := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "reaches_network.go", "internal/core/probe/planted.go")},
	}
	requireViolation(t, checkDialing(dialing), "may not reach the network")

	opening := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "opens_a_path.go", "internal/core/probe/planted.go")},
	}
	violations := checkFileOpening(opening)
	requireViolation(t, violations, "may not open a path")

	// BOTH SHAPES, AND THIS HALF WAS PAID FOR BY THE MUTATION REGISTER. Dropping
	// Stat from the list of watched calls left every test in this file green,
	// because the only fixture read a file and none of them asked about one. The
	// 21 seconds in the review this rule comes from were spent on an existence
	// check, so the shape that hurts most was the shape nothing covered.
	requireViolation(t, violations, "os.ReadFile")
	requireViolation(t, violations, "os.Stat")
}

// TestAnAllowlistedFileMayReach is the other side of both rules. A guard that
// refused everything would pass the two checks above while being useless, and
// nobody would notice until the first real dialler could not be written.
func TestAnAllowlistedFileMayReach(t *testing.T) {
	dialAllowlist["internal/adapter/probe/planted.go"] = true
	fileReadAllowlist["internal/adapter/probe/planted.go"] = true
	defer delete(dialAllowlist, "internal/adapter/probe/planted.go")
	defer delete(fileReadAllowlist, "internal/adapter/probe/planted.go")

	dialing := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "reaches_network.go", "internal/adapter/probe/planted.go")},
	}
	requireNoViolations(t, checkDialing(dialing), "an allowlisted file reaching the network")

	opening := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "opens_a_path.go", "internal/adapter/probe/planted.go")},
	}
	requireNoViolations(t, checkFileOpening(opening), "an allowlisted file opening a path")
}

// TestTheReachAllowlistsNameFilesThatExist keeps both lists from rotting. A
// renamed file would drop off the list and the guard would go on passing while
// covering one place less.
func TestTheReachAllowlistsNameFilesThatExist(t *testing.T) {
	tr := mustLoadModule(t)
	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for _, list := range []map[string]bool{dialAllowlist, fileReadAllowlist} {
		for rel := range list {
			if !present[rel] {
				t.Errorf("an allowlist names %s, which is not in the tree", rel)
			}
		}
	}
}

// checkDialing reports every file outside the list that declares an import able
// to open a connection.
//
// It reads DECLARED imports rather than calls, for the same reason the layer
// guard does: this rule erodes one innocent looking import at a time, each of
// them unused on the day it was added.
//
// WHAT IT DOES NOT SEE, said here rather than discovered later: a dependency
// that reaches the network from inside its own tree. Our imports are what this
// reads, and docs/14 section 3 says so plainly - the guard is PARTIAL, and full
// proof needs a traffic monitor we do not have.
func checkDialing(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || dialAllowlist[sf.rel] {
			continue
		}
		for _, imp := range importsOf(sf) {
			if !networkPackages[imp.path] {
				continue
			}
			violations = append(violations, Violation{sf.rel, imp.line, fmt.Sprintf(
				"%s may not reach the network - inviolable rule 16 allows a connection only to what was derived "+
					"from the user's own question, and every place able to start one has to be on the short list in reach_test.go", sf.rel)})
		}
	}
	return sortViolations(violations)
}

// checkFileOpening reports every file outside the list that turns a path into
// something readable.
//
// It reads CALLS rather than imports, and the difference is forced: os is
// imported all over this program for things that touch nothing, so an import
// based rule would either report every file or cover none.
func checkFileOpening(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || fileReadAllowlist[sf.rel] {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "os" || !fileOpeningFunctions[selector.Sel.Name] {
				return true
			}
			violations = append(violations, Violation{sf.rel, sf.fset.Position(call.Pos()).Line, fmt.Sprintf(
				"%s may not open a path with os.%s - a path from somebody else's configuration can be a UNC path, "+
					"and opening one is a connection the network guard cannot see (docs/14 section 3a)", sf.rel, selector.Sel.Name)})
			return true
		})
	}
	return sortViolations(violations)
}
