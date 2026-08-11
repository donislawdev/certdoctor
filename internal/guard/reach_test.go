package guard

import (
	"fmt"
	"go/ast"
	"testing"
)

// dialAllowlist names the files allowed to reach the network.
//
// IT WAS EMPTY UNTIL 2026-08-10 AND HAS TWO ENTRIES, which is still a number
// somebody can hold in their head. An entry here is not a formality: it means
// there is one more place in this program where a connection can begin, and the
// promise of inviolable rule 16 - that certdoctor connects only to what it
// derived from the user's own question - rests on how few such places there are.
// Each entry goes in together with the code it covers, never ahead of it.
//
// THE TWO ARE THE TWO LENSES OF L1 AND NOTHING ELSE: the socket our own queries
// go out of, and the dialler net.Resolver is handed for the system view. Both
// consult the same refusal rule. A third entry means a third way to start a
// connection, and it should be as hard to add as these two were.
//
// THE GUARD WAS WRITTEN BEFORE THERE WAS ANYTHING TO CATCH, at P3a, and that is
// why this list could start at zero. A guard written afterwards arrives to find
// the rule already broken and is then something to repair rather than something
// that protects. It also means this entry was added the way the rule intends: the
// scanner went red on the new file, and the line below is the answer to it.
var dialAllowlist = map[string]bool{
	// The UDP socket L1 sends a query out of, and nothing else. It is not called
	// directly anywhere: the entry point wraps it in dial.Guarded, so the allowed
	// set refuses an address the run did not derive before this file is reached.
	//
	// It is one FILE and not the package, deliberately. Everything else under
	// internal/adapter/dns - reading a reply, listing this machine's resolvers -
	// stays on the wrong side of this list, so a second way to open a connection
	// cannot appear next to the first one without turning this test red.
	"internal/adapter/dns/network.go": true,

	// The system view's dialler, added 2026-08-11 with the code it covers. It is
	// handed to net.Resolver, whose own shape it has to match, so it cannot go
	// through dial.Guarded like everything else - ADR35. It asks the SAME rule
	// instead: dial.Permission, consumed rather than copied, so an entry in the
	// mutation register aimed at the refusal still aims at both diallers.
	"internal/adapter/dns/system.go": true,
}

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

	// The plumbing behind the file port, added 2026-08-10 with L1. THIS IS THE
	// FIRST ENTRY THAT READS A PATH FROM SOMEBODY ELSE'S CONFIGURATION -
	// /etc/resolv.conf - which is the exact case the rest of this comment is
	// about, and it is why the port in front of it judges the path as written,
	// then resolves links, then judges what they led to, and only then opens.
	//
	// The rule itself is in file.go and touches nothing. Only this file does, so
	// the count of places able to turn a path into bytes goes up by one and stays
	// readable.
	"internal/adapter/file/live.go": true,
}

// fileReachingCalls are the standard library calls that make a path touch a
// filesystem, by package.
//
// os.Stat and friends are here too, and that is deliberate: a UNC path is
// reached by ASKING ABOUT IT, not only by opening it. The 21 seconds measured
// in that neighbouring project were spent on an existence check.
//
// path/filepath IS THE SECOND ENTRY AND IT WAS ADDED BECAUSE THIS GUARD HAD
// A HOLE THE SHAPE OF THE NEXT THING WE WERE ABOUT TO WRITE. The list used to
// ask only whether the package was os, so filepath.EvalSymlinks - which walks
// every component of a path on disk, and is exactly what the file port's new
// resolver is built on - went past it without a word. Found on 2026-08-05 while
// widening that port, not by a red run.
//
// Deliberately absent from the filepath entry: Clean, Join, Abs, Base and the
// rest. They rearrange text. Only these four go and look.
var fileReachingCalls = map[string]map[string]bool{
	"os": {
		"Open":     true,
		"ReadFile": true,
		"ReadDir":  true,
		"Stat":     true,
		"Lstat":    true,
		"OpenFile": true,
	},
	"filepath": {
		"EvalSymlinks": true,
		"Walk":         true,
		"WalkDir":      true,
		"Glob":         true,
	},
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

// TestTheReachGuardsCanFail is the canary, and it carried the whole weight until
// 2026-08-10.
//
// While both lists were empty, the two checks above ran over a set with nothing
// in it and would have looked exactly the same if they had read no files at all.
// That is no longer true - each list now names real files - but the canary stays
// and matters MORE, not less: from here on the checks pass partly because the
// allowlists say so, and a scanner that silently stopped scanning would look
// identical to one finding nothing outside them.
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
	requireViolation(t, violations, "may not reach a path")

	// ALL THREE SHAPES, AND THE MIDDLE ONE WAS PAID FOR BY THE MUTATION REGISTER.
	// Dropping Stat from the list of watched calls left every test in this file
	// green, because the only fixture read a file and none of them asked about
	// one. The 21 seconds in the review this rule comes from were spent on an
	// existence check, so the shape that hurts most was the shape nothing
	// covered.
	requireViolation(t, violations, "os.ReadFile")
	requireViolation(t, violations, "os.Stat")
	// The third was paid for the cheaper way, by noticing before writing the
	// code: the file port's resolver is built on this exact call, and until
	// 2026-08-05 this scanner could not see it.
	requireViolation(t, violations, "filepath.EvalSymlinks")
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
			if !ok || !fileReachingCalls[pkg.Name][selector.Sel.Name] {
				return true
			}
			violations = append(violations, Violation{sf.rel, sf.fset.Position(call.Pos()).Line, fmt.Sprintf(
				"%s may not reach a path with %s.%s - a path from somebody else's configuration can be a UNC path or "+
					"a link to one, and touching it is a connection the network guard cannot see (docs/14 section 3a)",
				sf.rel, pkg.Name, selector.Sel.Name)})
			return true
		})
	}
	return sortViolations(violations)
}
