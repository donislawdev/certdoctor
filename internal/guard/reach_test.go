package guard

import (
	"fmt"
	"go/ast"
	"testing"
)

// dialAllowlist names the files allowed to reach the network.
//
// IT WAS EMPTY UNTIL 2026-08-10 AND THE COUNT IS DELIBERATELY NOT WRITTEN HERE
// ANY MORE - it went stale the first time the list grew, and a number in a
// comment above the thing it counts is a number nobody updates. Read the entries.
//
// An entry here is not a formality: it means there is one more place in this
// program where a connection can begin, and the promise of inviolable rule 16 -
// that certdoctor connects only to what it derived from the user's own question -
// rests on how few such places there are. Each entry goes in together with the
// code it covers, never ahead of it.
//
// THE SENTENCE THAT USED TO DESCRIBE THIS LIST'S CONTENTS HAS BEEN REMOVED, AND
// ITS REMOVAL IS THE POINT. It said "two lenses of L1 and one layer below it,
// and nothing else", and it was already wrong when a fourth entry arrived - the
// same failure the paragraph above warns about, committed one paragraph later.
// What is worth saying instead does not go stale: EVERY ENTRY CONSULTS THE SAME
// REFUSAL RULE rather than a copy of it, so a mutation entry aimed at that rule
// aims at all of them; and each new entry is a new WAY to start a connection,
// which should be as hard to add as the ones before it. Read the entries.
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

	// The connection L3 opens to each address a name resolved to, added
	// 2026-08-12 with the code it covers. It is the first place in this program
	// that connects to the TARGET rather than to infrastructure - a resolver is
	// something we ask about the target, this is the target itself.
	//
	// It does not go through dial.Guarded either, and for a different reason than
	// system.go: this port hands back an io.Closer, because L3 only needs to know
	// whether the connection opens and closes it at once. It asks dial.Permission
	// directly - the same function, consumed rather than copied.
	"internal/adapter/tcp/network.go": true,

	// The connection L4 opens to complete a handshake, added 2026-08-17 with the
	// code it covers. IT IS A SECOND CONNECTION TO AN ADDRESS L3 ALREADY TRIED,
	// and that is not waste: L3 answers whether the port accepts anything and
	// closes at once, and a connection cannot be handed between layers without
	// welding them together - the seam between them is a list of strings.
	//
	// It borrows BOTH halves rather than copying either: dial.Permission for the
	// rule, tcp.Target for the spelling. A fourth entry here therefore adds a
	// place that connects, not a fourth answer to "may we".
	"internal/adapter/handshake/handshake.go": true,

	// The request L2 makes for an automatic configuration script, added
	// 2026-09-06 with the code it covers. IT IS THE FIRST ENTRY HERE THAT IS NOT
	// ABOUT THE TARGET OR ABOUT ASKING SOMEBODY ABOUT THE TARGET, and that is
	// what made it a separate decision rather than a fifth line: the four above
	// reach a resolver, the target, or the target again, and this one reaches an
	// address READ OUT OF THIS MACHINE'S CONFIGURATION. Rule 16 lists it as the
	// fifth permitted derivation, so it is allowed - but it is the first place
	// where what this program connects to was chosen by somebody other than the
	// user, and the set is widened for it only from the entry point, which the
	// widening guard below enforces.
	//
	// It borrows the rule rather than copying it, like the three before it:
	// dial.Permission goes in front of the transport's own DialContext, so a
	// mutation entry aimed at the refusal still aims at this caller too.
	//
	// IT IS ONE FILE AND NOT THE PACKAGE, deliberately, and here that matters
	// more than anywhere else on this list: internal/adapter/pac also holds the
	// engine that runs somebody else's JavaScript, and the sandbox's first
	// condition is that it has no network. Listing the package would put the
	// evaluator on the wrong side of that sentence.
	"internal/adapter/pac/fetch.go": true,

	// The question L2 puts to a proxy, added 2026-09-07 with the code it covers.
	// IT IS THE FIRST ENTRY HERE THAT SPEAKS TO A MACHINE IN ORDER TO LEARN
	// SOMETHING ABOUT THAT MACHINE ITSELF, and that is what made it a separate
	// decision rather than a sixth line. The five above reach a resolver, the
	// target, the target again, or the place a configuration file is kept; this
	// one asks a proxy a question whose whole answer is about the proxy. Rule 16
	// lists it as the fourth permitted derivation, so it is allowed - and like
	// the script fetch it reaches an address chosen by somebody other than the
	// user, so the set is widened for it only from the entry point.
	//
	// IT IS WIDENED LATER THAN ANY OTHER ENTRY ON THIS LIST, which is worth
	// knowing before touching it. Every address here but this one is in the set
	// before the layer that dials it starts; a proxy is learned in the middle of
	// L2's own work, so the orchestrator widens the set BETWEEN the two halves of
	// that layer. The rule that stays true is the one that matters: the widening
	// still happens in the entry point's closure and never in the layer.
	//
	// It borrows the rule rather than copying it, like the four before it:
	// dial.Permission goes in front of the dialler, so a mutation entry aimed at
	// the refusal still aims at this caller too.
	//
	// IT IS ONE FILE AND NOT THE PACKAGE, deliberately, and the package holds
	// nothing else today - which is the point of naming the file rather than the
	// directory. A second way to open a connection cannot appear beside this one
	// without turning this test red.
	"internal/adapter/proxyauth/challenge.go": true,
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

// allowedPackage is the set of places this run may reach.
const allowedPackage = "github.com/donislawdev/certdoctor/internal/core/allowed"

// wideningAllowlist names the files allowed to ADD to that set.
//
// THE TWO REACH LISTS ABOVE ASK WHO MAY OPEN A CONNECTION. THIS ONE ASKS WHO MAY
// DECIDE WHERE ONE IS ALLOWED TO GO, and until 2026-09-03 nothing asked it at
// all. The rule was true and unguarded: Allow is declared once, on
// *allowed.Targets, and called from one file, so a reader had to reconstruct the
// invariant from where the calls happened to be.
//
// WHAT IT PROTECTS IS NOT A CRASH TODAY BUT ONE THAT CANNOT BE CAUGHT. The
// entry point writes this map on the goroutine that walks the layers, between L1
// and L3, and the eight fan-out goroutines of L3 and L4 only read it. Concurrent
// reads of a map are safe, a read racing a write is a fatal error - not a panic,
// so recover does not see it, and the run dies with no report and a code from
// outside the table. That is the same failure ADR63 bought Freeze to avoid for
// the system view, whose goroutines outlive the call that started them.
//
// IT GOES IN BEFORE THE CODE THAT WOULD BREAK IT, WHICH IS THE ONLY TIME A GUARD
// IS CHEAP. P8-K2 introduces ReasonProxy and ReasonPACFile - two new reasons to
// widen the set, arriving in a layer that has its own inputs and outputs. A
// guard written afterwards arrives to find the rule already broken, and is then
// a repair rather than a protection. The reach lists above could start at zero
// for exactly this reason, and this one starts at one.
//
// AN ENTRY HERE IS NOT A FORMALITY. It means one more place that can decide
// where this program is permitted to connect, which is the promise of inviolable
// rule 16 read from the other end.
var wideningAllowlist = map[string]bool{
	// The entry point, and only the entry point. Every widening happens here,
	// before L3 exists as a possibility - a layer that adds its own targets is a
	// layer permitting itself, which would make the set a description of what
	// happened rather than a rule about what may.
	"cmd/certdoctor/cli.go": true,
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

// TestNothingOutsideTheAllowlistWidensTheAllowedSet is the third question, and
// it is about the rule rather than about the reaching.
//
// The two checks above ask who may open a connection. This one asks who may say
// where one is permitted to go - and getting that wrong does not produce a
// refusal a reader can see, it produces a set that quietly agrees with whatever
// happened.
func TestNothingOutsideTheAllowlistWidensTheAllowedSet(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkWidening(tr), "the allowed set widened outside the allowlist")
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

	// The widening guard, added 2026-09-03. Its canary matters more than the
	// other two, not less: the list it consults has a single entry and the check
	// would look exactly the same if the scanner had stopped reading files.
	widening := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "widens_the_set.go", "internal/core/probe/planted.go")},
	}
	requireViolation(t, checkWidening(widening), "may not widen")
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

	wideningAllowlist["internal/adapter/probe/planted.go"] = true
	defer delete(wideningAllowlist, "internal/adapter/probe/planted.go")

	widening := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "widens_the_set.go", "internal/adapter/probe/planted.go")},
	}
	requireNoViolations(t, checkWidening(widening), "an allowlisted file widening the allowed set")
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
	for _, list := range []map[string]bool{dialAllowlist, fileReadAllowlist, wideningAllowlist} {
		for rel := range list {
			if !present[rel] {
				t.Errorf("an allowlist names %s, which is not in the tree", rel)
			}
		}
	}
}

// checkWidening reports every file outside the list that adds to the set of
// places this run may reach.
//
// IT READS CALLS RATHER THAN IMPORTS, and unlike checkDialing that is forced
// rather than chosen: internal/core/allowed is imported all over this program to
// ASK the set whether an address is permitted, which is the read side and is
// exactly what the rule wants everywhere. Only the write side is rare. An import
// based check here would report every layer and cover nothing.
//
// The import is still consulted, as a narrowing rather than as the rule: Allow
// is declared once in this module, on *allowed.Targets, so a call to something
// named Allow in a file that never imports that package belongs to somebody
// else's type and is not this guard's business.
//
// WHAT IT DOES NOT SEE, said here rather than discovered later: a widening
// reached through a function value or an interface, where the name Allow never
// appears at the call site. The entry point hands Wire an Authorise callback
// doing exactly that, which is why cli.go is on the list and Wire is not - the
// decision is still taken in the one allowed place, and this scanner would not
// have caught it if it were not.
func checkWidening(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || wideningAllowlist[sf.rel] {
			continue
		}
		knowsTheSet := false
		for _, imp := range importsOf(sf) {
			if imp.path == allowedPackage {
				knowsTheSet = true
				break
			}
		}
		if !knowsTheSet {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Allow" {
				return true
			}
			violations = append(violations, Violation{sf.rel, sf.fset.Position(call.Pos()).Line, fmt.Sprintf(
				"%s may not widen the set of places this run may reach - the set is written on the goroutine that "+
					"walks the layers and READ by the fan-out goroutines of L3 and L4, so a write from anywhere else "+
					"is a fatal error recover cannot catch, and the run dies with no report at all", sf.rel)})
			return true
		})
	}
	return sortViolations(violations)
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
