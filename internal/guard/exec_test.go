package guard

import (
	"fmt"
	"testing"
)

// execAllowlist names the files allowed to start another program.
//
// WHY THIS LIST EXISTS AT ALL, AND IT IS NOT WHAT IT LOOKS LIKE. The layer guard
// already forbids os/exec, but it forbids it in internal/core/ ONLY, because
// coreForbiddenStdlib is attached to that one layer in layerMap. An adapter has
// always been free to run anything - it is the layer that talks to the world,
// which is why internal/adapter/privilege may import syscall. So this list does
// not relax a rule. It closes a hole the tree already knew about and named: the
// comment on checkWrites says os/exec "can run a program that writes. The layer
// guard keeps that out of the core, and nothing keeps it out of an adapter YET".
// This is the yet - ADR49.
//
// ONE FILE RATHER THAN THREE PROBES, and that is the whole shape. L5 has to ask
// keytool what a Java keystore holds and curl which TLS backend it was built
// against, because neither answer is readable from disk: measured 2026-08-18,
// the stores on this machine are PKCS12 in the JDKs and JKS in the JRE, and
// mingw64\bin ships libcurl-4.dll and libcurl-openssl-4.dll side by side, so a
// backend read off the filesystem would be a guess. Letting each probe run its
// own process would put ONE RULE IN THREE PLACES - the measured shape of OBS50,
// where a copy of a boundary function disarmed three mutation entries at once
// and reported them as SKIP. The rule lives once, this list has one entry, and
// the number of places able to start somebody else's code stays countable.
//
// git is deliberately NOT here. Its backend and its bundle are plain INI, read
// with the file guard's permission like any other file - measured on the same
// day. A probe that does not need a process does not get one.
var execAllowlist = map[string]bool{
	// The one place. Every probe calls probe.Run, so the four narrowing rules of
	// ADR49 - absolute path, arguments from our own constants, no shell, nothing
	// on the child stdin - are consumed rather than copied. A second file here
	// would be one rule in two places, which is the measured shape of OBS50.
	"internal/adapter/probe/exec.go": true,
}

// execPackages are the imports able to start another program.
var execPackages = map[string]bool{
	"os/exec": true,
}

// TestNothingOutsideTheAllowlistStartsAProcess is the guard.
//
// It reads DECLARED imports rather than calls, for the reason checkDialing
// gives: this kind of rule erodes one innocent looking import at a time, each
// unused on the day it was added.
func TestNothingOutsideTheAllowlistStartsAProcess(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkExec(tr), "process execution outside the allowlist")
}

// TestTheExecGuardCanFail is the canary, and while the list is empty it is
// carrying the entire weight of this file.
//
// An empty allowlist means the check above runs over a set with nothing in it
// and would look exactly the same if it had read no files at all. That is the
// state reach_test.go was in until 2026-08-10, and it is why every list here
// gets a canary of its own rather than sharing one.
func TestTheExecGuardCanFail(t *testing.T) {
	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		// The layer fixture already imports os/exec, which is the whole reason
		// it is reused rather than copied: a second fixture saying the same
		// thing is a second place to keep in step.
		files: []sourceFile{loadFixture(t, "layer_violation.go", "internal/adapter/probe/planted.go")},
	}
	requireViolation(t, checkExec(planted), "may not start another program")
}

// TestAnAllowlistedFileMayStartAProcess proves the list is consulted rather than
// decorative. Without it the guard could be refusing everything and still look
// exactly like a guard that works.
func TestAnAllowlistedFileMayStartAProcess(t *testing.T) {
	execAllowlist["internal/adapter/probe/planted.go"] = true
	defer delete(execAllowlist, "internal/adapter/probe/planted.go")

	planted := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "layer_violation.go", "internal/adapter/probe/planted.go")},
	}
	for _, v := range checkExec(planted) {
		t.Errorf("an allowlisted file was reported anyway: %s", v.Detail)
	}
}

// TestTheExecAllowlistNamesFilesThatExist is the fifth place this shape stands
// in the tree - OBS63 records the four before it, and the point of writing it
// now is that an entry naming a file that is not there is an exemption waiting
// in ambush: it costs nothing while the path is empty, and starts exempting
// whatever later appears under a name chosen for entirely different reasons.
func TestTheExecAllowlistNamesFilesThatExist(t *testing.T) {
	tr := mustLoadModule(t)
	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for rel := range execAllowlist {
		if !present[rel] {
			t.Errorf("the exec allowlist names %s, which is not in the tree", rel)
		}
	}
}

// checkExec reports every file outside the list that declares an import able to
// start another program.
//
// WHAT IT DOES NOT SEE, said here rather than discovered later. A dependency
// that runs a process from inside its own tree, and any of the four narrowing
// rules of ADR49 - an absolute path, arguments from our own constants, no
// shell, nothing written to the child's input. Those live in the one allowed
// file and are checked by its own tests, because they are about VALUES and this
// scanner reads imports.
func checkExec(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || execAllowlist[sf.rel] {
			continue
		}
		for _, imp := range importsOf(sf) {
			if !execPackages[imp.path] {
				continue
			}
			violations = append(violations, Violation{sf.rel, imp.line, fmt.Sprintf(
				"%s may not start another program - somebody else's process can write, which is the one thing "+
					"inviolable rule 14 forbids, so every place able to start one has to be on the short list in exec_test.go", sf.rel)})
		}
	}
	return sortViolations(violations)
}
