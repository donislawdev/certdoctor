package guard

import (
	"fmt"
	"go/ast"
	"go/build"
	"io"
	"path"
	"slices"
	"strings"
	"testing"
)

// pureLayers are the three layers that work a verdict out of what they are
// handed and touch nothing themselves: the core, which grades evidence (ADR7),
// the orchestrator, which takes every port it uses as a parameter, and the
// tools, which judge the bytes a person hands them at the time the entry point
// hands them (ADR141 point 7). Three rules in this file hold them to that, and
// each one turns a sentence already written in a comment into something that
// fails.
var pureLayers = []string{"internal/core/", "internal/app/", "internal/tool/"}

// closedList is the standard library a layer may import, and why the list is
// closed.
type closedList struct {
	why      string
	packages []string
}

// closedStdlib names, for a layer, the ONLY standard library packages its files
// may import - tests included, because a test that reaches the disk is how a
// layer learns to need the disk.
//
// IT WAS A LIST OF SEVEN FORBIDDEN PACKAGES UNTIL 2026-11-11, and a forbidden
// list only forbids what somebody thought of. Measured that day: path/filepath
// walks and globs the disk, crypto/tls dials, log/syslog and net/rpc reach the
// network, io/ioutil reads files and math/rand makes a run unrepeatable - and
// every one of them was legal in the core. The orchestrator had no list at all,
// so os/exec was legal there. A closed list fails the other way: a package the
// layer has never used is refused until somebody writes it down here, and the
// standard library Go adds over the years arrives refused too.
//
// WHAT IS ON THE CORE'S LIST IS VALUES, NEVER PLACES. net/netip and net/url
// parse and format without a socket or a name lookup - net/netip joined on
// 2026-08-05 as a decision, because the alternative was writing IPv6 text
// formatting by hand in the one package that reads hostile bytes off the
// network. time carries durations and deadlines, and the clock itself arrives
// as a port (checkNoWallClock). io is there for its interfaces, never a reader
// of its own. context, sync and sync/atomic are how the core runs side by side
// (ADR45). crypto/x509 is NOT here, although it only parses: it holds
// SystemCertPool, which goes to the network on Windows (ADR101), and the core
// has never needed it.
//
// Every entry has to be used by some file of the layer - the check that every
// door in the layer map is used - so this list says exactly what the layer
// imports today, no more.
var closedStdlib = map[string]closedList{
	"internal/core/": {
		why: "the core is a pure function of evidence",
		packages: []string{
			"context", "errors", "fmt", "io", "net/netip", "net/url", "regexp", "slices", "sort",
			"strconv", "strings", "sync", "sync/atomic", "testing", "time", "unicode", "unicode/utf8",
		},
	},
	"internal/app/": {
		why:      "the orchestrator is handed every port it uses and touches nothing itself",
		packages: []string{"bytes", "context", "fmt", "io", "strings", "testing", "time"},
	},
	// The tools read what a person hands them, so their list is the core's
	// rule - values, never places - with the encodings they read in it
	// (ADR141 point 7). It is a list of its own rather than the core's grown,
	// so the core keeps exactly what it uses. reflect and slices are for the
	// tests.
	//
	// crypto/x509 AND WHAT READS A CERTIFICATE CAME HERE BY THE OWNER'S
	// DECISION (ADR146 decision 1), for the cert tool and the rules it shares
	// with L4 - crypto/x509/pkix, encoding/pem and encoding/asn1 to read it,
	// crypto/sha256, crypto/sha1 and encoding/hex for its fingerprints,
	// crypto/rsa and crypto/ecdsa for its key. It is
	// still kept out of the core, and the part of it that reaches the network
	// - SystemCertPool, and Verify without Roots, on Windows (ADR101) - is
	// refused everywhere by the guard on connections, so no tool calls it.
	"internal/tool/": {
		why: "a tool is a pure function of the bytes it is handed and the time it is given",
		packages: []string{
			"bytes", "crypto/ecdsa", "crypto/rsa", "crypto/sha1", "crypto/sha256", "crypto/x509",
			"crypto/x509/pkix", "encoding/asn1", "encoding/base64", "encoding/hex", "encoding/json",
			"encoding/pem", "errors", "fmt", "io", "math", "reflect", "regexp", "slices", "sort",
			"strconv", "strings", "testing", "time", "unicode/utf8",
		},
	},
}

// refusedStdlib judges one standard library import against the closed list of
// the layer the file stands in. A module from outside this repository is not
// its question - the guard on dependencies says where those may be imported.
func refusedStdlib(sf sourceFile, rule layerRule, imp declaredImport) (Violation, bool) {
	closed, isClosed := closedStdlib[rule.location]
	if !isClosed || isOutsideModule(imp.path) || slices.Contains(closed.packages, imp.path) {
		return Violation{}, false
	}
	return Violation{
		File: sf.rel,
		Line: imp.line,
		Detail: fmt.Sprintf("%s may not import %q - %s, and the standard library it may use is the closed list in closedStdlib",
			rule.location, imp.path, closed.why),
	}, true
}

// wallClock are the functions of package time that read the real clock or wait
// on it.
var wallClock = map[string]bool{
	"Now": true, "Since": true, "Until": true, "Sleep": true, "After": true,
	"Tick": true, "NewTimer": true, "NewTicker": true, "AfterFunc": true,
}

// TestThePureLayersReadNoClock holds a rule two layers already state in prose:
// "THE CLOCK IS THE PORT AND NEVER time.Until" stands in core/handshake and
// core/tcp, so a budget behaves the same in a test as on a machine. Nothing
// held it. Tests are free - they are where a real clock is measured against.
//
// What it does not see: a deadline set with context.WithTimeout, which reads
// the clock inside the standard library. That is how a budget is handed to a
// port, and it is allowed on purpose.
func TestThePureLayersReadNoClock(t *testing.T) {
	requireNoViolations(t, checkNoWallClock(mustLoadModule(t)), "the real clock read in a pure layer")
}

// TestTheClockGuardCanFail plants a file that reads the clock under its own
// name and under one of its own, and expects every reading reported in the
// orchestrator, none reported in an adapter or a test, and a constant of
// package time left alone.
func TestTheClockGuardCanFail(t *testing.T) {
	inApp := checkNoWallClock(plantedTree(t, "reads_the_clock.go", "internal/app/run/planted.go"))
	requireViolation(t, inApp, "clock.Now")
	requireViolation(t, inApp, "clock.Sleep")
	requireViolation(t, inApp, "time.Since")
	for _, v := range inApp {
		if strings.Contains(v.Detail, "Second") {
			t.Errorf("a constant of package time was reported as a clock reading: %s", v)
		}
	}
	for _, rel := range []string{"internal/adapter/probe/planted.go", "internal/core/tcp/planted_test.go"} {
		requireNoViolations(t, checkNoWallClock(plantedTree(t, "reads_the_clock.go", rel)), "the clock read in "+rel)
	}
}

// checkNoWallClock reports every reference to a wall clock function of package
// time in the production files of a pure layer, called or handed on as a value.
func checkNoWallClock(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || !hasAnyPrefix(sf.rel, pureLayers) {
			continue
		}
		for _, name := range importNames(sf, "time") {
			violations = append(violations, clockReadings(sf, name)...)
		}
	}
	return sortViolations(violations)
}

// clockReadings finds name.Now and its kin in one file.
func clockReadings(sf sourceFile, name string) []Violation {
	var found []Violation
	ast.Inspect(sf.file, func(n ast.Node) bool {
		sel, isSelector := n.(*ast.SelectorExpr)
		if !isSelector {
			return true
		}
		if pkg, isIdent := sel.X.(*ast.Ident); isIdent && pkg.Name == name && wallClock[sel.Sel.Name] {
			found = append(found, Violation{
				File: sf.rel,
				Line: sf.fset.Position(sel.Pos()).Line,
				Detail: fmt.Sprintf("%s.%s reads the real clock - a pure layer takes the clock as a port, so a budget behaves the same in a test",
					name, sel.Sel.Name),
			})
		}
		return true
	})
	return found
}

// importNames are the names a file uses for an imported package - every one of
// them, because Go lets a file import one package twice under two names. A
// blank import names nothing, and a dot import is refused everywhere by the
// guard on package hygiene.
func importNames(sf sourceFile, importPath string) []string {
	var names []string
	for _, spec := range sf.file.Imports {
		if literalValue(spec.Path) != importPath {
			continue
		}
		switch {
		case spec.Name == nil:
			names = append(names, path.Base(importPath))
		case spec.Name.Name != "_" && spec.Name.Name != ".":
			names = append(names, spec.Name.Name)
		}
	}
	return names
}

// TestThePureLayersReadTheSameOnEveryPlatform holds the core and the
// orchestrator free of files that build on one system only. A difference
// between systems belongs to the adapter that reads the system (rule 36), and
// the verdict worked out of its evidence is the same everywhere - which is what
// lets it be tested on one machine for all three.
func TestThePureLayersReadTheSameOnEveryPlatform(t *testing.T) {
	requireNoViolations(t, checkNoPlatformFiles(mustLoadModule(t)), "a platform file in a pure layer")
}

// TestThePlatformGuardCanFail plants a constrained file, a file named for a
// system and a file whose underscore names nothing, and expects the first two
// reported in the core and nothing reported in an adapter.
func TestThePlatformGuardCanFail(t *testing.T) {
	requireViolation(t, checkNoPlatformFiles(plantedTree(t, "builds_on_one_system.go", "internal/core/tcp/planted.go")),
		"//go:build windows")
	requireViolation(t, checkNoPlatformFiles(plantedTree(t, "reads_the_clock.go", "internal/app/run/planted_linux_test.go")),
		"named for one system")
	for _, rel := range []string{"internal/core/trust/linux_fix_test.go", "internal/adapter/dns/planted_windows.go"} {
		requireNoViolations(t, checkNoPlatformFiles(plantedTree(t, "reads_the_clock.go", rel)), rel)
	}
	requireNoViolations(t, checkNoPlatformFiles(plantedTree(t, "builds_on_one_system.go", "internal/adapter/dns/planted.go")),
		"a constrained adapter")
}

// checkNoPlatformFiles reports every file of a pure layer, tests included, that
// carries a build constraint or is named for one system or architecture.
func checkNoPlatformFiles(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if !hasAnyPrefix(sf.rel, pureLayers) {
			continue
		}
		if constraint := buildConstraint(sf); constraint != "" {
			violations = append(violations, Violation{File: sf.rel, Line: 1,
				Detail: constraint + " - a pure layer builds the same on every system, and a difference between systems belongs to an adapter"})
		}
		if namedForAPlatform(path.Base(sf.rel)) {
			violations = append(violations, Violation{File: sf.rel, Line: 1,
				Detail: "this file is named for one system or architecture, so it builds there only - a pure layer builds the same on every system"})
		}
	}
	return sortViolations(violations)
}

// buildConstraint returns the first build constraint above the package clause,
// in either spelling, or "".
func buildConstraint(sf sourceFile) string {
	for _, group := range sf.file.Comments {
		if group.Pos() > sf.file.Package {
			break
		}
		for _, c := range group.List {
			if strings.HasPrefix(c.Text, "//go:build") || strings.HasPrefix(c.Text, "// +build") {
				return c.Text
			}
		}
	}
	return ""
}

// namedForAPlatform asks the go command's own rule whether a file name
// restricts the build, rather than a copy of its list of systems: a context for
// a system that does not exist matches every file whose name restricts nothing,
// and no file named for a real one. The list Go keeps grows with Go, and a copy
// here would not.
func namedForAPlatform(base string) bool {
	nowhere := build.Context{GOOS: "nowhere", GOARCH: "nothing", OpenFile: func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("package planted\n")), nil
	}}
	match, err := nowhere.MatchFile(".", base)
	return err != nil || !match
}

// TestTheClosedListRefusesWhatTheForbiddenListLetThrough plants imports the old
// rule let through - path/filepath and crypto/tls in the core, os/exec in the
// orchestrator, which had no list at all. Each is refused in the pure layer it
// stands in, a package on the list and a module from outside are not judged
// here, and an adapter may still import what it needs.
func TestTheClosedListRefusesWhatTheForbiddenListLetThrough(t *testing.T) {
	inCore := checkLayerDirection(plantedTree(t, "reaches_past_the_list.go", "internal/core/tcp/planted.go"))
	requireViolation(t, inCore, `may not import "path/filepath" - the core is a pure function of evidence`)
	requireViolation(t, inCore, `may not import "crypto/tls"`)
	inApp := checkLayerDirection(plantedTree(t, "reaches_past_the_list.go", "internal/app/run/planted.go"))
	requireViolation(t, inApp, `may not import "os/exec" - the orchestrator is handed every port`)
	for _, v := range append(inCore, inApp...) {
		if strings.Contains(v.Detail, `"strings"`) || strings.Contains(v.Detail, "dop251") {
			t.Errorf("an import the closed list does not judge was refused: %s", v)
		}
	}
	requireNoViolations(t, checkLayerDirection(plantedTree(t, "reaches_past_the_list.go", "internal/adapter/probe/planted.go")),
		"an adapter importing the standard library")
}

// plantedTree is a tree of one fixture presented under a path of its own.
func plantedTree(t *testing.T, fixture, pretendRel string) tree {
	t.Helper()
	return tree{modulePath: "github.com/donislawdev/certdoctor", files: []sourceFile{loadFixture(t, fixture, pretendRel)}}
}
