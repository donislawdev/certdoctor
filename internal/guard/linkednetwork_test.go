package guard

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// WHAT THE BINARIES LINK OF SOMEBODY ELSE'S NETWORKING (2026-11-11, beside
// notelemetry_test.go). The guards on our source read our source. A module we
// depend on reaches the network from inside its own tree, where none of them
// looks, and tools/expected-modules.txt holds which MODULES are linked, not
// which of their packages - a toolkit raised by one version can bring a package
// that dials without a single line of ours changing.
//
// So the compiler is asked, for every program and every build that ships,
// which packages outside this module and the standard library import a network
// package (networkPackage in reach_test.go) or os/exec, and the answer is held
// to the registry below, exact in both directions. Measured 2026-11-11: the
// command line links none - its only network imports are our six adapters -
// and the window links the toolkit's.
//
// It also closes the claim parseOnlyPackages makes: an entry there that imports
// a network package itself, in any build, is reported - the list says those
// packages only parse, and this is where that is asked rather than believed.
//
// What it cannot see: a package that reaches the network through syscall
// rather than through an import, and C code.

// linkedWaysOut are the imports of somebody else's packages, by program, that
// can open a connection or start a program, each with why it is accepted.
var linkedWaysOut = map[string]string{
	"./cmd/certdoctor-gui|fyne.io/fyne/v2 -> net/http": "LoadResourceFromURLString in resource.go, an http.Get " +
		"nothing of ours calls - notelemetry_test.go refuses it",
	"./cmd/certdoctor-gui|fyne.io/fyne/v2/internal/repository -> net/http": "the toolkit's handler of http and " +
		"https addresses, which app.New puts behind both schemes (fyne v2.8.2 app/app.go) - reached only through " +
		"an address of that scheme, and notelemetry_test.go refuses every way of making one",
	"./cmd/certdoctor-gui|fyne.io/fyne/v2/storage/repository -> net": "net.ParseIP in parse.go, to read an " +
		"address in a URI - parsing only",
	"./cmd/certdoctor-gui|golang.org/x/sys/windows -> net": "types of socket addresses beside the system calls " +
		"of Windows - the calls that use them are refused by notelemetry_test.go",
	"./cmd/certdoctor-gui|github.com/godbus/dbus/v5 -> net": "the session bus the toolkit talks to on a Linux " +
		"desktop, at the address DBUS_SESSION_BUS_ADDRESS names - a socket on this machine unless that variable " +
		"says tcp",
	"./cmd/certdoctor-gui|github.com/godbus/dbus/v5 -> os/exec": "dbus-launch when no session bus is named, and " +
		"launchctl on macOS to find one (conn_other.go, conn_darwin.go)",
	"./cmd/certdoctor-gui|fyne.io/fyne/v2/app -> os/exec": "OpenURL hands a page to the system's opener - " +
		"rundll32, open or xdg-open - and on macOS osascript for a notification",
	"./cmd/certdoctor-gui|fyne.io/fyne/v2/dialog -> os/exec": "xdg-user-dir on Linux, asking where the " +
		"person's folders are for the folder dialog (file_xdg.go)",
	"./cmd/certdoctor-gui|github.com/jeandeaual/go-locale -> os/exec": "the person's language on macOS, " +
		"asked of the system (locale_darwin.go)",
}

// linkedFinding is one import of somebody else's package that can reach out,
// keyed the way linkedWaysOut is, with the builds it was found in.
type linkedFinding map[string][]string

// waysOutLinked adds to found the imports of packages outside this module and
// the standard library that can open a connection or start a program, and to
// broken the parse-only packages that import a network package after all.
func waysOutLinked(program string, build string, packages []listedPackage, found linkedFinding, broken *[]string) {
	for _, p := range packages {
		if _, parses := parseOnlyPackages[p.ImportPath]; parses {
			for _, imp := range p.Imports {
				if networkPackage(imp) {
					*broken = append(*broken, fmt.Sprintf("%s is on parseOnlyPackages and imports %s in %s", p.ImportPath, imp, build))
				}
			}
		}
		if p.Standard || (p.Module != nil && p.Module.Main) {
			continue
		}
		for _, imp := range p.Imports {
			if networkPackage(imp) || imp == "os/exec" {
				key := program + "|" + p.ImportPath + " -> " + imp
				found[key] = append(found[key], build)
			}
		}
	}
}

// TestTheBinariesLinkNoWayOutOfSomebodyElsesNobodyNamed is the guard.
func TestTheBinariesLinkNoWayOutOfSomebodyElsesNobodyNamed(t *testing.T) {
	root, _, err := findModuleRoot()
	if err != nil {
		t.Fatalf("finding the module root: %v", err)
	}
	found, broken := linkedFinding{}, []string{}
	for _, program := range noticedPrograms {
		for _, target := range program.targets {
			waysOutLinked(program.pkg, target[0]+"/"+target[1], listPackages(t, root, program, target), found, &broken)
		}
	}
	for _, problem := range broken {
		t.Errorf("%s - it only parses, the list says, so it imports no network package.", problem)
	}
	for _, problem := range settleLinked(found, linkedWaysOut) {
		t.Error(problem)
	}
}

// settleLinked are the findings no entry names and the entries nothing found.
func settleLinked(found linkedFinding, registry map[string]string) []string {
	var problems []string
	for key, builds := range found {
		if registry[key] == "" {
			problems = append(problems, fmt.Sprintf("%s, in %s, is not in linkedWaysOut in linkednetwork_test.go - "+
				"somebody else's code in a shipped binary that can open a connection or start a program, so a "+
				"new one is read at source and written there with why it is accepted", key, strings.Join(builds, ", ")))
		}
	}
	for key := range registry {
		if len(found[key]) == 0 {
			problems = append(problems, fmt.Sprintf("linkedWaysOut accepts %s, and no shipped build links it - delete the line", key))
		}
	}
	sort.Strings(problems)
	return problems
}

// The command line links nothing of somebody else's that can reach out - the
// sentence the registry would stop saying quietly the day it gained a line.
func TestTheCommandLineLinksNoWayOutOfSomebodyElses(t *testing.T) {
	for key := range linkedWaysOut {
		if strings.HasPrefix(key, "./cmd/certdoctor|") {
			t.Errorf("linkedWaysOut accepts %s for the command line, which links nothing of somebody else's that can "+
				"reach out - that is a change of what the program is, not a line in a registry", key)
		}
	}
}

// The canary: planted answers of go list, read the way the real ones are.
func TestTheLinkedScanReadsWhatItMustRead(t *testing.T) {
	main := &struct {
		Path    string
		Version string
		Dir     string
		Main    bool
	}{Main: true}
	packages := []listedPackage{
		{ImportPath: "example.org/telemetry", Imports: []string{"net/http", "fmt"}},
		{ImportPath: "example.org/shell", Imports: []string{"os/exec"}},
		{ImportPath: "example.org/quic", Imports: []string{"golang.org/x/net/quic"}},
		{ImportPath: "example.org/svg", Imports: []string{"golang.org/x/net/html/charset"}},
		{ImportPath: "net/http", Standard: true, Imports: []string{"net", "crypto/tls"}},
		{ImportPath: "github.com/donislawdev/certdoctor/internal/adapter/tcp", Module: main, Imports: []string{"net"}},
		{ImportPath: "golang.org/x/net/html/charset", Imports: []string{"net/http"}},
	}
	found, broken := linkedFinding{}, []string{}
	waysOutLinked("./cmd/certdoctor", "linux/amd64", packages, found, &broken)
	want := []string{
		"./cmd/certdoctor|example.org/quic -> golang.org/x/net/quic",
		"./cmd/certdoctor|example.org/shell -> os/exec",
		"./cmd/certdoctor|example.org/telemetry -> net/http",
		"./cmd/certdoctor|golang.org/x/net/html/charset -> net/http",
	}
	var got []string
	for key := range found {
		got = append(got, key)
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the scan found\n  %s\nand had to find\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	if len(broken) != 1 || !strings.Contains(broken[0], "golang.org/x/net/html/charset") {
		t.Errorf("a parse-only package importing net/http gave %v, and had to give one problem", broken)
	}
	if problems := settleLinked(found, map[string]string{"./cmd/certdoctor|gone -> net": "x"}); len(problems) != len(want)+1 {
		t.Errorf("four unnamed findings and one stale entry gave %d problem(s): %v", len(problems), problems)
	}
}
