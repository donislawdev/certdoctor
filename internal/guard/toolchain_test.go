package guard

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The window is built with cgo, so the C compiler's linker puts code of its own
// into it: start up code and a runtime that come with the compiler on the
// runner, not from this tree, and that no build record names - OBS208, ADR125.
// The notices guard reads what go list says is compiled and cannot see them.
//
// Three places describe that code, and each is read by something else: the pin,
// which window_toolchain.sh holds every release build of the window to by the
// linker's own map, the notices, which a person reads and the bill of materials
// is written from, and build_window.sh, which runs the reader. A library added
// to the pin alone would ship code whose licence nobody read, and a reader the
// build no longer runs would hold nothing to anything.
const (
	toolchainPin    = ".github/window-toolchain"
	toolchainReader = ".github/scripts/window_toolchain.sh"
	windowBuilder   = ".github/scripts/build_window.sh"
)

// A toolchainLibrary is one library the pin may name, with the section of the
// window's notices that answers for it, or with why none has to.
type toolchainLibrary struct {
	heading string
	why     string
}

// toolchainLibraries are the libraries the pin may name. A library this map
// does not know is refused, so the first build that links code of a new one
// asks somebody to read its licence before it can say whose it is.
var toolchainLibraries = map[string]toolchainLibrary{
	// MinGW-w64 wrote COPYING.MinGW-w64-runtime.txt for a program statically
	// linked against its runtime, and asks that the notices in it travel with it.
	"mingw-w64": {heading: "MinGW-w64 runtime"},
	// Two of the six start files are LGPL-2.1-or-later without the permission to
	// link them anywhere that the other four give, and section 6 of that licence
	// asks for a notice with a copy linked into another program.
	"glibc": {heading: "GNU C Library"},
	// The GCC Runtime Library Exception, version 3.1, section 1: a combination of
	// GCC's runtime with independent modules may be conveyed "under terms of your
	// choice" (https://www.gnu.org/licenses/gcc-exception-3.1.html, read
	// 2026-11-11). The opening of the notices says so and quotes nothing.
	"gcc": {why: "the GCC Runtime Library Exception lets a program carry GCC's runtime under terms of its own"},
}

// toolchainHeadings are the sections of the window's notices that answer for
// the compiler's own code, sorted.
func toolchainHeadings() []string {
	var out []string
	for _, lib := range toolchainLibraries {
		if lib.heading != "" {
			out = append(out, lib.heading)
		}
	}
	sort.Strings(out)
	return out
}

// pinnedToolchain is what the pin says, for each target the window is built for.
type pinnedToolchain struct {
	links    map[string]map[string]string // target to file to library
	versions map[string]map[string]string // target to library to version
	nothing  map[string]bool
}

// toolchainLineFields is how many fields each kind of line of the pin has.
var toolchainLineFields = map[string]int{"link": 4, "version": 4, "nothing": 2}

func parseToolchainPin(rel, body string) (pinnedToolchain, []Violation) {
	pin := pinnedToolchain{links: map[string]map[string]string{}, versions: map[string]map[string]string{}, nothing: map[string]bool{}}
	var problems []Violation
	at := func(line int, format string, args ...any) {
		problems = append(problems, Violation{rel, line, fmt.Sprintf(format, args...)})
	}
	for i, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		want := toolchainLineFields[fields[0]]
		switch {
		case want == 0:
			at(i+1, "has a %s line, and a line is link, version or nothing", fields[0])
		case len(fields) != want:
			at(i+1, "has %d fields where a %s line has %d", len(fields), fields[0], want)
		case !isWindowTarget(fields[1]):
			at(i+1, "names %s, which is not a target the window is built for", fields[1])
		default:
			if why := pin.take(fields); why != "" {
				at(i+1, "%s", why)
			}
		}
	}
	for _, t := range windowTargets {
		for _, why := range pin.gaps(t[0] + "/" + t[1]) {
			at(0, "%s", why)
		}
	}
	return pin, problems
}

// take records one line of the pin, or says why it cannot.
func (p pinnedToolchain) take(fields []string) string {
	target := fields[1]
	switch fields[0] {
	case "nothing":
		if p.nothing[target] {
			return "says twice that " + target + " links nothing of the compiler's"
		}
		p.nothing[target] = true
	case "link":
		file, lib := fields[2], fields[3]
		if _, known := toolchainLibraries[lib]; !known {
			return fmt.Sprintf("says %s is of %s, a library nobody has read the licence of - add it to toolchainLibraries first", file, lib)
		}
		return setOnce(p.links, target, file, lib)
	case "version":
		lib, version := fields[2], fields[3]
		if toolchainLibraries[lib].heading == "" {
			return fmt.Sprintf("names a version of %s, and no section of the notices quotes its texts", lib)
		}
		return setOnce(p.versions, target, lib, version)
	}
	return ""
}

func setOnce(into map[string]map[string]string, target, key, value string) string {
	if into[target] == nil {
		into[target] = map[string]string{}
	}
	if _, twice := into[target][key]; twice {
		return fmt.Sprintf("names %s for %s twice", key, target)
	}
	into[target][key] = value
	return ""
}

// gaps are what the pin leaves unsaid about one target: it has to say what the
// compiler links there or that it links nothing, and name the version of every
// library with notices of its own that it links - and no version of one it does
// not.
func (p pinnedToolchain) gaps(target string) []string {
	var out []string
	linked := map[string]bool{}
	for _, lib := range p.links[target] {
		linked[lib] = true
	}
	switch {
	case len(linked) > 0 && p.nothing[target]:
		out = append(out, "says both that "+target+" links files of the compiler's and that it links nothing")
	case len(linked) == 0 && !p.nothing[target]:
		out = append(out, "says nothing about "+target+", and window_toolchain.sh refuses a build it was not written for")
	}
	for lib := range linked {
		if toolchainLibraries[lib].heading != "" && p.versions[target][lib] == "" {
			out = append(out, fmt.Sprintf("links %s into %s and names no version of it, and its notices quote the texts of one", lib, target))
		}
	}
	for lib := range p.versions[target] {
		if !linked[lib] {
			out = append(out, fmt.Sprintf("names a version of %s for %s and links nothing of it there", lib, target))
		}
	}
	sort.Strings(out)
	return out
}

func isWindowTarget(target string) bool {
	for _, t := range windowTargets {
		if t[0]+"/"+t[1] == target {
			return true
		}
	}
	return false
}

// checkToolchainNotices holds the pin to the window's notices: every library
// a build links that has notices of its own has its section, at the version the
// pin names, and no such section stands for a library no build links.
func checkToolchainNotices(pin pinnedToolchain, sections map[string]string) []Violation {
	var problems []Violation
	at := func(format string, args ...any) {
		problems = append(problems, Violation{windowNotices, 0, fmt.Sprintf(format, args...)})
	}
	pinned := map[string]string{} // heading to the version the pin names
	for _, target := range slices.Sorted(maps.Keys(pin.versions)) {
		for lib, version := range pin.versions[target] {
			heading := toolchainLibraries[lib].heading
			if earlier, ok := pinned[heading]; ok && earlier != version {
				at("%s is pinned at %s on one target and %s on another, and one section quotes one version", lib, earlier, version)
			}
			pinned[heading] = version
		}
	}
	for _, heading := range toolchainHeadings() {
		version, isPinned := pinned[heading]
		section, present := sections[heading]
		switch {
		case isPinned && !present:
			at("a build links code the section \"## %s\" answers for, and there is no such section", heading)
		case !isPinned && present:
			at("has the section \"## %s\", and %s says no build links that code", heading, toolchainPin)
		case isPinned && versionIn(section) != version:
			at("the section %q states %s, and %s pins %s", heading, versionIn(section), toolchainPin, version)
		}
	}
	return problems
}

// checkToolchainWiring holds the two scripts to the pin: the build asks the
// linker for its map and runs the reader on it, and the reader reads the pin,
// which no other file of the release copies.
func checkToolchainWiring(builder, reader string, pin pinnedToolchain, others map[string]string) []Violation {
	var problems []Violation
	at := func(file, format string, args ...any) {
		problems = append(problems, Violation{file, 0, fmt.Sprintf(format, args...)})
	}
	for _, want := range []string{"bash " + toolchainReader + " ", "-extldflags=-Wl,-Map=", "-extldflags=-Wl,-map,"} {
		if !strings.Contains(builder, want) {
			at(windowBuilder, "does not carry %q, so the linker's map of the window is not read the way the pin needs", want)
		}
	}
	if !strings.Contains(reader, `pin="`+toolchainPin+`"`) {
		at(toolchainReader, "does not read %s, so it holds the build to a list of its own", toolchainPin)
	}
	for _, rel := range slices.Sorted(maps.Keys(others)) {
		for _, target := range slices.Sorted(maps.Keys(pin.links)) {
			for file := range pin.links[target] {
				if strings.HasSuffix(file, ".a") && strings.Contains(others[rel], file) {
					at(rel, "names %s, a second copy of %s that can drift from it", file, toolchainPin)
				}
			}
		}
	}
	return problems
}

// TestTheCompilersOwnCodeInTheWindowIsTheCodeItsNoticesAnswerFor holds the
// pin to the notices and both scripts to the pin.
func TestTheCompilersOwnCodeInTheWindowIsTheCodeItsNoticesAnswerFor(t *testing.T) {
	root := moduleRoot(t)
	pin, problems := parseToolchainPin(toolchainPin, readRel(t, root, toolchainPin))
	requireNoViolations(t, problems, "the pin of the C compiler's own code in the window")

	sections, parse := noticeSections(windowNotices, readRel(t, root, windowNotices))
	requireNoViolations(t, parse, "the notices file")
	requireNoViolations(t, checkToolchainNotices(pin, sections), "the notices of the C compiler's own code")

	others := map[string]string{}
	for _, rel := range append(workflowFiles(t, root), buildScript, signingScript, macSigning, windowBuilder) {
		others[rel] = readRel(t, root, rel)
	}
	requireNoViolations(t, checkToolchainWiring(readRel(t, root, windowBuilder), readRel(t, root, toolchainReader), pin, others),
		"the scripts that read the linker's map")
}

func TestTheToolchainGuardCanFail(t *testing.T) {
	good := "# a comment\nversion windows/amd64 mingw-w64 1.0.0\nlink windows/amd64 crt2.o mingw-w64\nlink windows/amd64 libgcc.a gcc\n" +
		"version linux/amd64 glibc 2.39\nlink linux/amd64 crt1.o glibc\nnothing darwin/arm64\n"
	pin, problems := parseToolchainPin("fixture", good)
	requireNoViolations(t, problems, "a well formed pin")

	_, problems = parseToolchainPin("fixture", good+"link windows/amd64 crt2.o mingw-w64\nlink linux/amd64 libssp.a ssp\n"+
		"version darwin/arm64 gcc 13\nlink freebsd/amd64 crt1.o glibc\nlink linux/amd64 crt1.o\ncolour linux/amd64\nnothing darwin/arm64\n")
	requireViolation(t, problems, "names crt2.o for windows/amd64 twice")
	requireViolation(t, problems, "a library nobody has read the licence of")
	requireViolation(t, problems, "names a version of gcc, and no section of the notices quotes its texts")
	requireViolation(t, problems, "names freebsd/amd64, which is not a target")
	requireViolation(t, problems, "has 3 fields where a link line has 4")
	requireViolation(t, problems, "has a colour line")
	requireViolation(t, problems, "says twice that darwin/arm64 links nothing")
	_, problems = parseToolchainPin("fixture", "link windows/amd64 crt2.o mingw-w64\nnothing windows/amd64\nversion linux/amd64 glibc 2.39\n")
	requireViolation(t, problems, "says both that windows/amd64 links files of the compiler's and that it links nothing")
	requireViolation(t, problems, "links mingw-w64 into windows/amd64 and names no version of it")
	requireViolation(t, problems, "names a version of glibc for linux/amd64 and links nothing of it there")
	requireViolation(t, problems, "says nothing about darwin/arm64")

	sections := map[string]string{"MinGW-w64 runtime": "\nVersion `1.0.0`. ZPL-2.1.\n", "GNU C Library": "\nVersion `2.39`. LGPL-2.1-or-later.\n"}
	requireNoViolations(t, checkToolchainNotices(pin, sections), "notices that agree with the pin")
	requireViolation(t, checkToolchainNotices(pin, map[string]string{"GNU C Library": sections["GNU C Library"]}), `no such section`)
	requireViolation(t, checkToolchainNotices(pin, map[string]string{"MinGW-w64 runtime": "\nVersion `0.9.0`. ZPL-2.1.\n",
		"GNU C Library": sections["GNU C Library"]}), "states 0.9.0")
	noGlibc, _ := parseToolchainPin("fixture", "version windows/amd64 mingw-w64 1.0.0\nlink windows/amd64 crt2.o mingw-w64\n"+
		"nothing linux/amd64\nnothing darwin/arm64\n")
	requireViolation(t, checkToolchainNotices(noGlibc, sections), `has the section "## GNU C Library"`)

	builder := "bash " + toolchainReader + " \"$target\"\n-extldflags=-Wl,-Map=\n-extldflags=-Wl,-map,\n"
	reader := `pin="` + toolchainPin + `"`
	requireNoViolations(t, checkToolchainWiring(builder, reader, pin, map[string]string{"x.yml": "go build"}), "scripts that read the pin")
	requireViolation(t, checkToolchainWiring("go build\n", reader, pin, nil), "does not carry \"bash .github/scripts/window_toolchain.sh \"")
	requireViolation(t, checkToolchainWiring(strings.Replace(builder, "-map,", "-Map,", 1), reader, pin, nil), `"-extldflags=-Wl,-map,"`)
	requireViolation(t, checkToolchainWiring(builder, `pin=".github/other"`, pin, nil), "holds the build to a list of its own")
	requireViolation(t, checkToolchainWiring(builder, reader, pin, map[string]string{"x.yml": "allowed: libgcc.a"}), "names libgcc.a, a second copy")
}
