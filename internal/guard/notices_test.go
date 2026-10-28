package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// noticesFile is the file whose text --license prints after the GPL, and which
// every release archive carries - ADR116 decision 5.
//
// WHY A GUARD AND NOT A CAREFUL HAND. MIT and BSD ask for their notice in every
// copy of the code, a binary copy included, and the notice that matters is the
// one of the code that is ACTUALLY LINKED. Measured on 2026-10-28, while this
// file was being written: the five modules come with three licence files besides
// their LICENSE - regexp2's ATTRIB, and two notices inside goja's ftoa packages,
// one of them V8's - and the Go standard library carries five notices of its own
// in source comments, from Sun, Cephes, fiat-crypto, FreeBSD and Inferno. The
// written decision listed none of the eight. A dependency raised, a package
// newly imported or a new Go release each move this set, and none of them
// touches this file.
const noticesFile = "THIRD-PARTY-NOTICES.md"

// stdHeading is the one section not named after a module. The Go runtime and
// standard library are linked into every Go program and are not a module, so go
// list never names them the way it names the rest.
const stdHeading = "Go standard library and runtime"

// releaseTargets are the five builds ADR116 decision 2 ships. The list is
// written here because the release workflow that builds them does not exist
// yet, and a change to it is a change to that decision.
//
// All five are asked, not one, because what is linked depends on the target -
// a file the runtime builds for amd64 alone carries a notice the arm64 builds
// do not have.
var releaseTargets = [][2]string{
	{"windows", "amd64"}, {"windows", "arm64"},
	{"linux", "amd64"}, {"linux", "arm64"},
	{"darwin", "arm64"},
}

// licenceName is a file that carries terms rather than code. Matched by name,
// because that is how a module publishes one: LICENSE beside the code, and in
// goja LICENSE_V8 beside the package that came from V8.
var licenceName = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice|attrib|patents|copyright|unlicense)([._-].*)?$`)

// copyrightLine is a statement of copyright in a source comment: the word, an
// optional (c) or the copyright sign, and a year. The year is what tells a
// statement from a sentence ABOUT copyright, which every licence is full of.
var copyrightLine = regexp.MustCompile(`(?i)\bcopyright\s*(?:\(c\)|\x{00A9})?\s*\d{4}`)

// commentMarker is what precedes the text of a comment line in Go and in the
// assembler.
var commentMarker = regexp.MustCompile(`^[\s/*]*`)

// statedVersion is how a section opens: the version as go list spells it,
// between backticks.
var statedVersion = regexp.MustCompile("(?m)^Version `([^`]+)`\\.")

// termsOfAnUnlinkedPart are licence files that sit in the tree of a linked
// package and cover a part of it that no release build links. Each names the
// package carrying that part, and the exception holds only while that package
// stays out of every build - the moment one links it, its licence is asked for
// like any other.
//
// One entry, measured 2026-10-28, the first time this guard ran. Every build
// links crypto/internal/boring as stubs, and its LICENSE says so in its first
// lines: the Go licence covers the Go code there, and the BoringSSL licence
// below applies only with GOEXPERIMENT=boringcrypto, to an object file that
// crypto/internal/boring/syso carries.
var termsOfAnUnlinkedPart = map[string]string{
	"src/crypto/internal/boring/LICENSE": "crypto/internal/boring/syso",
}

// linkedCode is what the five release builds link, gathered from go list.
type linkedCode struct {
	modules  map[string]string // module path to version, this module left out
	licences []ownedText       // licence files in the trees of linked packages
	sources  map[string]string // source file to the heading that answers for it
	skipped  []string          // licence files left out, with the reason
}

// ownedText is a piece of somebody else's text and the section it belongs in.
type ownedText struct {
	path  string
	owner string
	text  string
}

// listedPackage is the part of "go list -json" this guard reads.
type listedPackage struct {
	ImportPath string
	Dir        string
	Standard   bool
	GoFiles    []string
	SFiles     []string
	HFiles     []string
	Module     *struct {
		Path    string
		Version string
		Dir     string
		Main    bool
	}
	Error *struct{ Err string }
}

// TestTheNoticesCoverWhatTheBinaryLinks is the guard. One gathering, three
// questions: which modules and versions, which licence files, which copyright
// statements.
func TestTheNoticesCoverWhatTheBinaryLinks(t *testing.T) {
	root, _, err := findModuleRoot()
	if err != nil {
		t.Fatalf("finding the module root: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, noticesFile))
	if err != nil {
		t.Fatalf("%s is what --license prints and what every archive carries, and it cannot be read: %v", noticesFile, err)
	}
	sections, parseProblems := noticeSections(string(body))
	requireNoViolations(t, parseProblems, "the notices file")

	goroot := goEnv(t, root, "GOROOT")
	linked := gatherLinked(t, root, goroot)
	t.Logf("%d module(s), %d licence file(s) and %d source file(s) across %d targets",
		len(linked.modules), len(linked.licences), len(linked.sources), len(releaseTargets))
	for _, reason := range linked.skipped {
		t.Logf("not required: %s", reason)
	}

	t.Run("modules and versions", func(t *testing.T) {
		requireNoViolations(t, checkNoticedModules(sections, linked.modules), "the modules in the notices")
		// The first word only: a toolchain built with an experiment adds it
		// after a space, and the release is not built with one.
		running := strings.Fields(goEnv(t, root, "GOVERSION"))[0]
		requireNoViolations(t, checkGoVersion(sections, goModGo(t, root), running), "the Go version in the notices")
	})
	t.Run("licence files", func(t *testing.T) {
		requireNoViolations(t, checkLicenceTexts(sections, linked.licences), "a licence file of linked code")
	})
	t.Run("copyright statements", func(t *testing.T) {
		statements, err := copyrightStatements(linked.sources)
		if err != nil {
			t.Fatal(err)
		}
		requireNoViolations(t, checkLicenceTexts(sections, statements), "a copyright statement in linked code")
	})
}

// TestTheNoticesGuardCanFail is the canary, one planted gap per question. A
// guard over a list it never managed to fill looks exactly like a guard over a
// list that is complete.
func TestTheNoticesGuardCanFail(t *testing.T) {
	sections, problems := noticeSections("# Notices\n\n## " + stdHeading + "\n\nVersion `go1.0`. Some text.\n\n" +
		"## example.com/kept\n\nVersion `v1.0.0`. MIT.\n\n```\nCopyright (c) 2001 Somebody\n```\n\n" +
		"## example.com/gone\n\nVersion `v2.0.0`. MIT.\n")
	requireNoViolations(t, problems, "the planted notices")

	modules := checkNoticedModules(sections, map[string]string{"example.com/kept": "v1.1.0", "example.com/new": "v1.0.0"})
	requireViolation(t, modules, "example.com/new is linked")
	requireViolation(t, modules, "example.com/gone and nothing links it")
	requireViolation(t, modules, "states v1.0.0 and the build links v1.1.0")

	requireViolation(t, checkGoVersion(sections, "1.27.3", "go1.27.3"), "states go1.0")
	requireViolation(t, checkGoVersion(sections, "1.27.3", "go1.28.0"), "runs go1.28.0")

	texts := checkLicenceTexts(sections, []ownedText{
		{path: "kept/LICENSE", owner: "example.com/kept", text: "Copyright (c) 2001 Somebody\n"},
		{path: "kept/ATTRIB", owner: "example.com/kept", text: "Copyright (c) 2002 Somebody Else\n"},
		{path: "std/LICENSE", owner: stdHeading, text: "Copyright (c) 2001 Somebody\n"},
	})
	if len(texts) != 2 {
		t.Errorf("want exactly the missing ATTRIB and the text quoted under the wrong heading, got %v", texts)
	}
	requireViolation(t, texts, "kept/ATTRIB")
	requireViolation(t, texts, "std/LICENSE")

	boring := "src/crypto/internal/boring/LICENSE"
	if why := notRequired(boring, "BoringSSL terms", "grant", map[string]bool{"crypto/internal/boring/syso": true}); why != "" {
		t.Errorf("the BoringSSL terms were let off with their object file linked: %s", why)
	}
	if notRequired(boring, "BoringSSL terms", "grant", map[string]bool{}) == "" {
		t.Error("the BoringSSL terms were asked for with their object file linked nowhere")
	}
	if notRequired("", "conditions of somebody's own", "grant", nil) != "" {
		t.Error("a file was let off that is neither the grant nor an unlinked part")
	}

	_, dup := noticeSections("## a\n\n## a\n")
	requireViolation(t, dup, "two sections named a")
	_, fenced := noticeSections("## a\n\n```\n## not a heading\n")
	requireViolation(t, fenced, "a code block that never closes")
}

// copyrightSign is the sign as UTF-8 bytes, spelled so that this file stays
// ASCII - Inferno's notice in the runtime is written with it.
const copyrightSign = "\xc2\xa9"

// TestACopyrightStatementIsReadOffAComment pins what the third question picks
// up, because a statement it fails to see is a notice nobody is asked for.
func TestACopyrightStatementIsReadOffAComment(t *testing.T) {
	seen := map[string]bool{}
	for _, line := range []string{
		"// Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.",
		" * Copyright (c) 2001 David E. O'Brien",
		"//         Revisions Copyright " + copyrightSign + " 2000-2007 Vita Nuova Holdings Limited.  All rights reserved.",
	} {
		text, ok := copyrightStatement(line)
		seen[text] = ok
	}
	for _, want := range []string{
		"Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.",
		"Copyright (c) 2001 David E. O'Brien",
		"Revisions Copyright " + copyrightSign + " 2000-2007 Vita Nuova Holdings Limited. All rights reserved.",
	} {
		if !seen[want] {
			t.Errorf("did not read %q off its comment, read %v", want, seen)
		}
	}
	for _, line := range []string{
		"// Copyright 2009 The Go Authors. All rights reserved.",
		"// Redistributions of source code must retain the above copyright",
		"var copyright = 1",
	} {
		if text, ok := copyrightStatement(line); ok {
			t.Errorf("read %q as a statement somebody else's notice has to carry", text)
		}
	}
}

// noticeSections cuts the notices file at its second-level headings. A heading
// inside a code block is licence text, not a heading, so fences are followed.
func noticeSections(body string) (map[string]string, []Violation) {
	sections := map[string]string{}
	var problems []Violation
	var current string
	var text strings.Builder
	inFence, open := false, false
	flush := func() {
		if open {
			sections[current] = text.String()
		}
		text.Reset()
	}
	for i, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
		}
		if heading, ok := strings.CutPrefix(line, "## "); ok && !inFence {
			flush()
			current, open = strings.TrimSpace(heading), true
			if _, dup := sections[current]; dup {
				problems = append(problems, Violation{noticesFile, i + 1, "two sections named " + current})
			}
			continue
		}
		text.WriteString(line + "\n")
	}
	flush()
	if inFence {
		problems = append(problems, Violation{noticesFile, 0, "the file ends inside a code block that never closes"})
	}
	return sections, problems
}

// checkNoticedModules compares the sections with what is linked, both ways, and
// the version each section states with the one the build links.
func checkNoticedModules(sections map[string]string, modules map[string]string) []Violation {
	var problems []Violation
	for path, version := range modules {
		section, ok := sections[path]
		if !ok {
			problems = append(problems, Violation{noticesFile, 0, fmt.Sprintf(
				"%s is linked into the binary and has no section here - read its licence files in the module "+
					"cache and add \"## %s\", \"Version `%s`.\" and each file in full", path, path, version)})
			continue
		}
		if stated := versionIn(section); stated != version {
			problems = append(problems, Violation{noticesFile, 0, fmt.Sprintf(
				"the section for %s states %s and the build links %s - a notice belongs to the code that ships",
				path, stated, version)})
		}
	}
	for heading := range sections {
		if _, ok := modules[heading]; !ok && heading != stdHeading {
			problems = append(problems, Violation{noticesFile, 0, fmt.Sprintf(
				"the notices name %s and nothing links it - a section for code that does not ship", heading)})
		}
	}
	return sortViolations(problems)
}

// checkGoVersion asks the standard library section for the Go that builds the
// release - the go line of go.mod, which CI installs - and refuses to judge it
// with a different Go, whose standard library may carry other notices.
func checkGoVersion(sections map[string]string, goModGo, running string) []Violation {
	want := "go" + goModGo
	if running != want {
		return []Violation{{noticesFile, 0, fmt.Sprintf(
			"this guard runs %s and the release is built with %s from go.mod - the notices of one say "+
				"nothing about the other, so run it with that one", running, want)}}
	}
	section, ok := sections[stdHeading]
	if !ok {
		return []Violation{{noticesFile, 0, "there is no section \"## " + stdHeading + "\", and every build links it"}}
	}
	if stated := versionIn(section); stated != want {
		return []Violation{{noticesFile, 0, fmt.Sprintf("the standard library section states %s and the release is built with %s", stated, want)}}
	}
	return nil
}

// checkLicenceTexts asks that every piece of somebody else's text stands, in
// full, in the section of the code it came with. Under another heading it does
// not count: the reader looks for a notice where its code is named.
//
// Whitespace runs are folded on both sides. A licence file in the module cache
// may end its lines differently than this file does, and a comment loses its
// indentation when it is quoted - the words and their order are what is asked.
func checkLicenceTexts(sections map[string]string, texts []ownedText) []Violation {
	folded := map[string]string{}
	for heading, section := range sections {
		folded[heading] = fold(section)
	}
	var problems []Violation
	for _, piece := range texts {
		if strings.Contains(folded[piece.owner], fold(piece.text)) {
			continue
		}
		problems = append(problems, Violation{noticesFile, 0, fmt.Sprintf(
			"%s is not quoted in full under \"## %s\" - copy it there inside a code block, as it stands", piece.path, piece.owner)})
	}
	return sortViolations(problems)
}

func fold(s string) string { return strings.Join(strings.Fields(s), " ") }

func versionIn(section string) string {
	if m := statedVersion.FindStringSubmatch(section); m != nil {
		return m[1]
	}
	return "no version"
}

// gatherLinked asks go list what the entry point links on every release target.
func gatherLinked(t *testing.T, root, goroot string) linkedCode {
	t.Helper()
	code := linkedCode{modules: map[string]string{}, sources: map[string]string{}}
	tops := map[string]string{} // package directory to the directory its walk stops at
	owners := map[string]string{}
	imported := map[string]bool{}
	for _, target := range releaseTargets {
		for _, p := range listPackages(t, root, target) {
			imported[p.ImportPath] = true
			owner, top := stdHeading, goroot
			if !p.Standard {
				if p.Module == nil {
					t.Fatalf("%s is neither in the standard library nor in a module", p.ImportPath)
				}
				if p.Module.Main {
					continue
				}
				code.modules[p.Module.Path] = p.Module.Version
				owner, top = p.Module.Path, p.Module.Dir
			}
			tops[p.Dir], owners[p.Dir] = top, owner
			for _, name := range append(append(append([]string{}, p.GoFiles...), p.SFiles...), p.HFiles...) {
				code.sources[filepath.Join(p.Dir, name)] = owner
			}
		}
	}
	grant := readText(t, filepath.Join(goroot, "PATENTS"))
	found := map[string]bool{}
	for dir, top := range tops {
		for _, path := range licenceFilesUp(t, dir, top) {
			if found[path] {
				continue
			}
			found[path] = true
			text := readText(t, path)
			if why := notRequired(relativeTo(goroot, path), text, grant, imported); why != "" {
				code.skipped = append(code.skipped, path+" "+why)
				continue
			}
			code.licences = append(code.licences, ownedText{path: path, owner: owners[dir], text: text})
		}
	}
	for rel := range termsOfAnUnlinkedPart {
		if !found[filepath.Join(goroot, filepath.FromSlash(rel))] {
			t.Errorf("termsOfAnUnlinkedPart names %s, which no walk reached - an exception for nothing reads as protection", rel)
		}
	}
	if !found[filepath.Join(goroot, "LICENSE")] {
		t.Fatalf("the walk never reached %s, so it proves nothing about the files above any package", filepath.Join(goroot, "LICENSE"))
	}
	sort.Slice(code.licences, func(i, j int) bool { return code.licences[i].path < code.licences[j].path })
	sort.Strings(code.skipped)
	return code
}

func listPackages(t *testing.T, root string, target [2]string) []listedPackage {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-json", "./cmd/certdoctor")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+target[0], "GOARCH="+target[1], "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list for %s/%s: %v\n%s", target[0], target[1], err, stderr.String())
	}
	var packages []listedPackage
	for dec := json.NewDecoder(bytes.NewReader(out)); dec.More(); {
		var p listedPackage
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("reading go list for %s/%s: %v", target[0], target[1], err)
		}
		if p.Error != nil {
			t.Fatalf("go list could not load %s for %s/%s: %s", p.ImportPath, target[0], target[1], p.Error.Err)
		}
		packages = append(packages, p)
	}
	if len(packages) == 0 {
		t.Fatalf("go list named no package for %s/%s", target[0], target[1])
	}
	return packages
}

// licenceFilesUp lists the licence files in a package directory and in every
// directory above it, up to and including top. A licence beside the module's
// go.mod covers every package below it, and one beside a package covers that
// package - which is where goja keeps V8's.
func licenceFilesUp(t *testing.T, dir, top string) []string {
	t.Helper()
	var found []string
	for d := filepath.Clean(dir); ; {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatalf("listing %s: %v", d, err)
		}
		for _, e := range entries {
			if e.Type().IsRegular() && licenceName.MatchString(e.Name()) {
				found = append(found, filepath.Join(d, e.Name()))
			}
		}
		if d == filepath.Clean(top) {
			return found
		}
		parent := filepath.Dir(d)
		if parent == d {
			t.Fatalf("%s is not below %s, so the walk for its licence files had nowhere to stop", dir, top)
		}
		d = parent
	}
}

// copyrightStatements reads every statement of copyright out of the linked
// source files, other than the Go Authors' own, whose licence is quoted whole.
func copyrightStatements(sources map[string]string) ([]ownedText, error) {
	var statements []ownedText
	for path, owner := range sources {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		for i, line := range strings.Split(string(content), "\n") {
			if text, ok := copyrightStatement(line); ok {
				statements = append(statements, ownedText{path: fmt.Sprintf("%s:%d (%q)", path, i+1, text), owner: owner, text: text})
			}
		}
	}
	sort.Slice(statements, func(i, j int) bool { return statements[i].path < statements[j].path })
	return statements, nil
}

// copyrightStatement reads one line, and says whether it states somebody
// else's copyright, with the comment markers taken off.
func copyrightStatement(line string) (string, bool) {
	if !copyrightLine.MatchString(line) || strings.Contains(line, "The Go Authors") {
		return "", false
	}
	return fold(commentMarker.ReplaceAllString(line, "")), true
}

// notRequired says why a licence file found in the tree of linked code need not
// be quoted, and answers with nothing when it must be. rel is the path below
// the Go distribution, empty for a file outside it.
//
// The grant is matched by its text and not by the name PATENTS, because a file
// of that name in somebody else's module may set conditions of its own.
func notRequired(rel, text, grant string, imported map[string]bool) string {
	if text == grant {
		return "is Go's patent grant, which sets no condition on passing it on"
	}
	if part, ok := termsOfAnUnlinkedPart[rel]; ok && !imported[part] {
		return "covers " + part + ", which no release build links"
	}
	return ""
}

// relativeTo spells a path below root the way termsOfAnUnlinkedPart does, and
// answers with nothing for a path outside it.
func relativeTo(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return filepath.ToSlash(rel)
}

func readText(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return strings.ReplaceAll(string(content), "\r\n", "\n")
}

func goEnv(t *testing.T, root, name string) string {
	t.Helper()
	cmd := exec.Command("go", "env", name)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go env %s: %v", name, err)
	}
	value := strings.TrimSpace(string(out))
	if value == "" {
		t.Fatalf("go env %s answered nothing", name)
	}
	return value
}

func goModGo(t *testing.T, root string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^go (\S+)\s*$`).FindStringSubmatch(readText(t, filepath.Join(root, "go.mod")))
	if m == nil {
		t.Fatal("go.mod has no go line")
	}
	return m[1]
}
