package main

import (
	"reflect"
	"strings"
	"testing"

	certdoctor "github.com/donislawdev/certdoctor"
)

// TestTheNoticesInThisTreeDescribeABuild reads the notices this tree compiles
// into every binary, so a section edited into a shape this command cannot read
// fails here, on the push, rather than on the day of a release.
func TestTheNoticesInThisTreeDescribeABuild(t *testing.T) {
	notes, err := parseTree(shippedTree)
	if err != nil {
		t.Fatal(err)
	}
	n, w := notes[programPath], notes[windowPath]
	if !goRelease.MatchString(n.std.version) {
		t.Errorf("the standard library is at %q, which is not a Go release", n.std.version)
	}
	if w.std.version != n.std.version {
		t.Errorf("the window's notices name %s and the command line's %s, and one commit builds both with one toolchain",
			w.std.version, n.std.version)
	}
	if len(n.modules) == 0 {
		t.Error("the notices name no module, and goja and what it brings are linked into every build")
	}
	for _, c := range append([]component{n.std}, n.modulesInOrder()...) {
		if len(c.copyrights) == 0 {
			t.Errorf("%q quotes no copyright line", c.path)
		}
	}
	for program, want := range map[string][]string{
		programPath: {"LicenseRef-Sun-fdlibm-2004", "LicenseRef-Cephes"},
		windowPath: {"LicenseRef-Sun-fdlibm-2004", "LicenseRef-Cephes", "LicenseRef-Arev", "LicenseRef-Public-Domain", "LicenseRef-SGI-FreeB",
			"LicenseRef-MinGW-w64-Cephes"},
	} {
		var ids []string
		for _, e := range notes[program].extracted {
			ids = append(ids, e.id)
		}
		if !reflect.DeepEqual(ids, want) {
			t.Errorf("the texts without an SPDX identifier in the notices of %s are %v, want %v", program, ids, want)
		}
	}
	if len(w.works["Mesa 3D"].files) != 2 || len(w.works["Inter"].files) != 0 || len(w.works) != 4 ||
		w.works["MinGW-w64 runtime"].version == "" || w.works["GNU C Library"].version == "" {
		t.Errorf("the window's works are read as %+v", w.works)
	}
}

// shippedTree is the tree this command is compiled with.
var shippedTree = tree{notices: certdoctor.Notices, windowNotices: certdoctor.WindowNotices, version: certdoctor.Version}

// The window's notices name a choice in brackets, a licence once for each of
// two texts, files beside a binary and an exception, and each is read for what
// it is.
func TestTheWindowsFixtureNoticesAreRead(t *testing.T) {
	w := fixtureNotes(t)[windowPath]
	for path, want := range map[string][]string{
		"example.com/toolkit": {"Unlicense OR BSD-3-Clause", "MIT", "LicenseRef-Arev"},
		"github.com/go-gl/gl": {"MIT", "LicenseRef-SGI-FreeB"},
	} {
		if got := w.modules[path].licences; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
	mesa := w.works["Mesa 3D"]
	if want := []string{"MIT", "Apache-2.0 WITH LLVM-exception"}; !reflect.DeepEqual(mesa.licences, want) {
		t.Errorf("Mesa 3D: %q, want %q", mesa.licences, want)
	}
	want := []listedFile{
		{"opengl/libgallium_wgl.dll", "61880320", "700e1fb7b9487d9d1c53752b03aeb040d22f3731b46aa254d88830b6279474de"},
		{"opengl/opengl32.dll", "139264", "c8511461ba71a0288750467e3be2f5c1c2bbbceaaf0ab5d8c496b0ba7302daa8"},
	}
	if !reflect.DeepEqual(mesa.files, want) {
		t.Errorf("Mesa 3D lists %+v", mesa.files)
	}
	if inter := w.works["Inter"]; inter.version != "4.1" || inter.files != nil {
		t.Errorf("Inter is read as %+v", inter)
	}
}

// A work is in one place: compiled into a build or beside it, never both, and
// every entry of the table says one of the two at most.
func TestAWorkIsEitherCompiledInOrBesideABuild(t *testing.T) {
	if err := (work{beside: "windows/amd64", in: "linux/amd64"}).check(component{path: "Both"}); err == nil ||
		!strings.Contains(err.Error(), `"Both" is both compiled into linux/amd64 and beside windows/amd64`) {
		t.Errorf("a work both compiled in and beside was let through: %v", err)
	}
	for heading, w := range works {
		if w.beside != "" && w.in != "" {
			t.Errorf("programs.go says %q is both compiled into %s and beside %s", heading, w.in, w.beside)
		}
	}
}

// A section names a licence once for each text it quotes, so a licence named
// twice is two texts under one licence, and is one term of the expression.
func TestALicenceNamedTwiceIsOneTerm(t *testing.T) {
	n, err := parseNotices(edited("MIT AND Apache-2.0", "MIT AND Apache-2.0 AND MIT"))
	if err != nil {
		t.Fatal(err)
	}
	if got := n.modules["example.com/alpha"].licences; !reflect.DeepEqual(got, []string{"MIT", "Apache-2.0"}) {
		t.Errorf("read %q", got)
	}
}

func (n notices) modulesInOrder() []component {
	var out []component
	for _, path := range sortedKeys(n.modules) {
		out = append(out, n.modules[path])
	}
	return out
}

func TestTheFixtureNoticesAreRead(t *testing.T) {
	n, err := parseNotices(fixtureNotices)
	if err != nil {
		t.Fatal(err)
	}
	want := notices{
		std: component{
			version:  "go1.27.3",
			licences: []string{"BSD-3-Clause", "LicenseRef-Sun-fdlibm-2004", "LicenseRef-Cephes"},
			copyrights: []string{
				"Copyright 2009 The Go Authors.",
				"Copyright (C) 2004 by Sun Microsystems, Inc. All rights reserved.",
				"Copyright 1984 by Stephen L. Moshier",
			},
		},
		modules: map[string]component{
			"example.com/alpha": {path: "example.com/alpha", version: "v1.2.3", licences: []string{"MIT", "Apache-2.0"},
				copyrights: []string{"Copyright (c) 2020 Alpha Authors"}},
			"example.com/beta/v2": {path: "example.com/beta/v2", version: "v2.0.0+incompatible", licences: []string{"BSD-2-Clause"},
				copyrights: []string{"Copyright (c) 2016 Beta & <Contributors>"}},
		},
		extracted: []extractedLicence{
			{id: "LicenseRef-Sun-fdlibm-2004", name: "Sun Microsystems fdlibm notice, 2004 form",
				text: "Copyright (C) 2004 by Sun Microsystems, Inc. All rights reserved.\n\nPermission to use, copy, modify, and distribute this\n" +
					"software is freely granted, provided that this notice\nis preserved."},
			{id: "LicenseRef-Cephes", name: "Cephes Math Library notice",
				text: "Cephes Math Library Release 2.8:  June, 2000\nCopyright 1984 by Stephen L. Moshier\n## Not a heading, because it is quoted."},
		},
	}
	if !reflect.DeepEqual(n, want) {
		t.Errorf("read\n%+v\nwant\n%+v", n, want)
	}
}

// edited is the fixture with one piece of it replaced, for the refusals below.
func edited(old, replacement string) string {
	return strings.Replace(fixtureNotices, old, replacement, 1)
}

func TestNoticesThatCannotDescribeABuildAreRefused(t *testing.T) {
	sum := strings.Repeat("0", 64)
	for _, c := range []struct{ name, text, want string }{
		{"quoted before any section", "```\nCopyright 2020 Nobody\n```\n" + fixtureNotices, "comes before any section"},
		{"never closed", fixtureNotices + "\n```\nCopyright 2020 Nobody\n", "never closed"},
		{"no opening line", edited("Version `v1.2.3`. MIT AND Apache-2.0.", "MIT."), `"example.com/alpha" does not open with`},
		{"subheading first", edited("## example.com/beta/v2\n\n", "## example.com/beta/v2\n\n### Aside\n\n"),
			`"example.com/beta/v2" does not open with`},
		{"bracket never closed", edited("MIT AND Apache-2.0.", "(MIT AND Apache-2.0."), "a bracket is opened and never closed"},
		{"bracket closed twice", edited("MIT AND Apache-2.0.", "MIT AND Apache-2.0)."), `")" follows a complete expression`},
		{"operator for a licence", edited("MIT AND Apache-2.0.", "MIT AND (OR)."), `"OR" stands where a licence should`},
		{"WITH and no exception", edited("MIT AND Apache-2.0.", "MIT AND Apache-2.0 WITH (LLVM-exception)."),
			"WITH after Apache-2.0 is not followed by an exception"},
		{"exception nobody read", edited("MIT AND Apache-2.0.", "MIT AND Apache-2.0 WITH Classpath-exception-2.0."),
			"names the exception Classpath-exception-2.0, which is not"},
		{"identifier nobody read", edited("BSD-2-Clause.", "BSD-2-Clause-Patent."), "names BSD-2-Clause-Patent, which is not"},
		{"identifier nobody read in a choice", edited("BSD-2-Clause.", "(BSD-2-Clause OR 0BSD)."), "names 0BSD, which is not"},
		{"unknown reference", edited("MIT AND Apache-2.0", "MIT AND LicenseRef-Mine"), "names LicenseRef-Mine, which is not"},
		{"reference without its text", edited("Cephes Math Library Release 2.8:  June, 2000", "Cephes Math Library"),
			"0 of its quoted texts open with"},
		{"reference text twice", edited("#### Cephes\n", "#### Cephes\n\n```\nCephes Math Library Release 2.8:  June, 2000\n```\n"),
			"2 of its quoted texts open with"},
		{"files beside a binary, none listed", fixtureNotices + "\n## Mesa 3D\n\nVersion `1`. MIT.\n",
			`"Mesa 3D" is of files beside a binary, and lists none`},
		{"a work compiled in, with files", fixtureNotices + "\n## Inter\n\nVersion `4.1`. OFL-1.1.\n\n- `x.ttf`, 1 bytes, SHA-256 `" + sum + "`\n",
			`"Inter" lists files, and it is a work compiled into a binary`},
		{"work twice", fixtureNotices + "\n## Inter\n\nVersion `4.1`. OFL-1.1.\n\n## Inter\n\nVersion `4.1`. OFL-1.1.\n",
			`"Inter" appears twice`},
		{"no standard library", edited("## Go standard library and runtime", "## example.com/gamma"),
			"there is no section"},
		{"standard library twice", fixtureNotices + "\n## Go standard library and runtime\n\nVersion `go1.27.3`. MIT.\n",
			"appears twice"},
		{"module twice", fixtureNotices + "\n## example.com/alpha\n\nVersion `v1.2.3`. MIT.\n", `"example.com/alpha" appears twice`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseNotices(c.text)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want one saying %q", err, c.want)
			}
		})
	}
}

// The two files are held to each other, and each refusal names the file it is
// about.
func TestTheNoticesOfTheTwoProgramsAreHeldToEachOther(t *testing.T) {
	cephes := "Cephes Math Library Release 2.8:  June, 2000"
	window := func(old, replacement string) tree {
		return tree{notices: fixtureNotices, windowNotices: strings.Replace(fixtureWindowNotices, old, replacement, 1), version: "0.1.0"}
	}
	// The window's standard library naming Cephes, and quoting another text
	// for it than the command line's does.
	twoTexts := window("BSD-3-Clause AND MIT. Every build", "BSD-3-Clause AND LicenseRef-Cephes. Every build")
	twoTexts.windowNotices = strings.Replace(twoTexts.windowNotices, "Copyright (c) 2010 Somebody Else",
		cephes+"\nAnother text altogether.", 1)
	for _, c := range []struct {
		name string
		from tree
		want string
	}{
		{"the window's unreadable", tree{notices: fixtureNotices, windowNotices: "no sections"},
			"THIRD-PARTY-NOTICES-GUI.md cannot describe a build"},
		{"the command line's unreadable", tree{notices: "no sections", windowNotices: fixtureWindowNotices},
			"THIRD-PARTY-NOTICES.md cannot describe a build"},
		{"a work in the other program's notices", tree{notices: fixtureNotices + "\n## Inter\n\nVersion `4.1`. OFL-1.1.\n",
			windowNotices: fixtureWindowNotices}, `THIRD-PARTY-NOTICES.md has the section "Inter", which is a work of certdoctor-gui`},
		{"a work nobody wrote a section for", window("## Inter\n", "## example.com/inter\n"),
			`names the work "Inter" for certdoctor-gui, and THIRD-PARTY-NOTICES-GUI.md has no section for it`},
		{"one identifier, two texts", twoTexts, "THIRD-PARTY-NOTICES-GUI.md quotes another text for LicenseRef-Cephes"},
		{"a reference nobody quotes", tree{notices: strings.Replace(fixtureNotices, " AND\nLicenseRef-Cephes.", ".", 1),
			windowNotices: fixtureWindowNotices}, "LicenseRef-Cephes is in the list of unlisted texts and no section names it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseTree(c.from)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want one saying %q", err, c.want)
			}
		})
	}
}

// A fence holding nothing but blank lines opens with nothing, and is never the
// text an unlisted identifier stands for.
func TestAnEmptyQuotedTextOpensWithNothing(t *testing.T) {
	if got := firstLine([]string{"", "  "}); got != "" {
		t.Errorf("an empty block opens with %q", got)
	}
	s := section{heading: "x", blocks: [][]string{{""}, {"Cephes Math Library Release 2.8:  June, 2000", ""}}}
	e, err := extract("LicenseRef-Cephes", s)
	if err != nil || e.text != "Cephes Math Library Release 2.8:  June, 2000" {
		t.Errorf("extracted %+v, %v", e, err)
	}
}
