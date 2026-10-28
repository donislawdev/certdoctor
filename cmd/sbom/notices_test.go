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
	n, err := parseNotices(certdoctor.Notices)
	if err != nil {
		t.Fatal(err)
	}
	if !goRelease.MatchString(n.std.version) {
		t.Errorf("the standard library is at %q, which is not a Go release", n.std.version)
	}
	if len(n.modules) == 0 {
		t.Error("the notices name no module, and goja and what it brings are linked into every build")
	}
	for _, c := range append([]component{n.std}, n.modulesInOrder()...) {
		if len(c.copyrights) == 0 {
			t.Errorf("%q quotes no copyright line", c.path)
		}
	}
	var ids []string
	for _, e := range n.extracted {
		ids = append(ids, e.id)
	}
	if want := []string{"LicenseRef-Sun-fdlibm-2004", "LicenseRef-Cephes"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("the texts without an SPDX identifier are %v, want %v", ids, want)
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
	stdOpening := "Version `go1.27.3`. BSD-3-Clause AND LicenseRef-Sun-fdlibm-2004 AND\nLicenseRef-Cephes."
	for _, c := range []struct{ name, text, want string }{
		{"quoted before any section", "```\nCopyright 2020 Nobody\n```\n" + fixtureNotices, "comes before any section"},
		{"never closed", fixtureNotices + "\n```\nCopyright 2020 Nobody\n", "never closed"},
		{"no opening line", edited("Version `v1.2.3`. MIT AND Apache-2.0.", "MIT."), `"example.com/alpha" does not open with`},
		{"subheading first", edited("## example.com/beta/v2\n\n", "## example.com/beta/v2\n\n### Aside\n\n"),
			`"example.com/beta/v2" does not open with`},
		{"identifier twice", edited("MIT AND Apache-2.0", "MIT AND MIT"), "names MIT twice"},
		{"identifier nobody read", edited("BSD-2-Clause.", "BSD-2-Clause-Patent."), "names BSD-2-Clause-Patent, which is not"},
		{"unknown reference", edited("MIT AND Apache-2.0", "MIT AND LicenseRef-Mine"), "names LicenseRef-Mine, which is not"},
		{"reference without its text", edited("Cephes Math Library Release 2.8:  June, 2000", "Cephes Math Library"),
			"0 of its quoted texts open with"},
		{"reference text twice", edited("#### Cephes\n", "#### Cephes\n\n```\nCephes Math Library Release 2.8:  June, 2000\n```\n"),
			"2 of its quoted texts open with"},
		{"reference unused", edited(stdOpening, "Version `go1.27.3`. BSD-3-Clause AND LicenseRef-Sun-fdlibm-2004."),
			"LicenseRef-Cephes is in the list of unlisted texts and no section names it"},
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
