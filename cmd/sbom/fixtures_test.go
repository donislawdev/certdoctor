package main

import (
	"fmt"
	"maps"
	"strings"
)

// fixtureRevision is the commit every fixture build records.
const fixtureRevision = "89c6fcaaf91fce867320c5a3dcd14db37ef50ddc"

// fixtureNotices is a small THIRD-PARTY-NOTICES.md in the shape of the real one:
// a preamble, the standard library with both unlisted texts under deeper
// headings, and two modules - one of them with a version that needs encoding
// in a package URL, and one quoting the Apache template line that names nobody.
//
// Written with ~ for a backtick, because a Go raw string cannot hold one.
var fixtureNotices = strings.ReplaceAll(`# Third party notices

A preamble that belongs to no section.

---

## Go standard library and runtime

Version ~go1.27.3~. BSD-3-Clause AND LicenseRef-Sun-fdlibm-2004 AND
LicenseRef-Cephes. Every build links it.

~~~
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms are permitted.
~~~

### Notices inside the standard library

#### fdlibm

~~~
Copyright (C) 2004 by Sun Microsystems, Inc. All rights reserved.

Permission to use, copy, modify, and distribute this
software is freely granted, provided that this notice
is preserved.
~~~

#### Cephes

~~~

Cephes Math Library Release 2.8:  June, 2000
Copyright 1984 by Stephen L. Moshier
## Not a heading, because it is quoted.
~~~

## example.com/alpha

Version ~v1.2.3~. MIT AND Apache-2.0. The first module.

~~~
Copyright (c) 2020 Alpha Authors
~~~

~~~
Apache License text.
Copyright [yyyy] [name of copyright owner]
Copyright (c) 2020 Alpha Authors
~~~

## example.com/beta/v2

Version ~v2.0.0+incompatible~. BSD-2-Clause.

~~~
Copyright (c) 2016 Beta & <Contributors>
~~~
`, "~", "`")

// fixtureDeps is what a build of the fixture links.
var fixtureDeps = map[string]string{
	"example.com/alpha":   "v1.2.3",
	"example.com/beta/v2": "v2.0.0+incompatible",
}

// listingFor is what go version -m prints for one release binary of the
// command line, of commit fixtureRevision, that links these modules.
func listingFor(file, target, goVersion string, deps map[string]string) string {
	return listingOf(programPath, file, target, goVersion, deps)
}

// windowListingFor is the same for a build of the window, made with cgo, in
// which a module replacements names comes from its directory as it does in a
// real build.
func windowListingFor(file, target string, deps map[string]string) string {
	return listingOf(windowPath, file, target, "go1.27.3", deps)
}

func listingOf(program, file, target, goVersion string, deps map[string]string) string {
	goos, goarch, _ := strings.Cut(target, "/")
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", file, goVersion)
	b.WriteString("\tpath\t" + program + "\n")
	b.WriteString("\tmod\t" + modulePath + "\tv0.0.0-20261028080106-89c6fcaaf91f\t\n")
	for _, path := range sortedKeys(deps) {
		if dir, ok := replacements[path]; ok {
			fmt.Fprintf(&b, "\tdep\t%s\t%s\n\t=>\t%s\t(devel)\t\n", path, deps[path], dir)
			continue
		}
		fmt.Fprintf(&b, "\tdep\t%s\t%s\th1:AAAA=\n", path, deps[path])
	}
	cgo := "CGO_ENABLED=0"
	if program == windowPath {
		cgo = "CGO_ENABLED=1"
	}
	for _, setting := range []string{
		"-buildmode=exe", "-compiler=gc", "-trimpath=true", cgo,
		"GOARCH=" + goarch, "GOOS=" + goos, "vcs=git",
		"vcs.revision=" + fixtureRevision, "vcs.time=2026-10-28T08:01:06Z", "vcs.modified=false",
	} {
		b.WriteString("\tbuild\t" + setting + "\n")
	}
	return b.String()
}

// fixtureListing is two release builds of the fixture.
func fixtureListing() string {
	return listingFor("dist/certdoctor-linux-amd64", "linux/amd64", "go1.27.3", fixtureDeps) +
		listingFor("dist/certdoctor-windows-arm64.exe", "windows/arm64", "go1.27.3", fixtureDeps)
}

// fixtureWindowNotices is a small THIRD-PARTY-NOTICES-GUI.md in the shape of
// the real one: a standard library naming another set of notices than the
// command line's, a module both programs link, a choice of licences in
// brackets, a licence named twice for two texts, a module linked on one
// system alone, the replaced OpenGL binding, every unlisted text the command
// line does not quote, and every kind of work - a typeface compiled in, two
// runtimes the C compiler links into one build each, and files beside the
// binary, the last two with an exception after WITH.
var fixtureWindowNotices = strings.ReplaceAll(`# Third party notices of the window

A preamble, with a list that belongs to no section:

- ~not/a/file~, 1 bytes, SHA-256 ~0000000000000000000000000000000000000000000000000000000000000000~

---

## Go standard library and runtime

Version ~go1.27.3~. BSD-3-Clause AND MIT. Every build links it.

~~~
Copyright 2009 The Go Authors.
~~~

~~~
Copyright (c) 2010 Somebody Else
~~~

## Inter

Version ~4.1~. OFL-1.1. A typeface.

~~~
Copyright (c) 2016 The Inter Project Authors
~~~

## example.com/beta/v2

Version ~v2.0.0+incompatible~. BSD-2-Clause.

~~~
Copyright (c) 2016 Beta & <Contributors>
Copyright (c) 2017 A Second Beta Author
~~~

## example.com/glfw

Version ~v0.1.0~. Zlib AND LicenseRef-Public-Domain. The library in C.

~~~
Copyright (c) 2002-2006 Marcus Geelnard
~~~

~~~
This file has no copyright assigned and is placed in the Public Domain.
This file is part of the mingw-w64 runtime package.
~~~

## example.com/portal

Version ~v0.4.2~. Apache-2.0. Linked on Linux alone.

~~~
Copyright (c) 2024 Portal Authors
~~~

## example.com/toolkit

Version ~v2.8.2~. (Unlicense OR BSD-3-Clause) AND MIT AND
LicenseRef-Arev AND MIT. The toolkit.

~~~
Copyright (c) 2018 Toolkit Authors
~~~

~~~
Fonts are (c) Bitstream (see below). DejaVu changes are in public domain.
Glyphs imported from Arev fonts are (c) Tavmjong Bah (see below)
~~~

~~~
Copyright (c) 2019 A Font Author
~~~

## github.com/go-gl/gl

Version ~v0.0.0-20260331235117-4566fea9a276~. MIT AND LicenseRef-SGI-FreeB.

~~~
Copyright (c) 2014 Eric Woroshow
~~~

~~~
Copyright (c) 2010 Khronos Group.
Copyright (c) 1991-2006 Silicon Graphics, Inc.
~~~

## MinGW-w64 runtime

Version ~13.0.0~. ZPL-2.1 AND LicenseRef-MinGW-w64-Cephes. Linked into the build for Windows alone.

~~~
Copyright (c) 2009, 2010, 2011, 2012, 2013 by the mingw-w64 project
~~~

~~~
FIXME: Cephes math lib
Copyright (C) 1984-1998 Stephen L. Moshier
~~~

## GNU C Library

Version ~2.39~. LGPL-2.1-or-later WITH GCC-exception-2.0-note AND LGPL-2.1-or-later. Linked into the build for Linux alone.

~~~
Copyright (C) 2001-2024 Free Software Foundation, Inc.
~~~

## Mesa 3D

Version ~26.2.5~. MIT AND Apache-2.0 WITH LLVM-exception. Two files beside the window.

- ~opengl/libgallium_wgl.dll~, 61880320 bytes, SHA-256 ~700e1fb7b9487d9d1c53752b03aeb040d22f3731b46aa254d88830b6279474de~
- ~opengl/opengl32.dll~, 139264 bytes, SHA-256 ~c8511461ba71a0288750467e3be2f5c1c2bbbceaaf0ab5d8c496b0ba7302daa8~
- a line of the list that names no file

~~~
Copyright (C) 1999-2007  Brian Paul   All Rights Reserved.
~~~
`, "~", "`")

// fixtureWindowDeps is what every build of the window fixture links, and
// fixturePortal what its Linux build links besides.
var (
	fixtureWindowDeps = map[string]string{
		"example.com/beta/v2": "v2.0.0+incompatible",
		"example.com/glfw":    "v0.1.0",
		"example.com/toolkit": "v2.8.2",
		"github.com/go-gl/gl": "v0.0.0-20260331235117-4566fea9a276",
	}
	fixturePortal = map[string]string{"example.com/portal": "v0.4.2"}
)

// windowDeps is fixtureWindowDeps, with more on top.
func windowDeps(more map[string]string) map[string]string {
	deps := maps.Clone(fixtureWindowDeps)
	maps.Copy(deps, more)
	return deps
}

// fixtureWindowListing is the three builds of the window, the Linux one
// linking the portal.
func fixtureWindowListing() string {
	return windowListingFor("dist/certdoctor-gui.exe", "windows/amd64", windowDeps(nil)) +
		windowListingFor("dist/certdoctor-gui", "linux/amd64", windowDeps(fixturePortal)) +
		windowListingFor("dist/certdoctor-gui.app", "darwin/arm64", windowDeps(nil))
}

// fixtureTree is the source the fixture builds came from.
var fixtureTree = tree{notices: fixtureNotices, windowNotices: fixtureWindowNotices, version: "0.1.0"}
