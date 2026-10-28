package main

import (
	"fmt"
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

// listingFor is what go version -m prints for one release binary of commit
// fixtureRevision that links these modules.
func listingFor(file, target, goVersion string, deps map[string]string) string {
	goos, goarch, _ := strings.Cut(target, "/")
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", file, goVersion)
	b.WriteString("\tpath\t" + programPath + "\n")
	b.WriteString("\tmod\t" + modulePath + "\tv0.0.0-20261028080106-89c6fcaaf91f\t\n")
	for _, path := range sortedKeys(deps) {
		fmt.Fprintf(&b, "\tdep\t%s\t%s\th1:AAAA=\n", path, deps[path])
	}
	for _, setting := range []string{
		"-buildmode=exe", "-compiler=gc", "-trimpath=true", "CGO_ENABLED=0",
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

// fixtureTree is the source the fixture builds came from.
var fixtureTree = tree{notices: fixtureNotices, version: "0.1.0"}
