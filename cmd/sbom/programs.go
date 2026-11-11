package main

import (
	"fmt"
	"strings"
)

// A program is one binary a release ships, with the notices that answer for
// it. The command line answers with THIRD-PARTY-NOTICES.md, which its --license
// prints, and the window with THIRD-PARTY-NOTICES-GUI.md, because it links what
// the command line does not (ADR127 decision 4). Each build is held to the
// notices of its own program, and one document describes both.
type program struct {
	path  string // the main package, as the compiler records it
	name  string // the package's name in the document
	file  string // the notices, for messages
	said  string // how a message names those notices
	notes func(tree) string
}

var programs = []program{
	{path: programPath, name: "certdoctor", file: "THIRD-PARTY-NOTICES.md", said: "the notices",
		notes: func(t tree) string { return t.notices }},
	{path: windowPath, name: "certdoctor-gui", file: "THIRD-PARTY-NOTICES-GUI.md", said: "the window's notices",
		notes: func(t tree) string { return t.windowNotices }},
}

// programNamed is the program built from a main package. readBuild refuses
// any other package first, so every build has one.
func programNamed(path string) program {
	for _, p := range programs {
		if p.path == path {
			return p
		}
	}
	panic("sbom: no program is built from " + path)
}

// A work is a section of the notices named after no module: somebody else's
// work that this repository keeps in its own tree and compiles in, or that
// travels beside a binary in its archive. No build records either, so neither
// can be checked against a build - what holds them to what ships is the
// notices guard in internal/guard, and what this table adds is where each one
// goes.
type work struct {
	program string // the main package of the program that carries it
	beside  string // the one target it travels beside, or "" when compiled into every build
	about   string // what the document says of it
}

// works are those sections, by heading. A heading the notices of a program use
// and this table names for another program is refused, and so is an entry here
// that the notices of its program never use - a work added on one side only.
var works = map[string]work{
	"Inter": {program: windowPath,
		about: "A typeface, compiled into certdoctor-gui from internal/gui/fonts of this repository."},
	"Mesa 3D": {program: windowPath, beside: "windows/amd64",
		about: "Not part of any binary: files that travel beside certdoctor-gui in its archive for windows/amd64, " +
			"in a folder called opengl, which it loads to draw when the graphics driver offers no OpenGL."},
}

// parseTree reads the notices of every program and holds them to each other:
// a text without an SPDX identifier is the same text in every file that quotes
// it, every work is in the notices of its own program, and every unlisted text
// licences.go knows is quoted somewhere.
//
// Both files are read whatever builds are given. They are compiled into this
// command from the same tree, and a file this cannot read is a file a person
// reads differently from the document published beside it.
func parseTree(t tree) (map[string]notices, error) {
	read := map[string]notices{}
	texts := map[string]string{} // LicenseRef identifier to its text
	for _, p := range programs {
		n, err := parseNotices(p.notes(t))
		if err != nil {
			return nil, fmt.Errorf("%s cannot describe a build: %w", p.file, err)
		}
		for heading := range n.works {
			if owner := works[heading].program; owner != p.path {
				return nil, fmt.Errorf("%s has the section %q, which is a work of %s", p.file, heading, programNamed(owner).name)
			}
		}
		for _, e := range n.extracted {
			if earlier, ok := texts[e.id]; ok && earlier != e.text {
				return nil, fmt.Errorf("%s quotes another text for %s than the notices read before it", p.file, e.id)
			}
			texts[e.id] = e.text
		}
		read[p.path] = n
	}
	for _, heading := range sortedKeys(works) {
		w := works[heading]
		if _, ok := read[w.program].works[heading]; !ok {
			return nil, fmt.Errorf("programs.go names the work %q for %s, and %s has no section for it",
				heading, programNamed(w.program).name, programNamed(w.program).file)
		}
	}
	for _, u := range unlisted {
		if _, ok := texts[u.id]; !ok {
			return nil, fmt.Errorf("%s is in the list of unlisted texts and no section names it - remove it from licences.go", u.id)
		}
	}
	return read, nil
}

// fileList is what the document says of the files a work beside a binary is.
func fileList(files []listedFile) string {
	parts := make([]string, 0, len(files))
	for _, f := range files {
		parts = append(parts, fmt.Sprintf("%s, %s bytes, SHA-256 %s", f.path, f.size, f.sha256))
	}
	return strings.Join(parts, "; ")
}
