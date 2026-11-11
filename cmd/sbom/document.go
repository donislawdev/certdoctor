package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// render writes the document for builds that reconcile has accepted.
//
// Every field that varies comes from the builds or the notices, never from a
// clock: the time is the commit's, and the namespace is a hash of the version,
// the commit and the builds. The same builds give the same bytes, which is
// what lets a second run be compared with the first.
//
// One document describes every program built: each is a package the document
// DESCRIBES, and each CONTAINS what its notices name. A component both link -
// the standard library, golang.org/x/text - is one package both contain.
func render(version string, builds []build, notes map[string]notices) ([]byte, error) {
	present := programsBuilt(builds)
	revision := builds[0].revision
	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "certdoctor-" + version,
		DocumentNamespace: namespace(version, revision, labels(builds)),
		CreationInfo: spdxCreation{
			Created:            builds[0].time,
			Creators:           []string{"Tool: certdoctor-sbom", "Organization: DonislawDev"},
			LicenseListVersion: licenseListVersion,
			Comment:            creationComment(present),
		},
	}
	seen := map[string]bool{}
	for _, p := range present {
		for _, e := range notes[p.path].extracted {
			if !seen[e.id] {
				doc.Extracted = append(doc.Extracted, spdxExtracted{LicenseID: e.id, ExtractedText: e.text, Name: e.name})
				seen[e.id] = true
			}
		}
	}

	for _, p := range present {
		mine := buildsOf(builds, p)
		root := programPackage(p, version, revision, mine, linksTheSame(mine))
		doc.Packages = append(doc.Packages, root)
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: root.SPDXID,
		})
	}
	parts, err := partsOf(present, notes, builds)
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		for _, earlier := range doc.Packages {
			if earlier.SPDXID == part.pkg.SPDXID {
				return nil, fmt.Errorf("%s and %s both become %s, and an identifier names one package", earlier.Name, part.pkg.Name, part.pkg.SPDXID)
			}
		}
		doc.Packages = append(doc.Packages, part.pkg)
	}
	doc.Relationships = append(doc.Relationships, relationships(present, parts)...)

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	// A quoted text may carry angle brackets or an ampersand, and escaping them
	// makes a document a person can no longer read without changing what a
	// machine reads.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// The ways a program holds a part.
const (
	// contained is code in the binary: statically linked, or embedded. The
	// code is in it rather than beside it at run time.
	contained = "CONTAINS"
	// besideIt is a work that travels beside the binary and that the program
	// loads when it needs it, so the program runs without it.
	besideIt = "OPTIONAL_DEPENDENCY_OF"
)

// A part is one component as the document lists it, merged across the notices
// of every program that names it, with how each of those programs holds it.
type part struct {
	pkg     spdxPackage
	holders map[string]string // program path to contained or besideIt
}

// partsOf lists the standard library, then every module by path, then every
// work by heading, each once.
func partsOf(present []program, notes map[string]notices, builds []build) ([]part, error) {
	var std merged
	modules, worksHeld := map[string]*merged{}, map[string]*merged{}
	for _, p := range present {
		n := notes[p.path]
		if err := std.add(n.std, p, contained); err != nil {
			return nil, err
		}
		for path, c := range n.modules {
			if err := addTo(modules, path, c, p, contained); err != nil {
				return nil, err
			}
		}
		for heading, c := range n.works {
			how, held := holds(works[heading], p, builds)
			if !held {
				continue
			}
			if err := addTo(worksHeld, heading, c, p, how); err != nil {
				return nil, err
			}
		}
	}

	pkg, err := stdlibPackage(std.c)
	if err != nil {
		return nil, err
	}
	if len(present) > 1 {
		pkg.Comment = "The Go runtime and standard library, linked into every build of every program. Its licence names " +
			"every notice in the parts of it that any of them links."
	}
	parts := []part{{pkg: pkg, holders: std.holders}}
	for _, path := range sortedKeys(modules) {
		m := modules[path]
		pkg := modulePackage(m.c)
		pkg.Comment = moduleComment(path, present, builds)
		parts = append(parts, part{pkg: pkg, holders: m.holders})
	}
	for _, heading := range sortedKeys(worksHeld) {
		m := worksHeld[heading]
		parts = append(parts, part{pkg: workPackage(m.c, works[heading]), holders: m.holders})
	}
	return parts, nil
}

// holds is how a program holds a work, and whether the builds given carry it
// at all: a work compiled in is in every build of its program, one the C
// compiler links in of its own only in the build for its target, and one beside
// a binary only in the archive of the build it travels beside.
func holds(w work, p program, builds []build) (string, bool) {
	switch {
	case w.in != "":
		return contained, builtFor(builds, p, w.in)
	case w.beside != "":
		return besideIt, builtFor(builds, p, w.beside)
	}
	return contained, true
}

// merged is one component as the notices of every program name it.
type merged struct {
	c       component
	holders map[string]string
}

func addTo(into map[string]*merged, key string, c component, p program, how string) error {
	if into[key] == nil {
		into[key] = &merged{}
	}
	return into[key].add(c, p, how)
}

// add takes one program's section into the part. Two programs that name one
// component at two versions are refused - one document names one version of a
// thing, and the two builds of one commit do not link two. The licence is
// every term either names and the copyright every line either quotes: the
// standard library is one package, and each program carries the notices of
// the parts of it that program links.
func (m *merged) add(c component, p program, how string) error {
	switch {
	case m.holders == nil:
		m.c = component{path: c.path, version: c.version, files: c.files,
			licences: slices.Clone(c.licences), copyrights: slices.Clone(c.copyrights)}
		m.holders = map[string]string{}
	case m.c.version != c.version:
		name := c.path
		if name == "" {
			name = stdHeading
		}
		return fmt.Errorf("%s is %s in the notices read before and %s in %s, and one document names one version of it",
			name, m.c.version, c.version, p.file)
	default:
		for _, t := range c.licences {
			m.c.licences = appendNew(m.c.licences, t)
		}
		for _, line := range c.copyrights {
			m.c.copyrights = appendNew(m.c.copyrights, line)
		}
	}
	m.holders[p.path] = how
	return nil
}

// moduleComment says what the module's package alone cannot: that it was
// built from a copy kept in this repository, and which builds link it when
// some of a program's builds do not.
func moduleComment(path string, present []program, builds []build) string {
	var said []string
	for _, b := range builds {
		if dir, ok := b.replaced[path]; ok {
			dir = strings.TrimPrefix(dir, "./")
			said = append(said, "Linked from a copy kept in "+dir+" of this repository rather than from the module's own "+
				"source, changed as "+dir+"/PATCH.md describes.")
			break
		}
	}
	for _, p := range present {
		mine := buildsOf(builds, p)
		var linking []string
		for _, b := range mine {
			if _, ok := b.deps[path]; ok {
				linking = append(linking, b.target)
			}
		}
		if len(linking) > 0 && len(linking) < len(mine) {
			slices.Sort(linking)
			said = append(said, "Linked into the build(s) of "+p.name+" for "+strings.Join(linking, ", ")+" and into no other.")
		}
	}
	return strings.Join(said, " ")
}

// relationships are each program containing what it contains, in the order
// the parts are listed, then each work that travels beside a program.
func relationships(present []program, parts []part) []spdxRelationship {
	var out []spdxRelationship
	for _, p := range present {
		for _, part := range parts {
			if part.holders[p.path] == contained {
				out = append(out, spdxRelationship{
					SPDXElementID: "SPDXRef-Package-" + p.name, RelationshipType: contained, RelatedSPDXElement: part.pkg.SPDXID,
				})
			}
		}
	}
	for _, part := range parts {
		for _, p := range present {
			if part.holders[p.path] == besideIt {
				out = append(out, spdxRelationship{
					SPDXElementID: part.pkg.SPDXID, RelationshipType: besideIt, RelatedSPDXElement: "SPDXRef-Package-" + p.name,
				})
			}
		}
	}
	return out
}

// programsBuilt are the programs the builds are of, in the order programs
// lists them.
func programsBuilt(builds []build) []program {
	var out []program
	for _, p := range programs {
		if len(buildsOf(builds, p)) > 0 {
			out = append(out, p)
		}
	}
	return out
}

func buildsOf(builds []build, p program) []build {
	var out []build
	for _, b := range builds {
		if b.program == p.path {
			out = append(out, b)
		}
	}
	return out
}

func builtFor(builds []build, p program, target string) bool {
	for _, b := range buildsOf(builds, p) {
		if b.target == target {
			return true
		}
	}
	return false
}

// linksTheSame is whether every one of the builds links the same modules.
func linksTheSame(builds []build) bool {
	for _, b := range builds[1:] {
		if !slices.Equal(sortedKeys(b.deps), sortedKeys(builds[0].deps)) {
			return false
		}
	}
	return true
}

// labels are the builds as messages name them, sorted. The command line's are
// its targets, so a document of the command line alone has the namespace it
// had before there was a window.
func labels(builds []build) []string {
	out := make([]string, 0, len(builds))
	for _, b := range builds {
		out = append(out, b.label())
	}
	slices.Sort(out)
	return out
}

func creationComment(present []program) string {
	files := make([]string, 0, len(present))
	for _, p := range present {
		files = append(files, p.file)
	}
	quotes := files[0] + ", which quotes"
	if len(files) > 1 {
		quotes = strings.Join(files, " and ") + ", the notices of the programs, which quote"
	}
	return "Generated by cmd/sbom from the build information each binary carries and from " + quotes +
		" in full every licence named here. It refuses to write a document when a build links a module or a version " +
		"the notices of its program do not name."
}

// summary is the one line written to standard error beside a document.
func summary(version string, builds []build, notes map[string]notices) string {
	present := programsBuilt(builds)
	modules, held := map[string]bool{}, map[string]bool{}
	for _, p := range present {
		for path := range notes[p.path].modules {
			modules[path] = true
		}
		for heading := range notes[p.path].works {
			if _, ok := holds(works[heading], p, builds); ok {
				held[heading] = true
			}
		}
	}
	beside := "the program"
	if len(present) > 1 {
		beside = "the programs"
	}
	return fmt.Sprintf("certdoctor %s at %.12s, %d build(s) (%s), %d components beside %s",
		version, builds[0].revision, len(builds), strings.Join(labels(builds), ", "), 1+len(modules)+len(held), beside)
}
