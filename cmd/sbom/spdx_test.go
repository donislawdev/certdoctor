package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// golden is the document the fixture renders to. It is the shape the SPDX
// project's own validator accepted - pyspdxtools from spdx-tools 0.8.5 on
// 2026-10-28, which on the same day rejected four documents broken on purpose
// (an unknown licence, a relationship to a missing package, a time in the wrong
// form, a LicenseRef without its text). A change to the renderer shows up here
// as a failure that prints the new document, and that document is what to run
// the validator on before it replaces this file.
var golden = filepath.Join("testdata", "fixture.spdx.json")

// goldenWindow is the document of both programs, held to the same validator
// the same way - spdx-tools 0.8.5 accepted it on 2026-11-11.
var goldenWindow = filepath.Join("testdata", "fixture-window.spdx.json")

func renderFixture(t *testing.T, listing string) []byte {
	t.Helper()
	document, err := render(fixtureTree.version, readBuilds(t, listing), fixtureNotes(t))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestTheDocumentIsTheOneTheValidatorAccepted(t *testing.T) {
	for file, listing := range map[string]string{
		golden:       fixtureListing(),
		goldenWindow: fixtureListing() + fixtureWindowListing(),
	} {
		document := renderFixture(t, listing)
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(document, want) {
			t.Errorf("the document is not %s. If the change is meant, validate this one and put it there:\n%s", file, document)
		}
	}
}

// What the window's document says about its parts, read back rather than
// trusted from the golden file: the parts both programs link are one package
// each, the binding says it was built from a copy, the portal says it is in
// one build, and the software renderer is a dependency of the window that the
// window does not contain.
func TestTheWindowsPartsAreDescribedForWhatTheyAre(t *testing.T) {
	var doc spdxDocument
	if err := json.Unmarshal(renderFixture(t, fixtureListing()+fixtureWindowListing()), &doc); err != nil {
		t.Fatal(err)
	}
	pkgs := map[string]spdxPackage{}
	for _, p := range doc.Packages {
		if _, twice := pkgs[p.Name]; twice {
			t.Errorf("%s is listed twice", p.Name)
		}
		pkgs[p.Name] = p
	}
	for name, want := range map[string]string{
		"github.com/go-gl/gl": "Linked from a copy kept in third_party/go-gl-gl of this repository",
		"example.com/portal":  "Linked into the build(s) of certdoctor-gui for linux/amd64 and into no other.",
		"Mesa 3D":             "opengl/opengl32.dll, 139264 bytes, SHA-256 c8511461ba71a0288750467e3be2f5c1c2bbbceaaf0ab5d8c496b0ba7302daa8.",
		"certdoctor-gui":      "and one linked into some of them alone says which",
		"certdoctor":          "Every one of these builds links each component this package contains",
		"stdlib":              "linked into every build of every program",
	} {
		if !strings.Contains(pkgs[name].Comment, want) {
			t.Errorf("%s says %q, which does not say %q", name, pkgs[name].Comment, want)
		}
	}
	for name, want := range map[string]string{
		"stdlib":              "BSD-3-Clause AND LicenseRef-Sun-fdlibm-2004 AND LicenseRef-Cephes AND MIT",
		"example.com/toolkit": "(Unlicense OR BSD-3-Clause) AND MIT AND LicenseRef-Arev",
		"Mesa 3D":             "MIT AND Apache-2.0 WITH LLVM-exception",
	} {
		if got := pkgs[name].LicenseDeclared; got != want {
			t.Errorf("%s is under %q, want %q", name, got, want)
		}
	}
	if got := pkgs["example.com/beta/v2"].CopyrightText; got != "Copyright (c) 2016 Beta & <Contributors>\nCopyright (c) 2017 A Second Beta Author" {
		t.Errorf("the module both link carries the copyright %q", got)
	}
	relations := map[string]bool{}
	for _, r := range doc.Relationships {
		relations[r.SPDXElementID+" "+r.RelationshipType+" "+r.RelatedSPDXElement] = true
	}
	for _, want := range []string{
		"SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-certdoctor-gui",
		"SPDXRef-Package-certdoctor CONTAINS SPDXRef-Package-example.com-beta-v2",
		"SPDXRef-Package-certdoctor-gui CONTAINS SPDXRef-Package-example.com-beta-v2",
		"SPDXRef-Package-certdoctor-gui CONTAINS SPDXRef-Package-Inter",
		"SPDXRef-Package-Mesa-3D OPTIONAL_DEPENDENCY_OF SPDXRef-Package-certdoctor-gui",
	} {
		if !relations[want] {
			t.Errorf("no relationship %q", want)
		}
	}
	for _, unwanted := range []string{
		"SPDXRef-Package-certdoctor CONTAINS SPDXRef-Package-Inter",
		"SPDXRef-Package-certdoctor-gui CONTAINS SPDXRef-Package-Mesa-3D",
		"SPDXRef-Package-certdoctor-gui CONTAINS SPDXRef-Package-example.com-alpha",
	} {
		if relations[unwanted] {
			t.Errorf("a relationship %q", unwanted)
		}
	}
}

// The software renderer travels beside the build for Windows alone, so a
// document of builds without that one does not name it.
func TestFilesBesideOneBuildAreNamedOnlyWithThatBuild(t *testing.T) {
	listing := fixtureListing() + windowListingFor("dist/certdoctor-gui", "linux/amd64", windowDeps(fixturePortal))
	var doc spdxDocument
	if err := json.Unmarshal(renderFixture(t, listing), &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Packages {
		if p.Name == "Mesa 3D" {
			t.Error("a document with no build for windows/amd64 names the files beside it")
		}
	}
	notes := fixtureNotes(t)
	if got := summary("0.1.0", readBuilds(t, listing), notes); !strings.HasSuffix(got, ", 8 components beside the programs") {
		t.Errorf("the summary counts the files beside a build that is not there: %s", got)
	}
}

// One document names one version of a thing, and the notices of the two
// programs naming two is refused - whether a module or the toolchain.
func TestTwoVersionsOfOnePartAreRefused(t *testing.T) {
	builds := readBuilds(t, fixtureListing()+fixtureWindowListing())
	for name, edit := range map[string]func(n *notices){
		"example.com/beta/v2 is v2.0.0+incompatible in the notices read before and v2.0.1 in THIRD-PARTY-NOTICES-GUI.md": func(n *notices) {
			c := n.modules["example.com/beta/v2"]
			c.version = "v2.0.1"
			n.modules["example.com/beta/v2"] = c
		},
		"Go standard library and runtime is go1.27.3 in the notices read before and go1.27.4": func(n *notices) {
			n.std.version = "go1.27.4"
		},
	} {
		notes := fixtureNotes(t)
		w := notes[windowPath]
		edit(&w)
		notes[windowPath] = w
		if _, err := render("0.1.0", builds, notes); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("err = %v, want one saying %q", err, name)
		}
	}
}

// The same builds give the same bytes, in whatever order they arrive, because a
// document that differs every time it is generated cannot be compared with the
// one published.
func TestTheSameBuildsGiveTheSameBytes(t *testing.T) {
	reversed := listingFor("dist/certdoctor-windows-arm64.exe", "windows/arm64", "go1.27.3", fixtureDeps) +
		listingFor("dist/certdoctor-linux-amd64", "linux/amd64", "go1.27.3", fixtureDeps)
	if !bytes.Equal(renderFixture(t, fixtureListing()), renderFixture(t, reversed)) {
		t.Error("two orders of the same builds rendered two documents")
	}
	windowFirst := fixtureWindowListing() + reversed
	if !bytes.Equal(renderFixture(t, fixtureListing()+fixtureWindowListing()), renderFixture(t, windowFirst)) {
		t.Error("two orders of the builds of both programs rendered two documents")
	}
}

// Another set of targets is another document, and a namespace names exactly one.
func TestAnotherSetOfTargetsIsAnotherNamespace(t *testing.T) {
	one := listingFor("dist/certdoctor-linux-amd64", "linux/amd64", "go1.27.3", fixtureDeps)
	var a, b spdxDocument
	if err := json.Unmarshal(renderFixture(t, one), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(renderFixture(t, fixtureListing()), &b); err != nil {
		t.Fatal(err)
	}
	if a.DocumentNamespace == b.DocumentNamespace {
		t.Errorf("one build and two builds share the namespace %s", a.DocumentNamespace)
	}
}

func TestAToolchainThatIsNotAReleaseIsRefused(t *testing.T) {
	if _, err := stdlibPackage(component{version: "go1.28rc1"}); err == nil || !strings.Contains(err.Error(), "not a Go release") {
		t.Errorf("err = %v", err)
	}
}

func TestTwoComponentsCannotShareAnIdentifier(t *testing.T) {
	notes := fixtureNotes(t)
	notes[programPath].modules["example.com-alpha"] = component{path: "example.com-alpha", version: "v1.0.0", licences: []string{"MIT"}}
	if _, err := render("0.1.0", readBuilds(t, fixtureListing()), notes); err == nil ||
		!strings.Contains(err.Error(), "both become SPDXRef-Package-example.com-alpha") {
		t.Errorf("err = %v", err)
	}
}

// A toolchain that is not a release is refused wherever the notices name it.
func TestAToolchainThatIsNotAReleaseIsRefusedInTheDocument(t *testing.T) {
	notes := fixtureNotes(t)
	n := notes[programPath]
	n.std.version = "go1.28rc1"
	notes[programPath] = n
	if _, err := render("0.1.0", readBuilds(t, fixtureListing()), notes); err == nil || !strings.Contains(err.Error(), "not a Go release") {
		t.Errorf("err = %v", err)
	}
}

func TestAPackageURLIsPercentEncoded(t *testing.T) {
	got := packageURL("example.com/a b/c~d", "v2.0.0+incompatible").ReferenceLocator
	if want := "pkg:golang/example.com/a%20b/c~d@v2.0.0%2Bincompatible"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestAComponentWithoutACopyrightLineAssertsNothing(t *testing.T) {
	if got := copyrightText(component{}); got != noAssertion {
		t.Errorf("got %q", got)
	}
}
