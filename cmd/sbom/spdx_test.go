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

func renderFixture(t *testing.T, listing string) []byte {
	t.Helper()
	builds, err := parseBuilds(listing)
	if err != nil {
		t.Fatal(err)
	}
	document, err := render(fixtureTree.version, builds, fixtureNoticesRead(t))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestTheDocumentIsTheOneTheValidatorAccepted(t *testing.T) {
	document := renderFixture(t, fixtureListing())
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(document, want) {
		t.Errorf("the document is not %s. If the change is meant, validate this one and put it there:\n%s", golden, document)
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
	n := fixtureNoticesRead(t)
	n.modules["example.com-alpha"] = component{path: "example.com-alpha", version: "v1.0.0", licences: []string{"MIT"}}
	builds, err := parseBuilds(fixtureListing())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := render("0.1.0", builds, n); err == nil || !strings.Contains(err.Error(), "both become SPDXRef-Package-example.com-alpha") {
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
