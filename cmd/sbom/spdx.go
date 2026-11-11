package main

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// repository is where this project lives. The document's namespace starts with
// it, and the program's download location is the commit inside it.
const repository = "https://github.com/donislawdev/certdoctor"

// ourCopyright is the line THIRD-PARTY-NOTICES.md opens with.
const ourCopyright = "Copyright (C) 2026 DonislawDev"

// noAssertion is what SPDX writes where the document says nothing, and it is
// written rather than left out wherever the field is required.
const noAssertion = "NOASSERTION"

// The shape of the document, as structs rather than maps, because a struct
// marshals its fields in the order they are declared and the same input then
// renders the same bytes. Only the fields this project fills are here - a field
// carrying NOASSERTION everywhere is noise that reads like information.
type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreation       `json:"creationInfo"`
	Extracted         []spdxExtracted    `json:"hasExtractedLicensingInfos,omitempty"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreation struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion"`
	Comment            string   `json:"comment"`
}

type spdxExtracted struct {
	LicenseID     string `json:"licenseId"`
	ExtractedText string `json:"extractedText"`
	Name          string `json:"name"`
}

type spdxPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	Supplier         string `json:"supplier,omitempty"`
	DownloadLocation string `json:"downloadLocation"`

	// False, and deliberately. The document describes components rather than
	// the files they arrive as, and claiming otherwise would oblige it to list
	// and checksum every file. A half filled list of files reads as a full one.
	FilesAnalyzed bool `json:"filesAnalyzed"`

	LicenseConcluded      string            `json:"licenseConcluded"`
	LicenseDeclared       string            `json:"licenseDeclared"`
	CopyrightText         string            `json:"copyrightText"`
	ExternalRefs          []spdxExternalRef `json:"externalRefs,omitempty"`
	PrimaryPackagePurpose string            `json:"primaryPackagePurpose,omitempty"`
	Comment               string            `json:"comment,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// goRelease is a toolchain that is a release, which is what a scanner can look
// up. The notices guard holds the running toolchain to the one go.mod names, so
// a release candidate or a development build stops there first.
var goRelease = regexp.MustCompile(`^go\d+\.\d+(?:\.\d+)?$`)

// namespace is unique for each document and stable for the same builds.
func namespace(version, revision string, targets []string) string {
	sum := sha256.Sum256([]byte(version + "|" + revision + "|" + strings.Join(targets, ",")))
	return fmt.Sprintf("%s/spdx/certdoctor-%s-%x", repository, version, sum[:8])
}

// stdlibPackage is the Go runtime and standard library.
//
// Named stdlib, with the package URL pkg:golang/stdlib and the CPE of the Go
// project, because that is how a scanner finds a vulnerability in it: syft
// writes exactly these for the standard library of a Go binary, the version
// without its "go" prefix - read at source 2026-10-28,
// https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/golang/stdlib_package.go
// - and grype matches on them. Under any other name the toolchain this program
// is built with would be invisible to the question a scanner asks most.
func stdlibPackage(c component) (spdxPackage, error) {
	if !goRelease.MatchString(c.version) {
		return spdxPackage{}, fmt.Errorf("the notices name the toolchain %s, which is not a Go release", c.version)
	}
	release := strings.TrimPrefix(c.version, "go")
	return spdxPackage{
		SPDXID:           "SPDXRef-Package-stdlib",
		Name:             "stdlib",
		VersionInfo:      c.version,
		DownloadLocation: noAssertion,
		LicenseConcluded: expression(c),
		LicenseDeclared:  expression(c),
		CopyrightText:    copyrightText(c),
		ExternalRefs: []spdxExternalRef{
			{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:golang/stdlib@" + release},
			{ReferenceCategory: "SECURITY", ReferenceType: "cpe23Type", ReferenceLocator: "cpe:2.3:a:golang:go:" + release + ":-:*:*:*:*:*:*"},
		},
		Comment: "The Go runtime and standard library, linked into every build.",
	}, nil
}

// programPackage is one of this project's programs, built from the commit the
// builds record.
func programPackage(p program, version, revision string, builds []build, whole bool) spdxPackage {
	targets := make([]string, 0, len(builds))
	for _, b := range builds {
		targets = append(targets, b.target)
	}
	slices.Sort(targets)
	linked := "Every one of these builds links each component this package contains"
	if !whole {
		linked = "Each component this package contains is linked into at least one of these builds, and one linked into " +
			"some of them alone says which"
	}
	return spdxPackage{
		SPDXID:      "SPDXRef-Package-" + p.name,
		Name:        p.name,
		VersionInfo: version,
		Supplier:    "Organization: DonislawDev",
		// The commit the builds record, in the form SPDX gives for a version
		// control location, so that the source of these exact binaries can be
		// fetched rather than the project's latest.
		DownloadLocation: "git+" + repository + ".git@" + revision,
		LicenseConcluded: ourLicence,
		LicenseDeclared:  ourLicence,
		CopyrightText:    ourCopyright,
		// The module's, for both programs: a package URL names a module, and
		// both are built from this one.
		ExternalRefs:          []spdxExternalRef{packageURL(modulePath, "v"+version)},
		PrimaryPackagePurpose: "APPLICATION",
		Comment: "The program built from " + strings.TrimPrefix(p.path, modulePath+"/") + " of commit " + revision +
			", for " + strings.Join(targets, ", ") + ". " + linked + ", as the build information in the binary records it.",
	}
}

func modulePackage(c component) spdxPackage {
	return spdxPackage{
		SPDXID:           identifier(c.path),
		Name:             c.path,
		VersionInfo:      c.version,
		DownloadLocation: noAssertion,
		LicenseConcluded: expression(c),
		LicenseDeclared:  expression(c),
		CopyrightText:    copyrightText(c),
		ExternalRefs:     []spdxExternalRef{packageURL(c.path, c.version)},
	}
}

// workPackage is a work that is not a module: a typeface compiled into the
// window, or files that travel beside it. Nothing a scanner looks things up by
// is asserted for it - neither is a Go module, so a package URL in the golang
// type would name something that does not exist.
func workPackage(c component, w work) spdxPackage {
	comment := w.about
	if len(c.files) > 0 {
		comment += " As the notices list them: " + fileList(c.files) +
			". These are the files as the release they come from holds them. A release signs them, and a signed copy is " +
			"longer and has another sum."
	}
	return spdxPackage{
		SPDXID:           identifier(c.path),
		Name:             c.path,
		VersionInfo:      c.version,
		DownloadLocation: noAssertion,
		LicenseConcluded: expression(c),
		LicenseDeclared:  expression(c),
		CopyrightText:    copyrightText(c),
		Comment:          comment,
	}
}

// expression is the component's licence expression. Declared and concluded
// carry the same one: every text it names ships in the component's own tree,
// so its authors declared it, and the notices quote each of them.
func expression(c component) string {
	return joinTerms(c.licences)
}

func copyrightText(c component) string {
	if len(c.copyrights) == 0 {
		return noAssertion
	}
	return strings.Join(c.copyrights, "\n")
}

// notIdentifier is everything the SPDX identifier grammar does not allow: it
// permits letters, digits, dots and hyphens, and a module path is full of
// slashes.
var notIdentifier = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

func identifier(name string) string {
	return "SPDXRef-Package-" + strings.Trim(notIdentifier.ReplaceAllString(name, "-"), "-")
}

// packageURL is how a machine looks a module up. Each segment and the version
// are percent encoded outside the characters the specification leaves alone,
// which turns the plus of "+incompatible" into %2B - the canonical form, per
// https://github.com/package-url/purl-spec/blob/main/docs/specification/lenient-ABNF-grammar.md
// read 2026-10-28.
func packageURL(path, version string) spdxExternalRef {
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = percentEncode(s)
	}
	return spdxExternalRef{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  "pkg:golang/" + strings.Join(segments, "/") + "@" + percentEncode(version),
	}
}

func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte(".-_~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}
