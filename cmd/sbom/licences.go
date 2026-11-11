package main

// licenseListVersion is the release of the SPDX License List every identifier
// below was read on, and the document records it.
const licenseListVersion = "3.29"

// ourLicence is what certdoctor is under.
//
// GPL-3.0-only rather than GPL-3.0-or-later, read from what the project says
// about itself rather than assumed: THIRD-PARTY-NOTICES.md and the readme say
// "the GNU General Public License, version 3", the help text says GPL-3.0,
// LICENSE is the bare text, and no file offers a later version. The two are different licences to a machine, and
// guessing the generous one would publish a permission nobody granted.
const ourLicence = "GPL-3.0-only"

// listedLicences are the identifiers from the SPDX License List a document may
// carry. Each was read on the list itself, at release 3.29.0 of 2026-09-16
// (https://github.com/spdx/license-list-data/tree/v3.29.0), and none is
// deprecated there - the first eight on 2026-10-28, for the command line, the
// rest on 2026-11-11, for the window, when 3.29.0 was still the newest release.
//
// Which text is which identifier was matched that day against the list's own
// templates, not by eye: the Lucent notice goja carries in ftoa is SMLNJ, the
// 1993 form of Sun's fdlibm notice is SunPro, and fiat-crypto's text, with its
// single condition, is BSD-1-Clause. The window's identifiers are the ones its
// notices were written with (ADR127), and what was read for them on 2026-11-11
// is that each is on the list under that name.
//
// The C compiler's runtime in the window was matched on 2026-11-11 against
// every template of 3.29.0 (internal_tools/noty-okna/spdx). One text of the
// MinGW-w64 runtime is named by judgement rather than by a match: its first
// notice is the Zope Public License 2.1 without the title and without the one
// sentence of the optional preamble that says a copyright notice accompanies
// the licence. The template keeps the two sentences of that preamble together,
// so the text matches ZPL-2.1 only with the remaining sentence left out too -
// and Fedora's package of the same runtime, mingw-crt, names it ZPL-2.1.
//
// An identifier the notices name and this list does not is refused rather than
// passed through. A misspelt one makes the whole document invalid, and a valid
// one nobody read is a licence nobody checked.
var listedLicences = map[string]bool{
	"Apache-2.0":   true,
	"BSD-1-Clause": true,
	"BSD-2-Clause": true,
	"BSD-3-Clause": true,
	"GPL-3.0-only": true,
	"MIT":          true,
	"SMLNJ":        true,
	"SunPro":       true,

	"Bitstream-Vera":    true,
	"BSL-1.0":           true,
	"CC-BY-4.0":         true,
	"HPND-sell-variant": true,
	"ISC":               true,
	"LGPL-2.1-or-later": true,
	"OFL-1.1":           true,
	"OPUBL-1.0":         true,
	"Unlicense":         true,
	"Zlib":              true,
	"ZPL-2.1":           true,
}

// listedExceptions are the identifiers from the list of exceptions the same
// release publishes beside the licences (json/exceptions.json at v3.29.0), the
// only words that may follow WITH. Read on 2026-11-11 and not deprecated there.
// LLVM's own exception to Apache-2.0 is in the software renderer that travels
// beside the window on Windows. The two GCC exceptions are the permission to
// link the start files of the GNU C Library into any program, with and without
// the paragraph that says modified versions need not keep it - matched against
// the templates that day, with the template's "Lesser" in place of "Library".
var listedExceptions = map[string]bool{
	"GCC-exception-2.0":      true,
	"GCC-exception-2.0-note": true,
	"LLVM-exception":         true,
}

// refPrefix is how SPDX names a text that is not on its list.
const refPrefix = "LicenseRef-"

// An unlistedLicence is a text the SPDX License List has no identifier for. A
// document that names one has to carry its words, and the words are the quoted
// text in the notices that opens with the line given here - so they exist
// once, in the notices, and not a second time in Go.
type unlistedLicence struct {
	id    string
	name  string
	opens string
}

// unlisted are those texts.
//
// The first two are in the standard library. On 2026-10-28 both were matched
// against every template in the list's repository, at release 3.29.0 and at the
// main branch of 2026-10-27, and neither matched any. The 2004 form of the
// fdlibm notice is the SunPro text without its "Developed at SunPro" line,
// which that template does not let go of.
//
// The other three are in the window. Read on 2026-11-11 against the texts of
// the list at 3.29.0 that a search of its names offers for each: the public
// domain statement of a MinGW-w64 header is none of the ten public domain
// entries (CC-PDDC, CC-PDM-1.0, libselinux-1.0, NCBI-PD, NIST-PD,
// NIST-PD-fallback, NIST-PD-TNT, NTIA-PD, SAX-PD, SAX-PD-2.0); no text on the
// list names the Arev fonts or their author; and the OpenGL reference pages
// name the SGI Free Software License B without a version, where the list has
// versions 1.0, 1.1 and 2.0 and SGI-OpenGL is another text.
var unlisted = []unlistedLicence{
	{
		id:    "LicenseRef-Sun-fdlibm-2004",
		name:  "Sun Microsystems fdlibm notice, 2004 form",
		opens: "Copyright (C) 2004 by Sun Microsystems, Inc. All rights reserved.",
	},
	{
		id:    "LicenseRef-Cephes",
		name:  "Cephes Math Library notice",
		opens: "Cephes Math Library Release 2.8:  June, 2000",
	},
	{
		id:    "LicenseRef-Arev",
		name:  "Arev Fonts notice, as DejaVu Sans Mono for Powerline carries it",
		opens: "Fonts are (c) Bitstream (see below). DejaVu changes are in public domain.",
	},
	{
		id:    "LicenseRef-Public-Domain",
		name:  "MinGW-w64 public domain notice",
		opens: "This file has no copyright assigned and is placed in the Public Domain.",
	},
	{
		id:    "LicenseRef-SGI-FreeB",
		name:  "SGI Free Software License B, with no version named",
		opens: "Copyright (c) 2010 Khronos Group.",
	},
	// No licence at all: MinGW-w64's own note, in the list of notices of its
	// runtime, that the Cephes files it carries came without one. It matched no
	// template of 3.29.0 on 2026-11-11, and it is not the Cephes notice the Go
	// standard library carries, which is LicenseRef-Cephes above.
	{
		id:    "LicenseRef-MinGW-w64-Cephes",
		name:  "MinGW-w64 note on the Cephes math library",
		opens: "FIXME: Cephes math lib",
	},
}

// unlistedNamed is the entry for one LicenseRef identifier, or nil.
func unlistedNamed(id string) *unlistedLicence {
	for i := range unlisted {
		if unlisted[i].id == id {
			return &unlisted[i]
		}
	}
	return nil
}
