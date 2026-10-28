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
// carry. Each was read on the list itself on 2026-10-28, at release 3.29.0 of
// 2026-09-16 (https://github.com/spdx/license-list-data/tree/v3.29.0), and none
// is deprecated there.
//
// Which text is which identifier was matched that day against the list's own
// templates, not by eye: the Lucent notice goja carries in ftoa is SMLNJ, the
// 1993 form of Sun's fdlibm notice is SunPro, and fiat-crypto's text, with its
// single condition, is BSD-1-Clause.
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
}

// refPrefix is how SPDX names a text that is not on its list.
const refPrefix = "LicenseRef-"

// An unlistedLicence is a text the SPDX License List has no identifier for. A
// document that names one has to carry its words, and the words are the quoted
// text in THIRD-PARTY-NOTICES.md that opens with the line given here - so they
// exist once, in the notices, and not a second time in Go.
type unlistedLicence struct {
	id    string
	name  string
	opens string
}

// unlisted are those texts. On 2026-10-28 both were matched against every
// template in the list's repository, at release 3.29.0 and at the main branch
// of 2026-10-27, and neither matched any. The 2004 form of the fdlibm notice is
// the SunPro text without its "Developed at SunPro" line, which that template
// does not let go of.
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
