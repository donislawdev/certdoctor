// Package certdoctor carries the facts about this binary that cannot be
// established from inside the tree: which version it is, what licence it ships
// under, and the notices of the code it carries that somebody else wrote.
//
// WHY THIS PACKAGE SITS IN THE MODULE ROOT, WHICH IS UNUSUAL AND DELIBERATE.
// The --license flag has to show what is in the binary rather than what is in
// the repository, because the person holding a downloaded executable has no
// repository to look at. That means embedding the licence text. Go's embed
// directive cannot reach a parent directory - measured on 2026-08-02, a
// subpackage asking for ../LICENSE is refused at compile time with "pattern
// ../LICENSE: invalid pattern syntax" - so the only package that can embed the
// file at the repository root is a package that lives beside it. The
// alternative was a second copy of a 35 kilobyte file that must stay identical
// to the first, which is a source of truth waiting to split.
//
// This package holds nothing else, imports nothing of ours, and only the entry
// point imports it. The layer guard enforces all three.
package certdoctor

import _ "embed"

// Version is what --version reports and what every report carries.
//
// It is not raised by the assistant. Raising it is a statement to the people
// using this tool - that something changed, and how much - and that statement
// belongs to the owner. A version bumped as tidying up is a promise nobody
// meant to make.
const Version = "0.2.0"

// Name is the command as it is invoked, used in help text and in the report.
const Name = "certdoctor"

// License is the full text of the licence this binary ships under.
//
// Embedded verbatim rather than summarised. The text was fetched from its
// source rather than reproduced from memory, and reproducing a licence from
// memory is the same class of mistake as reproducing a measurement from memory,
// only harder to notice because nobody reads it closely enough to catch it.
//
//go:embed LICENSE
var License string

// Notices is the text of THIRD-PARTY-NOTICES.md: the licences of the code
// somebody else wrote that this binary links - the Go runtime and standard
// library, and the modules behind the PAC evaluator.
//
// IN THE BINARY AND NOT ONLY IN THE RELEASE ARCHIVE, for the reason License is.
// MIT and BSD ask for their notice in every copy of the code, a binary copy
// included, and this binary travels on its own: copied into a container image,
// it leaves the archive and the file beside it behind. Until 2026-10-28 it
// carried the GPL and nothing else - ADR116.
//
//go:embed THIRD-PARTY-NOTICES.md
var Notices string

// WindowNotices is the text of THIRD-PARTY-NOTICES-GUI.md: the licences of the
// code somebody else wrote that the window, certdoctor-gui, links, and of the
// files that travel beside it (ADR127 decision 4).
//
// Here for the bill of materials alone, which describes the window's builds
// against it and, like every tool of this project, opens no file to do so. No
// binary a person downloads names it, and the linker leaves out a variable
// nothing names - measured on 2026-11-11: the command line built for windows,
// linux and macOS with this variable and without it, the build identifier
// blanked, is the same bytes.
//
//go:embed THIRD-PARTY-NOTICES-GUI.md
var WindowNotices string
