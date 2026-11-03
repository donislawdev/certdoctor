// Package fonts carries the typeface the window is set in: Inter 4.1, Regular
// and Bold, the static files of that release (ADR122, ADR124).
//
// The licence travels with the files. Inter is under the SIL Open Font License
// 1.1, which asks every copy of the font software to carry its copyright notice
// and the licence - and this repository is a copy as much as a release is. So
// LICENSE.txt beside the fonts is Inter's own, byte for byte as published under
// the tag, read at https://raw.githubusercontent.com/rsms/inter/v4.1/LICENSE.txt
// on 2026-11-03. The files name no Reserved Font Name and carry fsType 0.
//
// Both files report "Version 4.001;git-9221beed3", and that commit sits one
// commit before the tag v4.1 of 2024-11-16 - this is the build of that release.
// They are the same bytes as the ones TestingFilesGenerator ships.
package fonts

import _ "embed"

// Regular is Inter Regular.
//
//go:embed Inter-Regular.ttf
var Regular []byte

// Bold is Inter Bold.
//
//go:embed Inter-Bold.ttf
var Bold []byte
