package file

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// AppAlias names the package an app execution alias belongs to - the file of
// no bytes Windows keeps in %LOCALAPPDATA%\Microsoft\WindowsApps for a command
// a packaged application answers to. ADR112, decided by the owner 2026-10-21.
//
// IT IS A PORT OF ITS OWN BECAUSE Source CANNOT READ SUCH A FILE AT ALL. Go
// opens it as an ordinary file and Windows answers that the file cannot be
// accessed - measured with probe S28 on all forty-five aliases on the owner's
// machine, 2026-10-21. What it holds is a reparse point, and the only thing
// this program needs of it is the package behind it.
type AppAlias func(path string) (string, error)

// GuardedAppAlias refuses to read an alias that would leave this machine.
//
// THE RULE IS CONSUMED, NEVER COPIED - the same rule as Guarded and GuardedList
// and in the same order, through refuseRemote. Reading a reparse point opens
// the path, and a UNC path opened is a connection - docs/14 section 3a.
func GuardedAppAlias(inner AppAlias, resolve Resolve, record Record) AppAlias {
	return func(path string) (string, error) {
		if err := refuseRemote(path, resolve, record); err != nil {
			return "", err
		}
		if inner == nil {
			return "", fmt.Errorf("no way to read an app execution alias was supplied, so %s was not read", path)
		}
		pkg, err := inner(path)
		if record != nil {
			record(path, err == nil)
		}
		return pkg, err
	}
}

// ErrNotAnAppAlias is what a reparse point that is not an app execution alias,
// or not one in the measured shape, is refused with.
var ErrNotAnAppAlias = errors.New("not an app execution alias in the shape this program was measured on")

// The reparse tag of an app execution alias, IO_REPARSE_TAG_APPEXECLINK -
// MS-FSCC 2.1.2.1, read 2026-10-21 at
// https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
// - and the one version of its data that was measured.
const (
	appExecLinkTag     = 0x8000001B
	appExecLinkVersion = 3
)

// AppAliasPackage reads the package family name out of the reparse data of an
// app execution alias.
//
// THE LAYOUT IS MEASURED, NOT PUBLISHED. MS-FSCC 2.1.2.2 gives the header every
// reparse point shares - the tag, the length of the data after it, two reserved
// bytes - and says the data is its owner's to define, and Microsoft publishes
// nothing more of it. So the data is read the way probe S28 measured it on the
// owner's machine 2026-10-21, on all forty-five aliases of twenty-one packages in
// WindowsApps: a version, 3, and then strings in UTF-16, each ending in a zero -
// the package family name, the application within it, the file it starts, and
// on every one of them a fourth, "0". A version nobody measured is refused rather
// than guessed at, and so is data holding fewer than the three strings that make
// an alias.
func AppAliasPackage(data []byte) (string, error) {
	if len(data) < 8 || binary.LittleEndian.Uint32(data) != appExecLinkTag {
		return "", ErrNotAnAppAlias
	}
	body := data[8:]
	length := int(binary.LittleEndian.Uint16(data[4:]))
	if length > len(body) {
		return "", fmt.Errorf("%w: the data says it is %d bytes long and %d arrived", ErrNotAnAppAlias, length, len(body))
	}
	body = body[:length]
	if len(body) < 4 || binary.LittleEndian.Uint32(body) != appExecLinkVersion {
		return "", fmt.Errorf("%w: its version is not %d", ErrNotAnAppAlias, appExecLinkVersion)
	}
	strs := terminated(body[4:])
	if len(strs) < 3 || strs[0] == "" {
		return "", fmt.Errorf("%w: it holds %d of the strings an alias holds", ErrNotAnAppAlias, len(strs))
	}
	return strs[0], nil
}

// terminated splits UTF-16 in little-endian order into the strings ending in a
// zero, leaving out whatever follows the last zero.
func terminated(data []byte) []string {
	var strs []string
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		unit := binary.LittleEndian.Uint16(data[i:])
		if unit != 0 {
			units = append(units, unit)
			continue
		}
		strs = append(strs, string(utf16.Decode(units)))
		units = units[:0]
	}
	return strs
}
