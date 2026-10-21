package file

import (
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"
)

// reparseData is the reparse point of an app execution alias as probe S28
// measured it: the header, a version, and strings in UTF-16 each ending in a
// zero.
func reparseData(tag, version uint32, strs ...string) []byte {
	body := binary.LittleEndian.AppendUint32(nil, version)
	for _, s := range strs {
		for _, unit := range utf16.Encode([]rune(s)) {
			body = binary.LittleEndian.AppendUint16(body, unit)
		}
		body = binary.LittleEndian.AppendUint16(body, 0)
	}
	data := binary.LittleEndian.AppendUint32(nil, tag)
	data = binary.LittleEndian.AppendUint16(data, uint16(len(body)))
	data = binary.LittleEndian.AppendUint16(data, 0)
	return append(data, body...)
}

// THE ALIAS MEASURED ON THE OWNER'S MACHINE GIVES ITS PACKAGE, and a name past
// the Basic Multilingual Plane survives the trip through UTF-16.
func TestAnAppAliasNamesItsPackage(t *testing.T) {
	const manager = "PythonSoftwareFoundation.PythonManager_qbz5n2kfra8p0"
	measured := reparseData(appExecLinkTag, 3, manager, manager+"!Python.Exe",
		`C:\Program Files\WindowsApps\PythonSoftwareFoundation.PythonManager_26.4.240.0_x64__qbz5n2kfra8p0\python.exe`, "0")
	if got, err := AppAliasPackage(measured); err != nil || got != manager {
		t.Errorf("got %q, %v", got, err)
	}
	if got, err := AppAliasPackage(reparseData(appExecLinkTag, 3, "Paket\U0001F512_x", "app", "target")); err != nil ||
		got != "Paket\U0001F512_x" {
		t.Errorf("three strings and a surrogate pair: got %q, %v", got, err)
	}
}

// ANYTHING ELSE IS REFUSED, NOT GUESSED AT - another tag, a version nobody
// measured, data shorter than it says, too few strings, an empty package, and a
// string with no zero after it.
func TestWhatIsNotAMeasuredAliasIsRefused(t *testing.T) {
	short := reparseData(appExecLinkTag, 3, "pkg", "pkg!App", `C:\app.exe`)
	binary.LittleEndian.PutUint16(short[4:], uint16(len(short)-8+2))
	for name, data := range map[string][]byte{
		"nothing":            nil,
		"a junction":         reparseData(0xA0000003, 3, "pkg", "pkg!App", `C:\app.exe`),
		"version 4":          reparseData(appExecLinkTag, 4, "pkg", "pkg!App", `C:\app.exe`),
		"longer than it is":  short,
		"no version":         reparseData(appExecLinkTag, 3)[:8],
		"two strings":        reparseData(appExecLinkTag, 3, "pkg", "pkg!App"),
		"an empty package":   reparseData(appExecLinkTag, 3, "", "pkg!App", `C:\app.exe`),
		"no zero at the end": unterminated(reparseData(appExecLinkTag, 3, "pkg", "pkg!App", `C:\app.exe`)),
	} {
		if got, err := AppAliasPackage(data); !errors.Is(err, ErrNotAnAppAlias) || got != "" {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
	// THE LENGTH IN THE HEADER BOUNDS THE DATA - the zero past it does not end a
	// third string.
	beyond := append(unterminated(reparseData(appExecLinkTag, 3, "pkg", "pkg!App", `C:\app.exe`)), 0, 0)
	if got, err := AppAliasPackage(beyond); !errors.Is(err, ErrNotAnAppAlias) {
		t.Errorf("a zero past the length ended a string: got %q, %v", got, err)
	}
}

// unterminated drops the zero ending the last string and says so in the header.
func unterminated(data []byte) []byte {
	data = data[:len(data)-2]
	binary.LittleEndian.PutUint16(data[4:], uint16(len(data)-8))
	return data
}

// THE ALIAS PORT REFUSES WHAT THE READING PORT REFUSES, through the same rule,
// and records what it was asked for.
func TestGuardedAppAliasRefusesWhatGuardedRefuses(t *testing.T) {
	var asked []string
	var opened []bool
	record := func(path string, ok bool) { asked, opened = append(asked, path), append(opened, ok) }
	inner := func(string) (string, error) { return "pkg", nil }
	same := func(path string) (string, error) { return path, nil }

	var remote *RemotePath
	if _, err := GuardedAppAlias(inner, same, record)(`\\fileserver\apps\python.exe`); !errors.As(err, &remote) {
		t.Errorf("a UNC path was not refused as one: %v", err)
	}
	offMachine := func(string) (string, error) { return `\\fileserver\apps\python.exe`, nil }
	if _, err := GuardedAppAlias(inner, offMachine, nil)(`C:\apps\python.exe`); !errors.As(err, &remote) {
		t.Errorf("a link off this machine was not refused: %v", err)
	}
	if _, err := GuardedAppAlias(nil, same, nil)(`C:\apps\python.exe`); err == nil {
		t.Error("no inner port read anyway")
	}
	if got, err := GuardedAppAlias(inner, same, record)(`C:\apps\python.exe`); err != nil || got != "pkg" {
		t.Errorf("a local alias: got %q, %v", got, err)
	}
	failing := func(string) (string, error) { return "", ErrNotAnAppAlias }
	if _, err := GuardedAppAlias(failing, same, record)(`C:\apps\python.exe`); !errors.Is(err, ErrNotAnAppAlias) {
		t.Errorf("the inner failure was not handed on: %v", err)
	}
	if len(asked) != 3 || opened[0] || !opened[1] || opened[2] {
		t.Errorf("recorded %v %v", asked, opened)
	}
}
