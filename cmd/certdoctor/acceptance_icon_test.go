//go:build acceptance

package main

import (
	"debug/pe"
	"encoding/binary"
	"runtime"
	"testing"
)

// The resource types Windows reads an executable's icon and manifest from, as
// winuser.h numbers them (RT_ICON, RT_GROUP_ICON, RT_MANIFEST).
const (
	resourceIcon      = 3
	resourceIconGroup = 14
	resourceManifest  = 24
)

// TestTheShippedBinaryCarriesItsIconOnWindows opens the executable a person
// downloads and reads its resources the way Explorer and the taskbar do.
//
// THE ICON COMES FROM A FILE THE LINKER PICKS UP BY ITS NAME, which is why only
// the shipped binary can answer this. cmd/certdoctor/rsrc_windows_amd64.syso and
// its arm64 twin are linked into a Windows build because of how they are
// spelled, with no import and no line of Go naming them. A renamed or deleted
// file builds just as well and gives an executable Windows draws its own
// placeholder for.
//
// NO MANIFEST, and that is checked too. The resources were made with
// --manifest none on purpose: a manifest changes how Windows runs a program,
// and adding one is a decision of its own rather than a side effect of adding
// a picture.
func TestTheShippedBinaryCarriesItsIconOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the icon is a resource of the Windows executable - an ELF or a Mach-O binary carries " +
			"none, and macOS takes it from the .app bundle the release wraps the binary in")
	}
	file, err := pe.Open(theBinary(t))
	if err != nil {
		t.Fatalf("the binary is not a readable PE file: %v", err)
	}
	defer file.Close()

	section := file.Section(".rsrc")
	if section == nil {
		t.Fatal("the binary has no resource section, so Windows shows its placeholder instead of the icon - " +
			"is cmd/certdoctor/rsrc_windows_" + runtime.GOARCH + ".syso still there?")
	}
	data, err := section.Data()
	if err != nil {
		t.Fatalf("the resource section cannot be read: %v", err)
	}
	types := resourceTypes(t, data)
	if !types[resourceIconGroup] || !types[resourceIcon] {
		t.Errorf("the resource section carries types %v and an icon needs both %d and %d",
			types, resourceIconGroup, resourceIcon)
	}
	if types[resourceManifest] {
		t.Error("the binary carries a manifest, which changes how Windows runs it - " +
			"the icon resources are made with --manifest none")
	}
}

// resourceTypes reads the root of a resource section.
//
// The root is an IMAGE_RESOURCE_DIRECTORY - 16 bytes whose last two words count
// the entries with a name and the entries with a number - followed by 8 bytes
// per entry, the first four of which are the type. A type with its top bit set
// is a name rather than a number, and none of the types asked about here is one.
func resourceTypes(t *testing.T, data []byte) map[uint32]bool {
	t.Helper()
	if len(data) < 16 {
		t.Fatalf("the resource section is %d bytes, shorter than its own directory", len(data))
	}
	entries := int(binary.LittleEndian.Uint16(data[12:])) + int(binary.LittleEndian.Uint16(data[14:]))
	types := map[uint32]bool{}
	for i := 0; i < entries; i++ {
		at := 16 + 8*i
		if at+8 > len(data) {
			t.Fatalf("the resource directory names %d entries and the section ends after %d", entries, i)
		}
		if id := binary.LittleEndian.Uint32(data[at:]); id&0x80000000 == 0 {
			types[id] = true
		}
	}
	return types
}
