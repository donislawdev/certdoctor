package probe

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"
)

// headerWindow is how much of a binary is read to find the machine it was built
// for.
//
// THE THREE FIELDS SIT AT THE START, and only the PE one moves. An ELF header
// carries the machine at byte 18 and a Mach-O header at byte 4. A PE image
// carries it right after the signature, which sits where the four bytes at 0x3c
// say - "placed at location 0x3c during linking", read 2026-10-26 at
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format. That offset
// is a linker's choice and lands within the first few hundred bytes in practice,
// an ASSESSMENT, not a source, so a stub past this window gives "" rather than
// a longer read.
const headerWindow = 4096

// Architecture names the machine a binary was built for - x86, x64 or arm64 -
// read from the binary's own header, or "" when the header does not say one of
// those - ADR114 B15.
//
// IT USED TO BE READ OFF THE PATH: x86 where the path said "(x86)", x64 for
// everything else, which called every Java and git on an ARM Mac or an arm64
// Linux x64. A row that says nothing is honest, and one that says the wrong
// machine sends a fix to the wrong install.
//
// THE HEADER IS READ BY HAND, WITH THE CONSTANTS OF debug/pe, debug/elf AND
// debug/macho. Their NewFile wants an io.ReaderAt over the whole file, because
// section tables usually sit at the end, and the file port hands out a stream
// under a size cap. Three fields at the start need neither.
func Architecture(open func(string) (io.ReadCloser, error), path string) string {
	reader, err := open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = reader.Close() }()
	head := make([]byte, headerWindow)
	n, err := io.ReadFull(reader, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return ""
	}
	return machineOf(head[:n])
}

// machineOf tells the three formats apart by their first bytes.
func machineOf(head []byte) string {
	switch {
	case len(head) >= 4 && string(head[:4]) == elf.ELFMAG:
		return elfMachine(head)
	case len(head) >= 2 && string(head[:2]) == "MZ":
		return peMachine(head)
	case len(head) >= 8:
		return machoMachine(head)
	}
	return ""
}

// elfMachine reads e_machine in the byte order the header declares - the field
// after the sixteen identifying bytes and the two of the file type, Header32 and
// Header64 alike in debug/elf of Go 1.27.3.
func elfMachine(head []byte) string {
	if len(head) < 20 {
		return ""
	}
	var order binary.ByteOrder
	switch elf.Data(head[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		order = binary.LittleEndian
	case elf.ELFDATA2MSB:
		order = binary.BigEndian
	default:
		return ""
	}
	switch elf.Machine(order.Uint16(head[18:])) {
	case elf.EM_386:
		return "x86"
	case elf.EM_X86_64:
		return "x64"
	case elf.EM_AARCH64:
		return "arm64"
	}
	return ""
}

// peMachine reads the Machine field, the first of the COFF header right after
// the "PE\0\0" signature, little endian as every PE field is.
func peMachine(head []byte) string {
	if len(head) < 0x40 {
		return ""
	}
	at := binary.LittleEndian.Uint32(head[0x3c:])
	if at > uint32(len(head)-6) || string(head[at:at+4]) != "PE\x00\x00" {
		return ""
	}
	switch binary.LittleEndian.Uint16(head[at+4:]) {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	}
	return ""
}

// machoMachine reads the cpu type after the magic, in whichever byte order the
// magic is written - the test debug/macho's NewFile makes.
//
// A UNIVERSAL BINARY SAYS NOTHING HERE. It carries several machines and the Mac
// running it picks one, so naming any of them would be a guess - its magic,
// MagicFat, matches neither order below.
func machoMachine(head []byte) string {
	var order binary.ByteOrder
	switch macho.Magic32 &^ 1 {
	case binary.LittleEndian.Uint32(head) &^ 1:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(head) &^ 1:
		order = binary.BigEndian
	default:
		return ""
	}
	switch macho.Cpu(order.Uint32(head[4:])) {
	case macho.Cpu386:
		return "x86"
	case macho.CpuAmd64:
		return "x64"
	case macho.CpuArm64:
		return "arm64"
	}
	return ""
}
