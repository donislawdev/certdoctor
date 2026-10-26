package probe

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// peImage is the start of a PE image: the DOS header with the offset at 0x3c,
// then the signature and the Machine field where that offset says.
func peImage(machine uint16, at uint32) []byte {
	head := make([]byte, at+24)
	copy(head, "MZ")
	binary.LittleEndian.PutUint32(head[0x3c:], at)
	copy(head[at:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(head[at+4:], machine)
	return head
}

// elfImage is the start of an ELF file in the given byte order.
func elfImage(data elf.Data, order binary.ByteOrder, machine elf.Machine) []byte {
	head := make([]byte, 64)
	copy(head, elf.ELFMAG)
	head[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	head[elf.EI_DATA] = byte(data)
	order.PutUint16(head[18:], uint16(machine))
	return head
}

// machoImage is the start of a Mach-O file in the given byte order.
func machoImage(order binary.ByteOrder, magic uint32, cpu macho.Cpu) []byte {
	head := make([]byte, 32)
	order.PutUint32(head, magic)
	order.PutUint32(head[4:], uint32(cpu))
	return head
}

// THE MACHINE COMES FROM THE BINARY'S OWN HEADER - ADR114 B15. Every format
// names the three machines this program ships for, and anything it cannot read
// as one of them is "" rather than a guess.
func TestTheMachineIsReadFromTheHeader(t *testing.T) {
	for _, c := range []struct {
		name string
		head []byte
		want string
	}{
		{"PE x86", peImage(pe.IMAGE_FILE_MACHINE_I386, 0x80), "x86"},
		{"PE x64", peImage(pe.IMAGE_FILE_MACHINE_AMD64, 0xe8), "x64"},
		{"PE arm64", peImage(pe.IMAGE_FILE_MACHINE_ARM64, 0x80), "arm64"},
		{"PE of another machine", peImage(pe.IMAGE_FILE_MACHINE_ARMNT, 0x80), ""},
		{"PE whose signature is past the window", peImage(pe.IMAGE_FILE_MACHINE_AMD64, headerWindow), ""},
		{"MZ with no PE signature", append([]byte("MZ"), make([]byte, 0x80)...), ""},
		{"MZ too short for its offset", []byte("MZ\x00\x00"), ""},

		{"ELF x64", elfImage(elf.ELFDATA2LSB, binary.LittleEndian, elf.EM_X86_64), "x64"},
		{"ELF x86", elfImage(elf.ELFDATA2LSB, binary.LittleEndian, elf.EM_386), "x86"},
		{"ELF arm64, big endian", elfImage(elf.ELFDATA2MSB, binary.BigEndian, elf.EM_AARCH64), "arm64"},
		{"ELF of another machine", elfImage(elf.ELFDATA2LSB, binary.LittleEndian, elf.EM_RISCV), ""},
		{"ELF with no byte order", elfImage(elf.ELFDATANONE, binary.LittleEndian, elf.EM_X86_64), ""},
		{"ELF cut before its machine", elfImage(elf.ELFDATA2LSB, binary.LittleEndian, elf.EM_X86_64)[:19], ""},

		{"Mach-O arm64", machoImage(binary.LittleEndian, macho.Magic64, macho.CpuArm64), "arm64"},
		{"Mach-O x64", machoImage(binary.LittleEndian, macho.Magic64, macho.CpuAmd64), "x64"},
		{"Mach-O x86, 32-bit", machoImage(binary.LittleEndian, macho.Magic32, macho.Cpu386), "x86"},
		{"Mach-O big endian of another machine", machoImage(binary.BigEndian, macho.Magic32, macho.CpuPpc), ""},
		{"universal Mach-O", machoImage(binary.BigEndian, macho.MagicFat, macho.CpuArm64), ""},

		{"a script", []byte("#!/bin/sh\nexec java \"$@\"\n"), ""},
		{"three bytes", []byte("abc"), ""},
	} {
		head := c.head
		open := func(string) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(head))), nil }
		if got := Architecture(open, "binary"); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// A FILE THAT CANNOT BE READ SAYS NOTHING - the three ways a read ends before a
// header: no file, an empty one, a read that fails.
func TestABinaryThatCannotBeReadHasNoMachine(t *testing.T) {
	missing := func(string) (io.ReadCloser, error) { return nil, errors.New("no such file") }
	empty := func(string) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil }
	failing := func(string) (io.ReadCloser, error) { return io.NopCloser(failingReader{}), nil }
	// A READ THAT FAILS AFTER A WHOLE HEADER IS STILL A FAILED READ - what came
	// before the failure is not taken as the header.
	failingLate := func(string) (io.ReadCloser, error) {
		return io.NopCloser(io.MultiReader(strings.NewReader(string(peImage(pe.IMAGE_FILE_MACHINE_AMD64, 0x80))), failingReader{})), nil
	}
	for name, open := range map[string]func(string) (io.ReadCloser, error){
		"missing": missing, "empty": empty, "failing": failing, "failing after the header": failingLate,
	} {
		if got := Architecture(open, "binary"); got != "" {
			t.Errorf("%s: got %q, want nothing", name, got)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the disk went away") }
