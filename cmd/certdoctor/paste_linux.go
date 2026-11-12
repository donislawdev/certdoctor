//go:build linux && (amd64 || arm64)

package main

// The terminal requests of Linux, which the syscall package does not carry.
// x86 and arm64 both take them from include/uapi/asm-generic/ioctls.h in the
// kernel's sources - and paste_unix.go is built for those two alone, since
// another architecture numbers them differently.
const (
	getTermios        = 0x5401 // TCGETS
	setTermios        = 0x5402 // TCSETS
	setTermiosFlushed = 0x5404 // TCSETSF: set once output is written, with the input queue dropped
)
