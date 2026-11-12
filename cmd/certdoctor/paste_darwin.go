//go:build darwin

package main

import "syscall"

// The terminal requests of macOS, as the syscall package carries them.
const (
	getTermios        = syscall.TIOCGETA
	setTermios        = syscall.TIOCSETA
	setTermiosFlushed = syscall.TIOCSETAF // set once output is written, with the input queue dropped
)
