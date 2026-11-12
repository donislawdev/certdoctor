//go:build (linux && (amd64 || arm64)) || darwin

package main

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// THIS FILE IS ON unsafeAllowlist IN internal/guard/unsafe_test.go, the owner's
// decision with ADR143, and it is a file of its own for that reason: the entry
// takes that guard off the whole file. It needs unsafe for one thing - handing
// ioctl the address of a termios this program owns, to read the terminal's
// settings into it and to set them from it. It reads no memory anybody else
// allocated.
//
// THROUGH syscall AND NOT golang.org/x/sys/unix, which would make the command
// line link a module it does not link today - its notes, its SBOM, guard 32 -
// for two requests (ADR143, rejected there). On macOS syscall.Syscall is a trap
// into the kernel and not a call into libSystem, which Apple does not promise
// to keep working - it worked on macOS 27.2.1, measured 2026-11-12 with
// internal_tools/wklejanie, and a trap that stops working fails the first
// request, so the paste is read in the line mode rather than not at all.
//
// BUILT FOR THE TARGETS OF THE RELEASE ALONE (ADR116): the Linux requests in
// paste_linux.go are those of x86 and arm64, and another architecture would
// read a different number as a different request. Anything else keeps the
// line mode, paste_other.go.

// liveKeys switches r to hand over every key as it is pressed, without
// showing it, when r is a terminal. Anything else - the null device, a
// character device that is not a terminal - is answered false and read in the
// line mode, as before.
func liveKeys(r io.Reader) (keyTerminal, bool) {
	f, ok := r.(*os.File)
	if !ok {
		return nil, false
	}
	// Fd puts the descriptor in blocking mode, which the moment of quiet in
	// restore relies on: a terminal read without blocking answers at once
	// rather than after a tenth of a second.
	fd := f.Fd()
	var saved syscall.Termios
	if termios(fd, getTermios, &saved) != nil {
		return nil, false
	}
	keys := saved
	keys.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.ISIG | syscall.IEXTEN
	keys.Cc[syscall.VMIN], keys.Cc[syscall.VTIME] = 1, 0
	if termios(fd, setTermios, &keys) != nil {
		return nil, false
	}
	return &rawTerminal{file: f, fd: fd, saved: saved, keys: keys}, true
}

// rawTerminal is a terminal switched by liveKeys, with what it was before.
type rawTerminal struct {
	file        *os.File
	fd          uintptr
	saved, keys syscall.Termios
}

func (t *rawTerminal) Read(p []byte) (int, error) { return t.file.Read(p) }

// restore waits until nothing arrives for a tenth of a second, then sets the
// terminal back and drops what is queued in the same request.
//
// THE WAIT IS WHY THE REST OF A PASTE DOES NOT RUN IN THE SHELL. Dropping the
// queue alone drops what is already in it - and a terminal writes a long paste
// no faster than the program reads it, so its last lines are still on the way
// when Enter ends the first one. The wait is the terminal's own: VTIME with
// VMIN at zero makes a read answer empty after a tenth of a second without a
// byte, so no timer and no second goroutine is needed.
func (t *rawTerminal) restore() error {
	quiet := t.keys
	quiet.Cc[syscall.VMIN], quiet.Cc[syscall.VTIME] = 0, 1
	if termios(t.fd, setTermios, &quiet) == nil {
		var dropped [4096]byte
		for {
			if n, err := t.file.Read(dropped[:]); n == 0 || err != nil {
				break
			}
		}
	}
	return termios(t.fd, setTermiosFlushed, &t.saved)
}

// interrupt sends SIGINT to every process of this one's group, which is what
// the terminal does with Ctrl+C in its line mode - a script running this
// command stops as it would have. This process is in the group as well, and
// takes its own interrupt the way main.go takes every one.
func (t *rawTerminal) interrupt() { _ = syscall.Kill(0, syscall.SIGINT) }

// termios hands ioctl the address of t, to read the terminal's settings into t
// or to set them from it.
func termios(fd, request uintptr, t *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(unsafe.Pointer(t))); errno != 0 {
		return errno
	}
	return nil
}
