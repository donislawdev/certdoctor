//go:build linux && (amd64 || arm64)

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// openPseudoTerminal opens a pseudo-terminal: the side a terminal emulator
// writes a paste into, and the side a program reads it from.
func openPseudoTerminal(t *testing.T) (emulator, program *os.File) {
	t.Helper()
	emulator, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("no pseudo-terminal could be opened, so nothing here was measured: %v", err)
	}
	t.Cleanup(func() { _ = emulator.Close() })
	var unlock, number int32
	for _, request := range []struct {
		code  uintptr
		value *int32
	}{{syscall.TIOCSPTLCK, &unlock}, {syscall.TIOCGPTN, &number}} {
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, emulator.Fd(), request.code,
			uintptr(unsafe.Pointer(request.value))); errno != 0 {
			t.Fatalf("ioctl %#x on the pseudo-terminal: %v", request.code, errno)
		}
	}
	program, err = os.OpenFile("/dev/pts/"+strconv.Itoa(int(number)), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = program.Close() })
	return emulator, program
}

func settingsOf(t *testing.T, f *os.File) syscall.Termios {
	t.Helper()
	var s syscall.Termios
	if err := termios(f.Fd(), getTermios, &s); err != nil {
		t.Fatalf("reading the terminal's settings: %v", err)
	}
	return s
}

// The line mode of this very terminal cuts at 4095 (OBS229). A paste of
// 10000 arrives whole, the terminal is set back exactly as it was, and the
// second line of the paste is gone rather than waiting for the shell.
//
// THE SECOND LINE IS LONGER THAN THE TERMINAL'S QUEUE OF 4096, so its end is
// still being written when Enter ends the first: dropping the queue alone
// would leave that end for the shell, and only the moment of quiet in restore
// takes it. Without that wait this test reads the end of the paste instead of
// "next" - tried once by hand 2026-11-12.
func TestALongPasteReachesWholeThroughARealTerminal(t *testing.T) {
	emulator, program := openPseudoTerminal(t)
	before := settingsOf(t, program)
	keys, switched := liveKeys(program)
	if !switched {
		t.Fatal("a pseudo-terminal was not switched")
	}
	during := settingsOf(t, program)
	if during.Lflag&(syscall.ICANON|syscall.ECHO|syscall.ISIG|syscall.IEXTEN) != 0 || during.Cc[syscall.VMIN] != 1 {
		t.Errorf("switched to local flags %#x and VMIN %d", during.Lflag, during.Cc[syscall.VMIN])
	}

	token := strings.Repeat("x", 10_000)
	written := make(chan error, 1)
	go func() {
		_, err := emulator.Write([]byte(token + "\nrm -rf " + strings.Repeat("y", 20_000) + "\n"))
		written <- err
	}()
	typed, err := editLine(bufio.NewReader(keys), 256<<10)
	if err != nil || string(typed.text) != token {
		t.Errorf("%d of 10000 characters arrived (%v)", len(typed.text), err)
	}
	if err := keys.restore(); err != nil {
		t.Errorf("setting the terminal back: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("writing the paste: %v", err)
	}
	if after := settingsOf(t, program); after != before {
		t.Errorf("the terminal was set back to %+v, and was %+v", after, before)
	}

	if _, err := emulator.Write([]byte("next\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(program).ReadString('\n'); line != "next\n" {
		t.Errorf("the shell would have read %q next (%v), not the line typed after the paste", line, err)
	}
}
