//go:build windows

package main

import (
	"os"
	"syscall"
)

// commandLineFile is the command line's file beside the window.
const commandLineFile = "certdoctor.exe"

// createNoWindow runs a console program without a console window - "The
// process is a console application that is being run without a console
// window", 0x08000000 (https://learn.microsoft.com/windows/win32/procthread/process-creation-flags,
// read 2026-11-09). Measured in S29 on this machine 2026-11-03: no window for
// the child and none for a console program the child starts.
const createNoWindow = 0x08000000

// withoutConsole is how the command line is started without a window of its
// own.
func withoutConsole() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNoWindow}
}

// askToStop ends a run on Windows, which has no interrupt to send a process
// without a console to share with it. Its children finish the fixed script
// each one runs and end on their own (OBS197); a job object that ends them
// with it is work after the first release.
func askToStop(p *os.Process) error { return p.Kill() }
