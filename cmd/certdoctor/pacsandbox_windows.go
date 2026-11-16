//go:build windows

package main

import "syscall"

// createNoWindow is CREATE_NO_WINDOW from the Win32 process creation flags:
// "The process is a console application that is being run without a console
// window" - learn.microsoft.com, Process Creation Flags, read 2026-11-16.
const createNoWindow = 0x08000000

// sandboxProcess starts the sandbox process without a console. Its standard
// streams are pipes, so it needs none, and a console it got without asking
// would be a window flashing up when the window starts this program.
func sandboxProcess() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNoWindow}
}
