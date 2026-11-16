//go:build !windows

package main

import "syscall"

// sandboxProcess leaves the sandbox process in this program's own process
// group, so an interrupt typed at the terminal reaches both, and the evaluation
// stops with the run.
func sandboxProcess() *syscall.SysProcAttr { return nil }
