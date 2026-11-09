//go:build !windows

package main

import (
	"os"
	"syscall"
)

// commandLineFile is the command line's file beside the window.
const commandLineFile = "certdoctor"

// withoutConsole has nothing to set outside Windows, where a child shows no
// window of its own.
func withoutConsole() *syscall.SysProcAttr { return nil }

// askToStop asks a run to stop the way a person does at a terminal: with an
// interrupt, which the command line answers by ending the run and its own
// children (cmd/certdoctor/interrupt.go, ADR114). It is killed when it has not
// ended stopWait later.
func askToStop(p *os.Process) error { return p.Signal(os.Interrupt) }
