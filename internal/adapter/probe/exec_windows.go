//go:build windows

package probe

import (
	"os"
	"syscall"
)

// ownGroup leaves the child as exec starts it. Ending a wrapper's own children
// on Windows needs a job object, which needs unsafe - OBS197, a question for
// the owner with a measurement behind it rather than a guess.
func ownGroup() *syscall.SysProcAttr { return nil }

// endGroup ends the child alone, which is what exec does when nobody sets
// Cancel.
func endGroup(leader *os.Process) error { return leader.Kill() }
