//go:build windows

package probe

import (
	"os"
	"syscall"
)

// ownGroup leaves the child as exec starts it. Ending a wrapper's own children
// on Windows needs a job object, which needs unsafe - OBS197. Measured
// 2026-10-27: Scoop's shim ends its child itself and Chocolatey's leaves it
// running, so a cancelled run can leave one process finishing our script. The
// job object waits for the PAC evaluation in a child process after 0.1.0,
// decided by the owner, so the mechanism is built once.
func ownGroup() *syscall.SysProcAttr { return nil }

// endGroup ends the child alone, which is what exec does when nobody sets
// Cancel.
func endGroup(leader *os.Process) error { return leader.Kill() }
