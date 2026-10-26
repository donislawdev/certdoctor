//go:build !windows

package probe

import (
	"os"
	"syscall"
)

// ownGroup starts the child in a process group of its own, and endGroup ends
// the whole group when a run is cancelled - ADR114 point 6, decided by the
// owner. start applies both, so exec.go stays the one file able to start a
// program, as the exec guard in internal/guard requires.
//
// A WRAPPER IS A PARENT, NOT THE PROGRAM. A shim on PATH - pyenv's, or any
// script that starts the real runtime without exec - leaves the runtime as a
// child of what this program started, and exec.CommandContext kills only the
// process it started itself. Without this the runtime ran on after our budget
// was spent, holding memory and handles nobody was going to collect.
func ownGroup() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

// endGroup ends every process in the leader's group.
//
// IT RUNS ONLY ON CANCEL, while the leader is still unreaped, so its id cannot
// yet belong to anybody else. Ending the group after Wait would aim a kill at
// an id the system may have handed out again.
func endGroup(leader *os.Process) error { return syscall.Kill(-leader.Pid, syscall.SIGKILL) }
