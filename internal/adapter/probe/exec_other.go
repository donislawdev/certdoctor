//go:build !windows

package probe

import (
	"os/exec"
	"syscall"
)

// isolate starts the child in a process group of its own, and has a run that
// is cancelled end the whole group - ADR114 point 6, decided by the owner.
//
// A WRAPPER IS A PARENT, NOT THE PROGRAM. A shim on PATH - pyenv's, or any
// script that starts the real runtime without exec - leaves the runtime as a
// child of what this program started, and exec.CommandContext kills only the
// process it started itself. Without this the runtime ran on after our budget
// was spent, holding memory and handles nobody was going to collect.
//
// THE GROUP IS ENDED ONLY ON CANCEL, while the leader is still unreaped, so its
// id cannot yet belong to anybody else. Ending it after Wait would aim a kill at
// an id the system may have handed out again.
func isolate(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}
