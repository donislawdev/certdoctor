package main

import (
	"errors"
	"os"
	"os/exec"
)

// This file is the one place in the window that starts a process (ADR125 point
// 7). Today it starts one program, the window itself, and the command line it
// is to run (ADR121) is to come here as well, so that the list of what the
// window can start is read in one file. The guard over that list names this
// file and, for each spawn in it, the function its program comes from -
// internal/guard/exec_test.go.

// startAgain starts this executable again with args, waits for it, and answers
// its exit code.
//
// The second process inherits the streams of the first, so whatever started
// this program reads what the window says wherever it is said. Under the
// windows subsystem with nothing redirected those streams are not there, and
// the toolchain skips a handle that is not there rather than failing on it -
// read in go1.27.3, where a missing handle is nought (os.NewFile keeps it,
// syscall.Stdin is what GetStdHandle answered) and syscall/exec_windows.go
// hands the child only handles above nought. That matters because a second
// start that could not run from a double click would be one for the terminal
// only.
//
// The driver variable is handed over as well, so that the renderer in the
// second process reads it however it reads its environment. The second process
// sets it for itself too, and this is the half that does not depend on when
// the C runtime takes its copy.
func startAgain(args []string) (int, error) {
	cmd, err := ourselves(args)
	if err != nil {
		return 0, err
	}
	cmd.Env = append(os.Environ(), softwareDriver+"="+softwareLLVMPipe)
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		// The second process ran and answered. Its code is the answer, and a
		// code other than nought is a refusal it has already put in front of
		// the person, not an error of ours to wrap.
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

// ourselves is this program, with args: by the path the system answers for the
// running process and never through the search path, without a shell, and
// with arguments that are the ones this process was started with plus at most
// one flag of ours. Nothing a person typed chooses what runs.
func ourselves(args []string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd, nil
}
