package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
)

// This file is the one place in the window that starts a process (ADR125 point
// 7). It starts two programs: the window itself, for the software renderer,
// and the command line it runs a diagnosis with (ADR121) - so the list of what
// the window can start is read in one file. The guard over that list names
// this file and, for each spawn in it, the function its program comes from -
// spawnsAllowed in internal/guard/spawns_test.go.

// commandLine is the command line that came with the window: certdoctor in
// the window's own folder, by the path the system answers for the running
// process and never through the search path (ADR121 point 1) - a certdoctor
// found on the search path is somebody else's program under our name. On macOS
// that folder is Contents/MacOS inside the bundle, where the release is to put
// both.
func commandLine() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), commandLineFile), nil
}

// stopWait is how long a run asked to stop is given before it is killed, and
// how long the window waits for the streams of a run that ended to close. A
// program the command line started and that kept a copy of its streams would
// otherwise hold the window's answer until that program ended too.
const stopWait = 3 * time.Second

// commandLinePort runs the command line beside the window, as a child process
// (ADR121 point 2).
type commandLinePort struct{}

// Run starts certdoctor beside the window with args, waits for it, and answers
// what it left: what it wrote, kept up to the window's limits, what it
// printed, its exit code, and why it did not start when it did not.
//
// No window of its own on Windows - certdoctor is a console program, and
// started from a window it would flash one (S29, measured 2026-11-03: with the
// flag neither it nor a console program it starts shows one). Its standard
// input is nothing, its environment is the window's - the variables L0 reads
// are the ones the person's programs see - and a run whose context ends is
// asked to stop the way that system asks: an interrupt on Linux and macOS,
// which the command line answers by ending its own children (ADR114), and on
// Windows the end of the process, which its children outlive only until the
// fixed script each one runs is done (OBS197).
func (commandLinePort) Run(ctx context.Context, args []string) flow.Process {
	program, err := commandLine()
	if err != nil {
		return flow.Process{Program: commandLineFile, StartFailed: err}
	}
	out, printed := flow.NewCapped(flow.MaxDocument), flow.NewCapped(flow.MaxPrinted)
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdout, cmd.Stderr = out, printed
	cmd.SysProcAttr = withoutConsole()
	cmd.Cancel = func() error { return askToStop(cmd.Process) }
	cmd.WaitDelay = stopWait
	err = cmd.Run()
	p := flow.Process{
		Program: program,
		Out:     out.Bytes(), OutTooLong: out.Over(),
		Printed: printed.Bytes(), PrintedTooLong: printed.Over(),
		Stopped: ctx.Err(),
	}
	if cmd.ProcessState == nil {
		// It never ran. Nothing there and something the system would not start
		// are told apart, because the advice differs - put the program back,
		// against look at what is there.
		p.Missing = errors.Is(err, fs.ErrNotExist)
		if !p.Missing {
			p.StartFailed = err
		}
		return p
	}
	p.Code = cmd.ProcessState.ExitCode()
	return p
}

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
