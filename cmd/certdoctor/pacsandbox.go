package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/donislawdev/certdoctor/internal/adapter/pac"
)

// pacSandboxArgument is the one argument that makes this program the process a
// PAC file runs in - ADR150. It is not for people: it is never listed in --help,
// and the process it starts reads a request this program writes. Somebody
// typing it gets a process that waits for that request and refuses whatever
// else arrives - the same sandbox --pac-url already runs a file in, with no
// network of its own.
const pacSandboxArgument = "--pac-sandbox"

// pacStartAllowance is the time on top of the evaluation budget a sandbox
// process gets to start and to say its result, before it is ended.
//
// AN ASSESSMENT ON A MEASUREMENT. On an idle machine a start takes milliseconds -
// probe S33, 2026-11-16, twenty starts each: a median of 9.6 ms on Windows,
// 7.3 ms on Linux and 4.4 ms on macOS, and 23 ms at worst. The allowance is for
// a busy machine, where the whole process waits for the processor, not only its
// start: on 2026-11-24, with every core of sixteen kept busy on Windows, an
// honest file answered in a median of 991 ms, 2.9 s at the 90th percentile and
// 4.4 s at the 99th, over two hundred runs. With this allowance 7 of them would
// have missed the window, with half a second 88. So a machine that busy can
// still see time_limit, as the honest word for a file this program could not
// finish in time. What it costs is said plainly: a file stuck in native code -
// which the stopwatch cannot interrupt and only the end of its process stops -
// runs this much past pacEvaluationBudget, still well inside the layer's own
// deadline.
const pacStartAllowance = 3 * time.Second

// pacWaitDelay is how long the end of a sandbox process may wait for its
// standard error to close. Nothing it starts holds the pipe, so this is a bound
// and not a wait.
const pacWaitDelay = time.Second

// isPACSandbox says whether this process was started to run a PAC file. Only
// the exact argument alone counts, so no command line a person types for a
// diagnosis can arrive here by accident.
func isPACSandbox(args []string) bool {
	return len(args) == 2 && args[1] == pacSandboxArgument
}

// startPACSandbox starts this program again as the process a PAC file runs in.
//
// BY THE PATH os.Executable ANSWERS AND NEVER THE SEARCH PATH, the rule
// commandLine in the window keeps for the same reason: a file of the same name
// earlier in PATH is somebody else's program. This file is on execAllowlist and
// held to this one spawn by spawnsAllowed.
//
// THE PROCESS GETS NO CONSOLE OF ITS OWN ON WINDOWS - sandboxProcess. When the
// window starts this program without a console, a console program it starts
// would otherwise open a window of its own for every PAC file.
func startPACSandbox(ctx context.Context, stderr io.Writer) (pac.Child, error) {
	exe, err := os.Executable()
	if err != nil {
		return pac.Child{}, err
	}
	// This binary itself with one fixed switch (ADR150).
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, exe, pacSandboxArgument)
	cmd.SysProcAttr = sandboxProcess()
	cmd.Stderr = stderr
	cmd.WaitDelay = pacWaitDelay
	in, err := cmd.StdinPipe()
	if err != nil {
		return pac.Child{}, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return pac.Child{}, err
	}
	if err := cmd.Start(); err != nil {
		return pac.Child{}, err
	}
	return pac.Child{In: in, Out: out, Wait: func() int {
		_ = cmd.Wait()
		return cmd.ProcessState.ExitCode()
	}}, nil
}

// servePACSandbox is the whole life of a sandbox process.
func servePACSandbox() int {
	return pac.Serve(os.Stdin, os.Stdout, toolVersion, os.Exit)
}
