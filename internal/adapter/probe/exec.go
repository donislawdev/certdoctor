// Package probe runs the questions L5 has to ask other people's tooling.
//
// THIS FILE IS THE ONLY PLACE IN THIS PROGRAM THAT STARTS ANOTHER PROGRAM, and
// that is enforced rather than intended: exec_test.go in internal/guard refuses
// an import of os/exec anywhere else - ADR49. The reason is the one checkWrites
// gives about its own blind spot: somebody else's process can write, which is
// the single thing inviolable rule 14 forbids outright.
//
// WHY A PROCESS AT ALL, since it is the widest thing this program does. Two of
// the three L5 probes have no other way to get their answer, and both were
// measured on 2026-08-18 rather than assumed. A Java trust store is PKCS12 in
// the JDKs on this machine and JKS in the JRE, so reading it directly means two
// parsers or a dependency. curl is worse: mingw64\bin ships libcurl-4.dll AND
// libcurl-openssl-4.dll side by side, so the TLS backend read off the
// filesystem would be a guess - and a wrong guess there generates a fix command
// that does nothing while a person waits for it to work.
package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
)

// OutputLimit caps how much of a child's output is kept, per stream.
//
// It is a defence rather than a tuning knob: keytool -list on a store with a
// few hundred anchors is tens of kilobytes, and anything approaching this cap
// is a program behaving in a way we did not predict. Truncation is REPORTED
// rather than silent - a run that did less than it promised has to say so.
const OutputLimit = 1 << 20

// Output is what one program said, and how it ended.
//
// ExitCode is the number, never the wording. Recognising somebody else's result
// by the text of its message is what inviolable rule 19 forbids, because that
// text is translated on a machine whose language we do not choose.
type Output struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

// ErrNotAbsolute is returned for an executable given as a bare name.
//
// A NAME IS RESOLVED BY SOMEBODY ELSE'S PATH, which means the thing that runs is
// chosen by configuration we did not read and cannot show in the report. The
// probes find their binaries on disk first and hand over what they found -
// measured, this machine has two curl.exe on PATH and six Java installs, so
// "the one PATH picks" is never the whole answer anyway.
var ErrNotAbsolute = errors.New("an executable has to be an absolute path, not a name for somebody else's PATH to resolve")

// Runner is how a probe asks for a program to be run.
//
// IT IS A PORT AND NOT A DIRECT CALL, so a probe can be tested without starting
// anything - the same reason file.Source exists. Run below satisfies it, and is
// the only implementation that actually starts a process.
type Runner func(ctx context.Context, executable string, args ...string) (Output, error)

// Run starts one program, waits for it, and returns what it said.
//
// FOUR NARROWING RULES LIVE HERE AND NOWHERE ELSE - ADR49. The executable is an
// absolute path (refused otherwise, above). No shell is involved, because
// exec.CommandContext takes an argument vector rather than a command line, so
// there is nothing for a metacharacter to mean. NOTHING IS WRITTEN TO THE
// CHILD'S INPUT: Stdin is left nil, so a program that decides to prompt gets
// end-of-file and exits instead of hanging this run forever. Output is capped.
//
// THE ENVIRONMENT IS INHERITED, DELIBERATELY. A probe exists to report what
// happens ON THIS MACHINE, and a cleaned environment would answer a question
// nobody asked - if JAVA_TOOL_OPTIONS changes what keytool does here, that is a
// fact about this machine and belongs in the report rather than being tidied
// away before it can be seen.
//
// A NON-ZERO EXIT IS NOT AN ERROR. It is an answer, and often the interesting
// one, so it comes back in Output.ExitCode. The error return is for the cases
// where the question could not be put at all - the program is missing, the path
// is a directory, the run was cancelled.
func Run(ctx context.Context, executable string, args ...string) (Output, error) {
	if !filepath.IsAbs(executable) {
		return Output{}, fmt.Errorf("%w: %q", ErrNotAbsolute, executable)
	}

	command := exec.CommandContext(ctx, executable, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.Stdin = nil

	err := command.Run()

	out := Output{
		Stdout: capped(&stdout),
		Stderr: capped(&stderr),
	}
	out.Truncated = stdout.Len() > OutputLimit || stderr.Len() > OutputLimit

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return out, nil
	case errors.As(err, &exitErr):
		// The program ran and said no. That is an answer.
		out.ExitCode = exitErr.ExitCode()
		return out, nil
	default:
		// The question could not be put: no such file, not executable, cancelled.
		return Output{}, err
	}
}

// capped returns at most OutputLimit bytes of a buffer.
func capped(b *bytes.Buffer) string {
	if b.Len() <= OutputLimit {
		return b.String()
	}
	return string(b.Bytes()[:OutputLimit])
}
