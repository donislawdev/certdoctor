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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

// OutputLimit caps how much of a child's output is kept, per stream.
//
// It is a defence rather than a tuning knob: keytool -list on a store with a
// few hundred anchors is tens of kilobytes, and anything approaching this cap
// is a program behaving in a way we did not predict. Truncation is REPORTED
// rather than silent - a run that did less than it promised has to say so.
const OutputLimit = 1 << 20

// waitDelay bounds how long Run keeps waiting for OUTPUT once the child itself
// is gone. It belongs in the same paragraph as OutputLimit and for the same
// reason: both are places where somebody else decides when this program stops.
//
// WAITING FOR THE PIPES IS NOT THE SAME EVENT AS WAITING FOR THE CHILD. os/exec
// hands the child a pipe rather than a file, so a grandchild that inherited the
// descriptor holds it open long after its parent has been killed, and Wait sits
// on end-of-file that has not arrived. Measured 2026-09-03 on Windows and in
// golang:1.27-alpine, with a 300 ms budget and a grandchild alive for 30 s: Run
// came back after 30.02 s and 30.03 s - AND CAME BACK WITH NO ERROR, so a
// hundredfold overrun of the budget looked exactly like an answer. With this
// delay set the same measurement is 2.016 s and 2.004 s, and it comes back as an
// error that says whose limit stopped it.
//
// THE NUMBER IS A BOUND AND NOT A COST. It starts running only once the context
// is done or the child has already exited, so a probe that answers normally
// never pays it: the same measurement with a child that replies at once took
// 9 ms and 3 ms with the delay set. Two seconds is far longer than draining a
// pipe nobody is writing to, and far shorter than any budget a person sets.
const waitDelay = 2 * time.Second

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
// end-of-file and exits instead of hanging this run forever. Output is capped
// AS IT ARRIVES, per stream, by cappedWriter - not trimmed once the child has
// finished, which is what this sentence used to describe.
//
// THE ENVIRONMENT IS INHERITED, DELIBERATELY. A probe exists to report what
// happens ON THIS MACHINE, and a cleaned environment would answer a question
// nobody asked - if JAVA_TOOL_OPTIONS changes what keytool does here, that is a
// fact about this machine and belongs in the report rather than being tidied
// away before it can be seen. ONE PROBE NARROWS IT, AND ONLY BY TAKING AWAY -
// Without, below, which is ADR111's exception and not a second rule.
//
// A NON-ZERO EXIT IS NOT AN ERROR. It is an answer, and often the interesting
// one, so it comes back in Output.ExitCode. The error return is for the cases
// where the question could not be put at all - the program is missing, the path
// is a directory, the run was cancelled.
//
// AND OUR OWN BUDGET IS NOT AN ANSWER EITHER, which is the half that used to be
// missing and the half a reader of the report actually met. See the context
// check below.
func Run(ctx context.Context, executable string, args ...string) (Output, error) {
	return start(ctx, nil, executable, args...)
}

// Without returns a Runner that starts a program with this process's
// environment LESS the variables named, and with nothing added.
//
// THE FIFTH NARROWING RULE - ADR111 part 2, decided by the owner 2026-10-20:
// a child may LOSE variables and never gain one. It exists for node, where an
// inherited NODE_OPTIONS can carry --require, which would run somebody else's
// code inside the process this program started, and NODE_V8_COVERAGE writes a
// file - inviolable rules 16 and 14. Run above keeps inheriting everything, and
// that stays the rule for every other probe.
//
// NAMES ARE COMPARED THE WAY THE PLATFORM COMPARES THEM. Windows does not tell
// Node_Options from NODE_OPTIONS, so neither does this, and a spelling that
// slipped past would hand the child the variable this exists to withhold.
func Without(names ...string) Runner {
	withheld := slices.Clone(names)
	return func(ctx context.Context, executable string, args ...string) (Output, error) {
		return start(ctx, without(os.Environ(), withheld, runtime.GOOS == "windows"), executable, args...)
	}
}

// without is environ less every entry whose name is withheld. It only ever
// drops entries - the rule Without states - and keeps the rest in their order.
func without(environ, withheld []string, foldCase bool) []string {
	kept := make([]string, 0, len(environ))
	for _, entry := range environ {
		name := nameOf(entry)
		if !slices.ContainsFunc(withheld, func(w string) bool { return w == name || foldCase && strings.EqualFold(w, name) }) {
			kept = append(kept, entry)
		}
	}
	return kept
}

// nameOf is the name of one NAME=value entry. A NAME MAY START WITH "=" ON
// WINDOWS, where the current directory of each drive travels as an entry like
// "=C:=C:\work", so the separator is looked for after the first character.
func nameOf(entry string) string {
	if entry == "" {
		return ""
	}
	name, _, _ := strings.Cut(entry[1:], "=")
	return entry[:1] + name
}

// start runs one program with env as its environment, or with this process's
// own when env is nil - the rules are on Run.
func start(ctx context.Context, env []string, executable string, args ...string) (Output, error) {
	if !filepath.IsAbs(executable) {
		return Output{}, fmt.Errorf("%w: %q", ErrNotAbsolute, executable)
	}

	command := exec.CommandContext(ctx, executable, args...)
	command.Env = env
	var stdout, stderr cappedWriter
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.Stdin = nil
	command.WaitDelay = waitDelay

	err := command.Run()

	out := Output{
		Stdout: string(stdout.kept),
		Stderr: string(stderr.kept),
	}
	out.Truncated = stdout.over || stderr.over

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return out, nil
	case errors.Is(err, exec.ErrWaitDelay):
		// THE CHILD IS GONE AND ITS OUTPUT IS NOT. Somebody it started still
		// holds the pipe, so what we have is whatever arrived before waitDelay
		// ran out - which is a fact about OUR limit and has to say so rather
		// than travel as a complete answer.
		return Output{}, fmt.Errorf(
			"%s left its output open after it was gone, and this program waited %v for it: %w",
			executable, waitDelay, err)
	case errors.As(err, &exitErr):
		// OUR OWN BUDGET IS NEVER SOMEBODY ELSE'S ANSWER - #1 of the external
		// review, and the recipe it proposed does not work here. A child killed
		// because this program's deadline expired arrives as an ExitError too,
		// and what it carries cannot be told apart from a refusal: measured
		// 2026-09-03, Windows reports ExitCode 1 with ProcessState.Exited() TRUE
		// while Linux reports -1 with Exited() false, and errors.Is(err,
		// context.DeadlineExceeded) is false on both. So a gate on Exited()
		// would never fire on the owner's machine, and the exit code 1 it would
		// have let through is indistinguishable from "the program ran and said
		// no". THE CONTEXT IS THE ONLY DISCRIMINATOR THAT HOLDS ON BOTH.
		//
		// Left visible to a reader: this said "keytool exited with 1" about a
		// keytool that answered nothing, because certdoctor stopped it.
		//
		// THE err == nil BRANCH ABOVE IS DELIBERATELY NOT GATED THE SAME WAY. A
		// child that finished and exited zero answered the question, and
		// discarding that because the clock ran out a moment later would throw
		// away evidence already in hand.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Output{}, fmt.Errorf("%s was stopped before it answered: %w", executable, ctxErr)
		}
		// The program ran and said no. That is an answer.
		out.ExitCode = exitErr.ExitCode()
		return out, nil
	default:
		// The question could not be put: no such file, not executable, cancelled.
		return Output{}, err
	}
}

// cappedWriter keeps at most OutputLimit bytes and remembers that more arrived.
//
// IT REPLACED A bytes.Buffer READ AFTER THE FACT, AND THE DIFFERENCE IS THE
// ONLY ONE THAT MATTERS HERE: the buffer held everything the child produced and
// was trimmed once the child had finished, so the cap described the report and
// not the memory. This is the single place in this program where the AMOUNT of
// data is decided by somebody else - keytool -list -rfc over a store that has
// been damaged or swapped answers with as much as it likes - and the sentence
// at the top of Run promised a cap that did not exist until the run was over.
//
// A FULL COUNT IS RETURNED EVEN WHEN NOTHING IS KEPT, DELIBERATELY. os/exec
// copies the pipe into this writer and treats a short count as io.ErrShortWrite,
// which would turn a talkative probe into a failed one - "the question could not
// be put" - when the truth is that it answered at length. Dropping the excess is
// the intended behaviour, so it is reported as written.
type cappedWriter struct {
	kept []byte
	// over says the child produced more than was kept, which is what Truncated
	// reports. It is set at the moment the excess arrives rather than deduced
	// from a length afterwards, because after the change there is no length to
	// deduce it from.
	over bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	room := OutputLimit - len(w.kept)
	switch {
	case room <= 0:
		w.over = true
	case len(p) > room:
		w.kept = append(w.kept, p[:room]...)
		w.over = true
	default:
		w.kept = append(w.kept, p...)
	}
	return len(p), nil
}
