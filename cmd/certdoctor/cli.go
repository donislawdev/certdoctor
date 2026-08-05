package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	certdoctor "github.com/donislawdev/certdoctor"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/app/run"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

const (
	toolName    = certdoctor.Name
	toolVersion = certdoctor.Version
)

// environment is everything outside this process that a run may look at,
// gathered into one value that tests supply themselves.
//
// It exists so that the whole command line can be exercised without a terminal,
// without a clock and above all without a file system. The fuzz target over the
// command line depends on that last one: fuzzing a program that can create
// files is fuzzing a program that will eventually create a surprising one.
type environment struct {
	stdout io.Writer
	stderr io.Writer
	// capability answers what the report destination can render, given whether
	// colour was refused on the command line.
	capability func(noColorRequested bool) render.Capability
	now        func() time.Time
	platform   report.Platform
	privilege  report.PrivilegeLevel
	// lookupEnv is how L0 sees this machine's environment. It is a seam for the
	// same reason the clock is: a test reading the real environment would pass
	// or fail depending on whose machine it ran on, and the one variable that
	// would change its mind is exactly the sort this layer reports.
	lookupEnv func(name string) (string, bool)
	// writeFile puts a finished report at a path the user named. It is the only
	// way this package can reach the file system.
	writeFile func(path string, data []byte) error
}

// execute runs one command line from beginning to end and returns the code the
// process ends with.
//
// STANDARD OUTPUT IS WRITTEN ONCE, AT THE VERY END, OR NOT AT ALL. Every path
// that does not produce a complete report returns before touching it. A script
// that redirected standard output into a file gets an empty file rather than
// half a report, because half a report looks exactly like a whole one to
// whatever reads it next.
func execute(ctx context.Context, args []string, env environment) exitcode.Code {
	o, parseFault := parse(args)
	if parseFault != nil {
		return complain(env, parseFault)
	}
	if code, handled := answerMetaSwitch(o, env); handled {
		return code
	}
	return diagnose(ctx, o, env)
}

// diagnose is the path that produces a report: work out what to look at, walk
// the layers, check the result against its own rules, render it, deliver it.
func diagnose(ctx context.Context, o *options, env environment) exitcode.Code {
	shown, redaction, targetFault := readTarget(o)
	if targetFault != nil {
		return complain(env, targetFault)
	}

	finished, walkFault := walk(ctx, o, env, shown, redaction)
	if walkFault != nil {
		return complain(env, walkFault)
	}

	document, renderFault := renderReport(o, env, finished)
	if renderFault != nil {
		return complain(env, renderFault)
	}
	if deliverFault := deliver(o, env, document); deliverFault != nil {
		return complain(env, deliverFault)
	}
	return finished.Verdict.ExitCode
}

// walk runs the layers and hands back a report that has already been checked
// against its own invariants.
//
// The check happens here rather than at the point of printing, so that there is
// no arrangement of this file in which an unchecked report reaches a renderer. A
// verdict that disagrees with the rows beneath it is an internal failure, never
// something to print and let the reader sort out.
func walk(ctx context.Context, o *options, env environment, shown targetReduction, redaction *redact.Redaction) (report.Report, *fault) {
	finished, err := run.Execute(ctx, run.Options{
		Tool:        report.Tool{Name: toolName, Version: toolVersion},
		Target:      shown.target,
		Platform:    env.platform,
		Privilege:   env.privilege,
		Redaction:   redaction,
		Budget:      budget(o.timeout),
		LayerBudget: budget(o.probeTimeout),
		Now:         env.now,
		Layers:      run.Wire(env.lookupEnv),
		Notes:       pendingNotes(shown, env.privilege),
	})
	if err != nil {
		if ctx.Err() != nil {
			return report.Report{}, &fault{exitcode.Interrupted, "interrupted before the run finished"}
		}
		return report.Report{}, &fault{exitcode.Runtime, err.Error()}
	}
	if err := report.Validate(finished); err != nil {
		return report.Report{}, &fault{exitcode.Runtime,
			fmt.Sprintf("the assembled report failed its own checks and was not printed:\n%v", err)}
	}
	return finished, nil
}

// answerMetaSwitch handles the switches that describe the tool rather than a
// machine. Each of them is a complete answer, so each writes to standard output
// and ends successfully.
func answerMetaSwitch(o *options, env environment) (exitcode.Code, bool) {
	switch {
	case o.showHelp:
		fmt.Fprint(env.stdout, helpText())
	case o.showVersion:
		fmt.Fprint(env.stdout, versionText())
	case o.showLicense:
		fmt.Fprint(env.stdout, certdoctor.License)
	default:
		return exitcode.OK, false
	}
	return exitcode.OK, true
}

// complain writes the reason to the log channel and returns its code. It never
// touches standard output.
func complain(env environment, f *fault) exitcode.Code {
	fmt.Fprintf(env.stderr, "%s: %s\n", toolName, f.message)
	return f.code
}

// targetReduction records what the report shows as the target and whether
// anything was taken out of it.
type targetReduction struct {
	target string
	// removed says something was dropped, so the report can say so rather than
	// present a shortened URL as if it were the whole one.
	removed bool
}

// readTarget validates the URL, masks it, and hands back the redaction the whole
// run will use.
//
// THE TARGET IS MASKED BY POSITION, NOT BY NAME, and it is the only thing in
// this program that is. Everything else arrives from the machine, where a value
// that looks ordinary usually is. This one is typed by a person under time
// pressure and can be a secret in three places at once: user info, a token in
// the query, a session identifier in the path. There is no name to ask about, so
// the rule is positional - user info replaced, every query VALUE replaced with
// its name kept, the whole path reduced to one marker, the fragment dropped
// without one because it never reaches a server.
//
// It used to be reduced to its origin instead, with the report saying so, for
// the length of time between the entry point existing and the masking function
// being wired to it. That is over: the origin was strictly narrower than this,
// so the change can only show more.
//
// The redaction is built here because this is where the mode is known, and it is
// ONE instance for the whole report - a pseudonym has to mean the same machine
// wherever it appears.
//
// The scheme is required rather than guessed. Guessing would have to cope with
// "localhost:8080", which the URL parser reads as the scheme "localhost" and
// the opaque part "8080", and a tool that quietly diagnoses a different address
// than the one asked about is worse than one that asks for a clearer question.
func readTarget(o *options) (targetReduction, *redact.Redaction, *fault) {
	raw := o.target
	parsed, err := url.Parse(raw)
	if err != nil {
		return targetReduction{}, nil, usageFault(
			"%q is not a URL certdoctor can read: %v. Give one like https://example.com", raw, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		// The suggestion is quoted rather than pasted in. It contains what the
		// user typed, and %s reproduced that byte for byte onto a terminal:
		// a bidirectional override or a zero width character in a URL from a
		// ticket came straight back out, unescaped, into somebody's console and
		// their log. The parser refuses ASCII control characters, which is why
		// this looked safe - it does not refuse the ones above them.
		return targetReduction{}, nil, usageFault(
			"%q has no http:// or https:// scheme. Without one a host name cannot be told from a port number, so write it out, for example %q",
			raw, "https://"+raw)
	}
	if parsed.Host == "" {
		return targetReduction{}, nil, usageFault("%q names no host. Give one like https://example.com", raw)
	}

	// The host is lower cased and nothing else is. Names in DNS are case
	// insensitive, so EXAMPLE.COM and example.com are one machine - and left
	// alone they became two: two different targets in two reports of the same
	// run, a difference --compare would report where nothing had changed, and
	// two different pseudonyms under --redact for one host. A path and a query
	// are case sensitive and are left exactly as they were.
	//
	// It is done HERE rather than inside the masking rule, so that the rule for
	// the target stays the rule the owner approved and nothing else.
	parsed.Host = strings.ToLower(parsed.Host)

	mode := redact.Credentials
	if o.redact {
		mode = redact.Everything
	}
	// THE TARGET HOST IS HANDED OVER AS SENSITIVE, AND ADR26 IS WHY. Masking finds
	// a host inside a URL by pattern, which covered every host in this report until
	// L1 - that layer reports a BARE name in a field of its own, and no pattern
	// finds those without guessing which dotted words are names. This is the one
	// host we never have to guess about, so it is handed over by name.
	//
	// It is handed over in both modes. Names are only masked under Everything, so
	// this costs nothing in the weaker one, and a conditional here would be a
	// second place where the mode decides something.
	redaction := redact.New(mode, redact.Host(parsed.Hostname()))

	shown, removed := redaction.Target(parsed.String())
	return targetReduction{target: shown, removed: removed}, redaction, nil
}

// standingNotes are the shortfalls this build has no matter what it is asked to
// do.
//
// Each entry names one thing that is not built or not established, and each
// disappears the day that thing arrives - this list is meant to shrink to
// nothing. An empty notes array claims the run held nothing back, so these are
// not decoration: they are what will make that claim mean something when it is
// finally true.
// The blanket note that used to head this list is GONE, and its removal is the
// point rather than a tidy-up. It read "no diagnostic layer is implemented yet",
// which stopped being true the day L0 started reading this machine's context. A
// note kept past the arrival of the thing it announced is worse than no note:
// it teaches people that notes are boilerplate, and then the one that mattered
// goes unread with the rest. What it used to say is now COUNTED rather than
// asserted - the verdict names how many layers could not be assessed, and each
// of those layers says so in its own row, with a reason.
var standingNotes = []report.Note{
	{
		Kind:   report.NoteNotImplemented,
		Field:  "trust_matrix",
		Detail: "the per runtime trust matrix is not built yet and is absent from this report",
	},
	{
		Kind:   report.NoteUndetermined,
		Field:  "run.platform.container",
		Detail: "certdoctor does not detect containers yet, so this is left empty rather than answered no",
	},
}

// pendingNotes is the standing list plus whatever this particular invocation
// added to it.
func pendingNotes(shown targetReduction, privilege report.PrivilegeLevel) []report.Note {
	notes := append([]report.Note{}, standingNotes...)
	// An unknown privilege level is a legitimate answer and it is also the one
	// that makes a later comparison of two reports meaningless, so it is never
	// left to be noticed in the field alone. When the level IS established this
	// note disappears - a note that never goes away teaches people to skip
	// notes, and then the one that mattered goes with them.
	if privilege == report.PrivilegeUnknown {
		notes = append(notes, report.Note{
			Kind:   report.NoteUndetermined,
			Field:  "run.privilege_level",
			Detail: "the operating system did not answer when asked what privilege this process runs with, so the level is left unknown rather than guessed",
		})
	}
	if shown.removed {
		notes = append(notes, report.Note{
			Kind:  report.NoteReduced,
			Field: "run.target",
			Detail: "parts of the target were masked out of the report: user info, the values of any query parameters, " +
				"and the path, which is shown as a marker because deciding which path segments are identifiers would take a threshold nobody has measured",
		})
	}
	return notes
}

// renderReport turns the report into the bytes that will be delivered.
//
// It renders into memory in full before anything is delivered anywhere, and the
// machine readable document is checked against its declared schema on the way
// out. A document that does not match the contract we published is an internal
// failure: whoever parses it would get a different answer from the same run
// than we did.
func renderReport(o *options, env environment, finished report.Report) ([]byte, *fault) {
	var buffer bytes.Buffer

	if o.format == "json" {
		document, err := render.Encode(finished)
		if err != nil {
			return nil, &fault{exitcode.Runtime, fmt.Sprintf("the report could not be encoded: %v", err)}
		}
		if err := render.ValidateDocument(document); err != nil {
			return nil, &fault{exitcode.Runtime,
				fmt.Sprintf("the encoded report does not match its declared schema and was not printed:\n%v", err)}
		}
		return document, nil
	}

	terminal := render.Terminal{}
	// Colour and glyphs are for a person at a console. A report going into a
	// file gets neither, whatever the console behind this process can do.
	if o.out == "-" {
		capability := env.capability(o.noColor)
		terminal = render.Terminal{Color: capability.Color, Glyph: capability.Glyph}
	}
	if err := terminal.Render(&buffer, finished); err != nil {
		return nil, &fault{exitcode.Runtime, fmt.Sprintf("the report could not be rendered: %v", err)}
	}
	return buffer.Bytes(), nil
}

// deliver puts the finished bytes where they were asked for.
func deliver(o *options, env environment, document []byte) *fault {
	if o.out == "-" {
		if _, err := env.stdout.Write(document); err != nil {
			return &fault{exitcode.IO, fmt.Sprintf("the report could not be written to standard output: %v", err)}
		}
		return nil
	}
	if err := env.writeFile(o.out, document); err != nil {
		return &fault{exitcode.IO, err.Error()}
	}
	// Say where it went. Writing the file was the only thing this run did that
	// a person cannot see, and it is also the only irreversible thing this
	// program does - an existing file at that path has just been replaced. A run
	// that ended in complete silence gave no way to tell a report from a typo
	// in a path until somebody went looking for the file.
	fmt.Fprintf(env.stderr, "%s: report written to %s, %d bytes\n", toolName, o.out, len(document))
	return nil
}
