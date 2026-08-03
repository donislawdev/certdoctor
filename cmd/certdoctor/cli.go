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
	origin, reduced, targetFault := reduceTarget(o.target)
	if targetFault != nil {
		return complain(env, targetFault)
	}

	finished, walkFault := walk(ctx, o, env, origin, reduced)
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
func walk(ctx context.Context, o *options, env environment, origin string, reduced targetReduction) (report.Report, *fault) {
	finished, err := run.Execute(ctx, run.Options{
		Tool:        report.Tool{Name: toolName, Version: toolVersion},
		Target:      origin,
		Platform:    env.platform,
		Privilege:   env.privilege,
		Redacted:    o.redact,
		Budget:      budget(o.timeout),
		LayerBudget: budget(o.probeTimeout),
		Now:         env.now,
		Layers:      run.NotImplemented(),
		Notes:       pendingNotes(o, reduced, env.privilege),
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

// targetReduction records what was taken out of the URL before it was printed.
type targetReduction struct {
	origin string
	// removed says something was dropped, so the report can say so rather than
	// present a shortened URL as if it were the whole one.
	removed bool
}

// reduceTarget parses the URL and reduces it to its origin.
//
// WHY THE REPORT DOES NOT CARRY THE WHOLE URL YET. The target is itself capable
// of being a secret: user info, a token in the query string, a session
// identifier in the path. The rule is that credentials are masked always, with
// or without --redact, and the function that does that masking is deliberately
// scheduled before the layer that would first produce something to mask. Until
// it exists, printing the URL as given would create exactly the code that
// ordering was meant to prevent - code that writes a password out.
//
// The origin is not masking. It is the removal of every part that could carry a
// credential, which is strictly narrower than what masking will allow later.
// The report says it was reduced.
//
// The scheme is required rather than guessed. Guessing would have to cope with
// "localhost:8080", which the URL parser reads as the scheme "localhost" and
// the opaque part "8080", and a tool that quietly diagnoses a different address
// than the one asked about is worse than one that asks for a clearer question.
func reduceTarget(raw string) (string, targetReduction, *fault) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", targetReduction{}, usageFault(
			"%q is not a URL certdoctor can read: %v. Give one like https://example.com", raw, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		// The suggestion is quoted rather than pasted in. It contains what the
		// user typed, and %s reproduced that byte for byte onto a terminal:
		// a bidirectional override or a zero width character in a URL from a
		// ticket came straight back out, unescaped, into somebody's console and
		// their log. The parser refuses ASCII control characters, which is why
		// this looked safe - it does not refuse the ones above them.
		return "", targetReduction{}, usageFault(
			"%q has no http:// or https:// scheme. Without one a host name cannot be told from a port number, so write it out, for example %q",
			raw, "https://"+raw)
	}
	if parsed.Host == "" {
		return "", targetReduction{}, usageFault("%q names no host. Give one like https://example.com", raw)
	}

	// The host is lower cased and nothing else is. Names in DNS are case
	// insensitive, so EXAMPLE.COM and example.com are one machine - and left
	// alone they became two: two different targets in two reports of the same
	// run, a difference --compare would report where nothing had changed, and
	// two different pseudonyms under --redact for one host. A path and a query
	// are case sensitive and are left exactly as they were.
	origin := parsed.Scheme + "://" + strings.ToLower(parsed.Host)
	dropped := parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/")

	return origin, targetReduction{origin: origin, removed: dropped}, nil
}

// standingNotes are the shortfalls this build has no matter what it is asked to
// do.
//
// Each entry names one thing that is not built or not established, and each
// disappears the day that thing arrives - this list is meant to shrink to
// nothing. An empty notes array claims the run held nothing back, so these are
// not decoration: they are what will make that claim mean something when it is
// finally true.
var standingNotes = []report.Note{
	{
		Kind:   report.NoteNotImplemented,
		Detail: "no diagnostic layer is implemented yet, so nothing about this machine has been assessed",
	},
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
func pendingNotes(o *options, reduced targetReduction, privilege report.PrivilegeLevel) []report.Note {
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
	if reduced.removed {
		notes = append(notes, report.Note{
			Kind:   report.NoteReduced,
			Field:  "run.target",
			Detail: "the target is shown as its origin only, because the masking that would let a path or a query string be printed safely is not built yet",
		})
	}
	if o.redact {
		notes = append(notes, report.Note{
			Kind:   report.NoteNoEffect,
			Field:  "--redact",
			Detail: "nothing in this report can be masked yet, so the option changed nothing",
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
