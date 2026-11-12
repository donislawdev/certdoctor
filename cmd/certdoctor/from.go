package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/donislawdev/certdoctor/internal/adapter/file"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/switches"
)

// alongsideFrom are the switches a command line with --from accepts: the ones
// about where the report goes and how it looks, and the ones that describe the
// tool. Every other switch shapes a run, and --from makes none.
//
// IT LISTS WHAT IS ALLOWED RATHER THAN WHAT IS NOT, so a switch declared
// tomorrow is refused beside --from until somebody decides otherwise - a
// refusal is a sentence the person reads, where a switch quietly accepted and
// ignored is the defect checkMetaSwitches names.
// TestEverySwitchIsAcceptedOrRefusedBesideFrom holds each declared switch to
// one side of this.
var alongsideFrom = map[string]bool{
	"from":     true,
	"format":   true,
	"json":     true,
	"out":      true,
	"quiet":    true,
	"verbose":  true,
	"no-color": true,
	"help":     true,
	"version":  true,
	"license":  true,
}

// checkFrom applies the consistency rules of a command line with --from.
// Each ends in CONFIG: the switches are spelled right and ask for something
// that cannot be done together (docs/15 section 5.2).
func (o *options) checkFrom() *fault {
	if o.from == "" {
		// Given and empty is not the same as not given - the answer --out and
		// --pac-url give to the same shape, which is a shell variable that did
		// not expand.
		return configFault("--from was given no file. Name a report saved with --json, " +
			"or give a single dash to read one from standard input")
	}
	if o.target != "" {
		return configFault("--from writes a report saved earlier, and %q asks for a new run. Use one of them",
			o.target)
	}
	// --redact first and in words of its own, because it is the one a person
	// most plausibly expects to work: mask the report somebody sent me before I
	// attach it. A finished report cannot be masked as a run masks it - the
	// pseudonyms are issued while the run still knows every address - so the
	// honest answer is where a masked copy comes from.
	if o.given["redact"] {
		return configFault("--redact masks a report while a run makes it, and the one --from names was made "+
			"already. For a masked copy, run %s against the URL again with --redact", toolName)
	}
	for _, s := range switches.All {
		if o.given[s.Name] && !alongsideFrom[s.Name] {
			return configFault("--%s shapes a run, and --from runs nothing - it writes a report saved earlier. "+
				"Leave --%s out", s.Name, s.Name)
		}
	}
	for _, rule := range []func() *fault{o.checkFormat, o.checkChannels, o.checkOut} {
		if fault := rule(); fault != nil {
			return fault
		}
	}
	return nil
}

// rewrite is the path that writes a saved report again, ADR121 (c): read it,
// make sure it is a report this program wrote, render it, deliver it.
//
// IT ENDS IN OK WHEN THE REPORT WAS WRITTEN, whatever the report says - the
// owner's decision of 2026-11-09. The code of a run says what the run found,
// and this makes no run: it says the saved report was read and written. The
// verdict and its code stay in the report, as verdict.exit_code. Everything
// that stops it is CONFIG, from the same table, and nothing reaches standard
// output on that path - the same promise a run keeps.
func rewrite(o *options, env environment) exitcode.Code {
	document, readFault := readSaved(o, env)
	if readFault != nil {
		return complain(env, readFault)
	}
	saved, err := render.Decode(document)
	if err != nil {
		return complain(env, configFault("%s is not a report %s can write again: %v", savedName(o), toolName, err))
	}
	page, renderFault := renderReport(o, env, saved)
	if renderFault != nil {
		return complain(env, renderFault)
	}
	if deliverFault := deliver(o, env, page); deliverFault != nil {
		return complain(env, deliverFault)
	}
	return exitcode.OK
}

// savedName is how a sentence names where the report came from.
func savedName(o *options) string {
	if o.from == "-" {
		return "standard input"
	}
	return o.from
}

// errNothingPiped is what the standard input port answers when nothing is
// piped into this program, so reading it would wait for somebody to type a
// report.
var errNothingPiped = errors.New("nothing is piped into standard input")

// readSaved reads the report --from names, bounded by switches.MaxReport.
//
// A FILE GOES THROUGH THE SAME PORT EVERY OTHER FILE THIS PROGRAM READS DOES -
// file.Guarded, on the guard's list of places that may open a path. So a path
// on another machine is refused rather than opened (a UNC path is a connection
// made as whoever runs this), only a regular file is read (a pipe or a terminal
// may wait for ever), and the limit stops a read before a parser holds it.
func readSaved(o *options, env environment) ([]byte, *fault) {
	if o.from == "-" {
		return readStandardInput(env)
	}
	if env.openFile == nil {
		return nil, &fault{exitcode.Runtime, "this build has no way to read a file, so --from cannot be answered"}
	}
	handle, err := env.openFile(switches.MaxReport)(o.from)
	if err == nil {
		defer handle.Close()
		var document []byte
		if document, err = io.ReadAll(handle); err == nil {
			return document, nil
		}
	}
	return nil, unreadable(o.from, err)
}

// unreadable says why the file --from names was not read, in the words that
// tell a person what to do about it.
func unreadable(path string, err error) *fault {
	return unreadableNamed(namedFile{
		by:       "--from",
		what:     "report",
		tooLarge: fmt.Sprintf("larger than %d MiB - more than any report %s writes -", switches.MaxReport>>20, toolName),
	}, path, err)
}

// namedFile is how a refusal to read a file a person named speaks of it: the
// switch that named it, what the file was meant to be, and why it is too large.
type namedFile struct {
	by       string
	what     string
	tooLarge string
}

// unreadableNamed says why a file a person named was not read, in the words
// that tell them what to do about it. One place for --from and every tool's
// file, so the answer to a folder or a path on another machine is the same
// sentence wherever a path is named.
func unreadableNamed(n namedFile, path string, err error) *fault {
	var (
		tooLarge   *file.TooLarge
		remote     *file.RemotePath
		notRegular *file.NotRegular
	)
	switch {
	case errors.As(err, &tooLarge):
		return configFault("%s names %s, which is %s so it was not read", n.by, path, n.tooLarge)
	case errors.As(err, &remote) && remote.Via != "":
		return configFault("%s names %s, which leads to %s on another machine, and opening it would connect "+
			"there as you. Copy the %s to this machine and name the copy", n.by, path, remote.Via, n.what)
	case errors.As(err, &remote):
		return configFault("%s names %s, which is on another machine, and opening it would connect there as "+
			"you. Copy the %s to this machine and name the copy", n.by, path, n.what)
	case errors.As(err, &notRegular) && notRegular.Mode.IsDir():
		return configFault("%s names %s, which is a folder. Name the %s file in it", n.by, path, n.what)
	case errors.As(err, &notRegular):
		return configFault("%s names %s, which is not a file, and reading it could wait for ever", n.by, path)
	case errors.Is(err, fs.ErrNotExist):
		return configFault("%s names %s, and nothing is there", n.by, path)
	default:
		return configFault("%s names %s, which could not be read: %v", n.by, path, err)
	}
}

// readStandardInput reads a saved report piped into this program.
func readStandardInput(env environment) ([]byte, *fault) {
	if env.stdin == nil {
		return nil, &fault{exitcode.Runtime, "this build has no standard input to read, so --from - cannot be answered"}
	}
	input, err := env.stdin()
	switch {
	case errors.Is(err, errNothingPiped):
		// Said at once rather than waiting: a terminal on standard input means
		// nobody piped anything, and nobody types a report by hand.
		return nil, configFault("--from - reads a saved report from standard input, and nothing is piped in. "+
			"Pipe one in, as in %s --from - < report.json, or name the file", toolName)
	case err != nil:
		return nil, configFault("standard input could not be read: %v", err)
	}
	document, err := io.ReadAll(io.LimitReader(input, switches.MaxReport+1))
	if err != nil {
		return nil, configFault("standard input could not be read: %v", err)
	}
	if len(document) > switches.MaxReport {
		return nil, configFault("standard input carries more than %d MiB - more than any report %s writes - "+
			"so it was not read", switches.MaxReport>>20, toolName)
	}
	return document, nil
}
