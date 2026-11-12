package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"time"

	certdoctor "github.com/donislawdev/certdoctor"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/tool/jwt"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// runs joins each tool on the list to its code (ADR141 point 7). It is the
// one place that does: the list in spec names no code, so the window, which
// reads the list, links no tool. TestEveryToolOnTheListRuns holds the two to
// each other in both directions.
var runs = map[string]func(inputs map[string][]byte, now time.Time) (spec.Outcome, error){
	"jwt": func(in map[string][]byte, now time.Time) (spec.Outcome, error) { return jwt.Decode(in["token"], now) },
}

// toolOptions is a tool's command line, parsed.
type toolOptions struct {
	tool spec.Tool
	// files are the files named for each input, by its name: --file for the
	// first, --<name>-file for every other.
	files   map[string]string
	request string
	format  string
	noColor bool
	help    bool
}

// runTool is the path of "certdoctor tool ...": list the tools, or run one -
// read its inputs, judge them, render, deliver.
//
// LIKE A RUN, IT WRITES STANDARD OUTPUT ONCE, AT THE END, OR NOT AT ALL, and
// the code is OK whenever the tool read its input and showed what it found,
// whatever its checks say (ADR141 point 6). An input it cannot read is CONFIG,
// a command line it cannot parse is USAGE.
func runTool(args []string, env environment) exitcode.Code {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(env.stdout, toolListText())
		return exitcode.OK
	}
	tool, ok := spec.Find(args[0])
	if !ok {
		return complain(env, notATool(args[0]))
	}
	o, f := parseTool(tool, args[1:])
	if f != nil {
		return complain(env, f)
	}
	if o.help {
		fmt.Fprint(env.stdout, toolHelpText(tool))
		return exitcode.OK
	}
	inputs, f := readToolInputs(o, env)
	if f != nil {
		return complain(env, f)
	}
	// To the second: the page says when its "expired 3 hours ago" was true,
	// and a moment finer than the page can show would make two runs in one
	// second disagree for nothing.
	now := env.now().UTC().Truncate(time.Second)
	out, err := runs[tool.ID](inputs, now)
	var refusal *spec.Refusal
	switch {
	case errors.As(err, &refusal):
		return complain(env, configFault("%s", refusal.Reason))
	case err != nil:
		return complain(env, &fault{exitcode.Runtime, fmt.Sprintf("the %s tool failed: %v", tool.ID, err)})
	}
	page, f := renderTool(o, env, now, out)
	if f != nil {
		return complain(env, f)
	}
	if _, err := env.stdout.Write(page); err != nil {
		return complain(env, &fault{exitcode.IO, fmt.Sprintf("standard output could not be written: %v", err)})
	}
	return exitcode.OK
}

func isHelp(arg string) bool { return arg == "--help" || arg == "-help" || arg == "-h" }

// nameLike is what a mistyped tool name looks like. Anything else after "tool"
// is not repeated back: a token pasted where the name goes is a credential,
// and a message is copied into tickets.
var nameLike = regexp.MustCompile(`^[a-z0-9-]{1,24}$`)

func notATool(word string) *fault {
	if nameLike.MatchString(word) {
		return usageFault("%q is not a tool. %s tool lists the tools there are", word, toolName)
	}
	return usageFault("the word after tool is not the name of a tool, and it is not repeated here in case it "+
		"was meant as input. %s tool lists the tools there are", toolName)
}

// parseTool reads a tool's switches. Its own flag set, because a tool's
// switches are not the diagnosis's: --file reads an input here, and the
// diagnosis's --in names a container.
func parseTool(tool spec.Tool, args []string) (*toolOptions, *fault) {
	o := &toolOptions{tool: tool, files: map[string]string{}}
	fs := flag.NewFlagSet(toolName+" tool "+tool.ID, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	named := map[string]*string{}
	for i, in := range tool.Inputs {
		named[in.Name] = new(string)
		fs.StringVar(named[in.Name], inputSwitch(i, in), "", "")
	}
	asJSON := fs.Bool("json", false, "")
	fs.StringVar(&o.request, "request", "", "")
	fs.StringVar(&o.format, "format", "terminal", "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.BoolVar(&o.help, "help", false, "")
	fs.BoolVar(&o.help, "h", false, "")
	if err := fs.Parse(args); err != nil {
		return nil, usageFault("%v. %s tool %s --help lists its switches", err, toolName, tool.ID)
	}
	if fs.NArg() > 0 {
		return nil, usageFault("%s tool %s takes no argument - give its input on standard input or with --file. "+
			"An argument stays in your shell's history and in the list of running programs", toolName, tool.ID)
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for i, in := range tool.Inputs {
		if given[inputSwitch(i, in)] {
			o.files[in.Name] = *named[in.Name]
		}
	}
	return o, o.check(given, *asJSON)
}

// inputSwitch is the switch that names a file for input i: --file for the
// first, --<name>-file for every other (ADR141 point 2).
func inputSwitch(i int, in spec.Input) string {
	if i == 0 {
		return "file"
	}
	return in.Name + "-file"
}

// check applies the rules between a tool's switches. Each is CONFIG: spelled
// right, asking for something that cannot be done.
func (o *toolOptions) check(given map[string]bool, asJSON bool) *fault {
	switch o.format {
	case "terminal", "json":
	case "md", "html":
		return configFault("a tool writes its page for a terminal or its document with --json, and %s is a "+
			"format of the diagnosis's report", o.format)
	default:
		return usageFault("--format takes terminal or json for a tool")
	}
	if asJSON && given["format"] && o.format != "json" {
		return configFault("--json and --format %s ask for two different formats. Use one of them", o.format)
	}
	if asJSON {
		o.format = "json"
	}
	if given["request"] && len(o.files) > 0 {
		return configFault("--request gives every input itself, and a switch naming a file gives one again. " +
			"Use one of them")
	}
	if given["request"] && o.request == "" {
		return configFault("--request was given no file. Name a request document, or give a single dash " +
			"to read one from standard input")
	}
	for name, path := range o.files {
		if path == "" {
			return configFault("the switch for the %s was given no file", name)
		}
	}
	return nil
}

// renderTool is the page or the document for out.
func renderTool(o *toolOptions, env environment, now time.Time, out spec.Outcome) ([]byte, *fault) {
	if o.format == "json" {
		// The view goes out safe to draw - the window draws it and interprets
		// nothing - and the data as it came, for a script (render.Shown).
		doc, err := spec.NewDocument(o.tool, certdoctor.Version, now.Format(time.RFC3339), render.Shown(out))
		if err == nil {
			var page []byte
			if page, err = doc.Marshal(); err == nil {
				return page, nil
			}
		}
		return nil, &fault{exitcode.Runtime, fmt.Sprintf("the %s document could not be encoded: %v", o.tool.ID, err)}
	}
	capability := env.capability(o.noColor)
	terminal := render.Terminal{Color: capability.Color, Glyph: capability.Glyph}
	var b bytes.Buffer
	page := render.ToolPage{Tool: o.tool, Version: certdoctor.Version, EvaluatedAt: now, Outcome: out}
	if err := terminal.RenderTool(&b, page); err != nil {
		return nil, &fault{exitcode.Runtime, fmt.Sprintf("the %s page could not be rendered: %v", o.tool.ID, err)}
	}
	return b.Bytes(), nil
}
