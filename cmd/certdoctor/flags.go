package main

import (
	"flag"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
)

// Default budgets.
//
// These are the starting proposals from the architecture document and NOBODY
// HAS MEASURED THEM. They are written here with that said out loud, because a
// number in code reads like a measurement to the next person who finds it. The
// sign that the overall one is wrong is a person walking away before the run
// ends. The sign that the layer one is wrong is layers timing out on a healthy
// machine.
const (
	defaultBudgetSeconds      = 60
	defaultLayerBudgetSeconds = 10
)

// maxBudgetSeconds caps both budgets at a day.
//
// Not a guess about what anybody wants - a defence against arithmetic. A
// duration is nanoseconds in a signed 64 bit integer, so a budget of 1e300
// seconds overflows into something negative and a run given "an enormous
// timeout" would skip every layer instead. A day is absurdly generous for a
// tool whose own proposal is sixty seconds, and it makes the overflow
// unreachable.
const maxBudgetSeconds = 86400

// minBudgetSeconds is the shortest limit that can actually be honoured.
//
// The other end of the same defence against arithmetic, and it fails in the
// worse direction. A duration is a whole number of nanoseconds, so a budget of
// 1e-30 seconds truncates to zero - and zero is the documented way of asking
// for NO limit. Somebody typing the strictest budget they could think of got an
// unlimited run, which is the exact opposite of what they asked for and is
// silent about it.
//
// A millisecond is also below what the clock can resolve on some platforms, and
// that is said in the message rather than left as a surprise.
const minBudgetSeconds = 0.001

// options is one parsed command line.
type options struct {
	target string

	format string
	// formatSet says --format was written out on the command line, as opposed
	// to holding its default. The flag package cannot tell those apart and the
	// difference decides whether --json contradicts it.
	formatSet bool
	jsonAlias bool
	out       string
	redact    bool

	in      string
	image   string
	compare string

	quiet   bool
	verbose bool
	noColor bool

	timeout      float64
	probeTimeout float64

	showVersion bool
	showLicense bool
	showHelp    bool
}

// fault is a reason to stop, carrying the code the process ends with.
//
// The code travels with the reason rather than being chosen where the process
// exits. A code picked at the exit point is a code chosen by whoever wrote the
// exit point, and they are not the person who knows what went wrong.
type fault struct {
	code    exitcode.Code
	message string
}

func (f *fault) Error() string { return f.message }

func usageFault(format string, args ...any) *fault {
	return &fault{code: exitcode.Usage, message: fmt.Sprintf(format, args...)}
}

func configFault(format string, args ...any) *fault {
	return &fault{code: exitcode.Config, message: fmt.Sprintf(format, args...)}
}

// switchDecl declares one command line switch, once.
//
// Both the parser and the help text are built from this list, so they cannot
// describe two different tools. The guard that checks every accepted switch is
// documented still runs over the rendered help, because a switch registered
// straight onto the flag set would bypass this table and nothing else would
// notice.
type switchDecl struct {
	name string
	// aliases are additional accepted spellings. They exist for -h, which
	// people type without thinking and which should not end in a usage error.
	aliases []string
	// arg is the placeholder shown in help, empty for a switch taking no value.
	arg     string
	group   string
	summary string
	bind    func(fs *flag.FlagSet, o *options)
}

// formatDecl is one value --format accepts.
//
// Declared and built are separate fields on purpose. The flag surface is frozen
// and complete from today, and half of it names capabilities that do not exist
// yet. Accepting the value and refusing to pretend is honest. Rejecting it as
// an unknown value would be a lie about the contract, and accepting it silently
// would be worse than either.
type formatDecl struct {
	name  string
	built bool
	why   string
}

var formats = []formatDecl{
	{name: "terminal", built: true},
	{name: "json", built: true},
	{name: "md", built: false, why: "the markdown report is not built yet"},
	{name: "html", built: false, why: "the HTML report is not built yet"},
}

func formatNames() []string {
	names := make([]string, 0, len(formats))
	for _, f := range formats {
		names = append(names, f.name)
	}
	return names
}

func formatFor(name string) (formatDecl, bool) {
	for _, f := range formats {
		if f.name == name {
			return f, true
		}
	}
	return formatDecl{}, false
}

// switches is the whole flag surface, in the order help presents it.
var switches = []switchDecl{
	{
		name: "format", arg: "<" + strings.Join(formatNames(), "|") + ">", group: "output",
		summary: "how to write the report. Defaults to terminal",
		bind:    func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.format, "format", "terminal", "") },
	},
	{
		name: "json", group: "output",
		summary: "the same as --format json",
		bind:    func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.jsonAlias, "json", false, "") },
	},
	{
		name: "out", arg: "<path>", group: "output",
		summary: "where to write the report. A single dash means standard output, which is the default",
		bind:    func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.out, "out", "-", "") },
	},
	{
		name: "redact", group: "output",
		summary: "mask host names, paths and user names. Credentials are masked with or without it",
		bind:    func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.redact, "redact", false, "") },
	},
	{
		name: "in", arg: "<container>", group: "containers",
		summary: "diagnose from inside a running container",
		bind:    func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.in, "in", "", "") },
	},
	{
		name: "image", arg: "<image>", group: "containers",
		summary: "diagnose from inside a throwaway container built from an image",
		bind:    func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.image, "image", "", "") },
	},
	{
		name: "compare", arg: "host,container", group: "containers",
		summary: "show the host and the container side by side. Needs --in or --image",
		bind:    func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.compare, "compare", "", "") },
	},
	{
		name: "quiet", group: "channels",
		summary: "keep the log on standard error down to failures",
		bind:    func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.quiet, "quiet", false, "") },
	},
	{
		name: "verbose", group: "channels",
		summary: "say more on standard error about what is happening",
		bind:    func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.verbose, "verbose", false, "") },
	},
	{
		name: "no-color", group: "channels",
		summary: "never colour the output. NO_COLOR in the environment does the same",
		bind:    func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.noColor, "no-color", false, "") },
	},
	{
		name: "timeout", arg: "<seconds>", group: "budget",
		summary: fmt.Sprintf("limit for the whole run in seconds, at least %g. Zero means no limit. Defaults to %d",
			minBudgetSeconds, defaultBudgetSeconds),
		bind: func(fs *flag.FlagSet, o *options) {
			fs.Float64Var(&o.timeout, "timeout", defaultBudgetSeconds, "")
		},
	},
	{
		name: "probe-timeout", arg: "<seconds>", group: "budget",
		summary: fmt.Sprintf("limit for one layer in seconds, at least %g. Zero means no limit. Defaults to %d",
			minBudgetSeconds, defaultLayerBudgetSeconds),
		bind: func(fs *flag.FlagSet, o *options) {
			fs.Float64Var(&o.probeTimeout, "probe-timeout", defaultLayerBudgetSeconds, "")
		},
	},
	{
		name: "version", group: "meta",
		summary: "print the version of the tool and of every schema it emits",
		bind:    func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.showVersion, "version", false, "") },
	},
	{
		name: "license", group: "meta",
		summary: "print the licence this binary ships under",
		bind:    func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.showLicense, "license", false, "") },
	},
	{
		name: "help", aliases: []string{"h"}, group: "meta",
		summary: "print this text",
		bind: func(fs *flag.FlagSet, o *options) {
			fs.BoolVar(&o.showHelp, "help", false, "")
			fs.BoolVar(&o.showHelp, "h", false, "")
		},
	},
}

// newFlagSet registers the whole surface and returns it together with the
// options it writes into.
//
// It never prints and never exits. The standard library's default behaviour is
// to write to standard error and call os.Exit(2) on a parse failure, which
// would take the choice of exit code away from the code that knows what
// happened and put a message on a channel this program controls elsewhere.
func newFlagSet() (*flag.FlagSet, *options) {
	o := &options{}
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	for _, s := range switches {
		s.bind(fs, o)
	}
	return fs, o
}

// parse turns a command line into options, or into the fault the run ends with.
func parse(args []string) (*options, *fault) {
	fs, o := newFlagSet()

	target, rest, err := splitTarget(fs, args)
	if err != nil {
		return nil, err
	}
	if parseErr := fs.Parse(rest); parseErr != nil {
		return nil, usageFault("%v. Run %s --help to see what is accepted", parseErr, toolName)
	}
	if leftover := fs.Args(); len(leftover) > 0 {
		return nil, usageFault(
			"unexpected extra argument %q. %s takes one URL and its options, for example: %s https://example.com --json",
			leftover[0], toolName, toolName)
	}

	// Asked of the flag set rather than inferred from the value, because the
	// default and an explicit --format terminal are the same string and mean
	// different things next to --json.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "format" {
			o.formatSet = true
		}
	})

	o.target = target
	if fault := o.checkMetaSwitches(); fault != nil {
		return nil, fault
	}
	if o.showHelp || o.showVersion || o.showLicense {
		return o, nil
	}
	if fault := o.check(); fault != nil {
		return nil, fault
	}
	return o, nil
}

// splitTarget separates the positional URL from the switches.
//
// WHY THIS EXISTS. Measured on 2026-08-02 with Go 1.26.5: the standard flag
// package stops parsing at the first argument that is not a switch, and reports
// nothing about it. So "certdoctor https://example.com --json" - the form the
// plan uses throughout - would leave --json sitting in the leftovers, produce a
// terminal report, and never say why. That is the worst shape of defect
// available here, because the program looks like it worked.
//
// The flag set is asked which switches take a value rather than that being
// listed here, so a new switch cannot be added and left out of this.
func splitTarget(fs *flag.FlagSet, args []string) (string, []string, *fault) {
	var target string
	var haveTarget bool
	var rest []string
	positionalOnly := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case positionalOnly:
		case arg == "--":
			positionalOnly = true
			continue
		case len(arg) > 1 && arg[0] == '-':
			name, inlineValue := switchName(arg)
			// A switch nobody registered is reported HERE, by name, rather than
			// left for the parser. Left alone it consumed nothing, so the
			// argument behind it became the URL and the real URL became an
			// "unexpected extra argument" - a message pointing at the only
			// correct part of the line while saying nothing about the wrong
			// one. The same typo also read differently depending on whether it
			// stood before or after the URL.
			if fs.Lookup(name) == nil {
				return "", nil, usageFault(
					"%q is not a switch %s knows. Run %s --help to see what is accepted", arg, toolName, toolName)
			}
			rest = append(rest, arg)
			if !inlineValue && takesValue(fs, name) && i+1 < len(args) {
				i++
				rest = append(rest, args[i])
			}
			continue
		}
		if haveTarget {
			return "", nil, usageFault(
				"unexpected extra argument %q. %s takes one URL and its options, for example: %s https://example.com --json",
				arg, toolName, toolName)
		}
		target, haveTarget = arg, true
	}
	return target, rest, nil
}

// switchName strips the dashes and reports whether the value was written into
// the same argument with an equals sign.
func switchName(arg string) (string, bool) {
	name := strings.TrimLeft(arg, "-")
	if at := strings.IndexByte(name, '='); at >= 0 {
		return name[:at], true
	}
	return name, false
}

// takesValue reports whether a registered switch consumes the next argument.
//
// The flag set exposes this: a boolean switch's value implements IsBoolFlag,
// and nothing else does. Measured alongside the parsing order on 2026-08-02.
// An unknown name answers no, and the caller now refuses it before asking - the
// answer is kept honest anyway, because a function that says "yes" about a
// switch that does not exist would be wrong even where nobody looks.
func takesValue(fs *flag.FlagSet, name string) bool {
	found := fs.Lookup(name)
	if found == nil {
		return false
	}
	asBool, ok := found.Value.(interface{ IsBoolFlag() bool })
	return !(ok && asBool.IsBoolFlag())
}

// check applies the consistency rules. Every one of them ends in a code from
// the table and a sentence saying what to do instead.
func (o *options) check() *fault {
	if o.target == "" {
		return usageFault(
			"no URL was given. %s needs to know what to diagnose, for example: %s https://example.com",
			toolName, toolName)
	}
	for _, rule := range []func() *fault{o.checkFormat, o.checkContainers, o.checkChannels, o.checkBudgets, o.checkOut} {
		if fault := rule(); fault != nil {
			return fault
		}
	}
	return nil
}

// checkMetaSwitches refuses more than one switch that describes the tool.
//
// Each of them is a complete answer on its own, so two of them are two answers
// and only one can be given. The version handled that by printing the first in a
// fixed order and dropping the rest without a word - an option accepted and
// silently ignored, which is the same defect --redact carries a note about.
func (o *options) checkMetaSwitches() *fault {
	var asked []string
	for _, named := range []struct {
		name  string
		given bool
	}{
		{"--help", o.showHelp}, {"--version", o.showVersion}, {"--license", o.showLicense},
	} {
		if named.given {
			asked = append(asked, named.name)
		}
	}
	if len(asked) > 1 {
		return configFault("%s each print something different and only one of them can be answered. Use one",
			strings.Join(asked, " and "))
	}
	return nil
}

func (o *options) checkFormat() *fault {
	chosen, known := formatFor(o.format)
	if !known {
		return usageFault("unknown format %q. Accepted: %s", o.format, strings.Join(formatNames(), ", "))
	}
	// An explicit --format is what makes this a contradiction. Reading the value
	// alone could not tell "--format terminal" from the default, so --json
	// quietly won and produced a document nobody on the command line had asked
	// for in that form.
	if o.jsonAlias && o.formatSet && o.format != "json" {
		return configFault(
			"--json and --format %s ask for two different formats. Use one of them, or --format json",
			o.format)
	}
	if o.jsonAlias {
		o.format = "json"
		chosen, _ = formatFor("json")
	}
	if !chosen.built {
		return configFault(
			"--format %s cannot be satisfied: %s. Built today: %s",
			chosen.name, chosen.why, strings.Join(builtFormatNames(), " and "))
	}
	return nil
}

func builtFormatNames() []string {
	var names []string
	for _, f := range formats {
		if f.built {
			names = append(names, f.name)
		}
	}
	return names
}

func (o *options) checkContainers() *fault {
	if o.in != "" && o.image != "" {
		return configFault("--in and --image both name somewhere to run. Use one of them")
	}
	if o.compare != "" && o.in == "" && o.image == "" {
		return configFault("--compare has nothing to compare the host against. Add --in or --image")
	}
	// Ordered rather than a map: two of these can be set at once, and a message
	// that names a different one on different runs of the same command line is
	// the sort of thing that makes a person doubt the whole report.
	for _, named := range []struct{ name, value string }{
		{"--in", o.in}, {"--image", o.image}, {"--compare", o.compare},
	} {
		if named.value != "" {
			return configFault(
				"%s cannot be satisfied: container diagnosis is not built yet. Run %s against a URL from this machine instead",
				named.name, toolName)
		}
	}
	return nil
}

func (o *options) checkChannels() *fault {
	if o.quiet && o.verbose {
		return configFault("--quiet and --verbose ask for opposite amounts of logging. Use one of them")
	}
	return nil
}

func (o *options) checkBudgets() *fault {
	for _, named := range []struct {
		name    string
		seconds float64
	}{
		{"--timeout", o.timeout}, {"--probe-timeout", o.probeTimeout},
	} {
		switch {
		case math.IsNaN(named.seconds) || math.IsInf(named.seconds, 0):
			return configFault("%s is not a number of seconds. Give a value between 0 and %d, where 0 means no limit",
				named.name, maxBudgetSeconds)
		case named.seconds < 0:
			return configFault("%s is negative. Give a value between 0 and %d, where 0 means no limit",
				named.name, maxBudgetSeconds)
		case named.seconds > 0 && named.seconds < minBudgetSeconds:
			return configFault(
				"%s is shorter than a millisecond, which is too short to be honoured - it would round down to no limit at all. Give 0 if that is what you want, or at least %g",
				named.name, minBudgetSeconds)
		case named.seconds > maxBudgetSeconds:
			return configFault("%s is longer than a day. Give a value between 0 and %d, where 0 means no limit",
				named.name, maxBudgetSeconds)
		}
	}
	return nil
}

func (o *options) checkOut() *fault {
	if o.out == "" {
		return configFault("--out was given no path. Use a file name, or a single dash for standard output")
	}
	return nil
}

// budget turns a validated number of seconds into a duration.
func budget(seconds float64) time.Duration {
	return time.Duration(seconds * float64(time.Second))
}
