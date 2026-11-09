package main

import (
	"flag"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/switches"

	"github.com/donislawdev/certdoctor/internal/adapter/pac"
)

// The default budgets and the shortest one that can be honoured are part of
// the published surface - the help prints them - so they are declared with the
// switches, in internal/core/switches, and the window reads the same numbers.

// maxBudgetSeconds caps both budgets at a day.
//
// Not a guess about what anybody wants - a defence against arithmetic. A
// duration is nanoseconds in a signed 64 bit integer, so a budget of 1e300
// seconds overflows into something negative and a run given "an enormous
// timeout" would skip every layer instead. A day is absurdly generous for a
// tool whose own proposal is sixty seconds, and it makes the overflow
// unreachable.
const maxBudgetSeconds = 86400

// minBudgetSeconds is the other end of the same defence, explained where it is
// declared.
const minBudgetSeconds = switches.MinBudgetSeconds

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

	pacURL string
	// pacURLSet says --pac-url was written out on the command line, which the
	// flag package cannot tell from its default. An address that arrived empty
	// because a shell variable did not expand must not read as "no script".
	pacURLSet bool

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

// numericSwitches is the set of switch names whose value has to be a number,
// built from the one declaration rather than listed a second time.
var numericSwitches = func() map[string]bool {
	names := map[string]bool{}
	for _, s := range switches.All {
		if s.Numeric {
			names[s.Name] = true
		}
	}
	return names
}()

// checkNumericValue refuses a value that is not a number, in our own words.
//
// WHY THIS IS NOT LEFT TO THE FLAG PACKAGE. Its message reads "invalid value
// \"1,5\" for flag -timeout: parse error", and two things in that sentence are
// wrong for this program. It names the switch with ONE dash while every line of
// our help, our documentation and our other messages uses two, so it points at
// something that looks like a different switch. And "parse error" is the least
// useful thing to say to somebody whose keyboard puts a comma where this expects
// a dot - which is the reflex on a Polish, German or French layout and therefore
// the most likely wrong value this flag will ever be given.
//
// The alternative was to rewrite the flag package's message after the fact. That
// would mean matching on the TEXT of somebody else's error, which is the one
// thing this project refuses to do anywhere else.
func checkNumericValue(name, value string) *fault {
	if !numericSwitches[name] {
		return nil
	}
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return nil
	}
	if strings.ContainsRune(value, ',') {
		return usageFault(
			"--%s was given %q. %s reads a dot as the decimal point, so write --%s %s",
			name, value, toolName, name, strings.ReplaceAll(value, ",", "."))
	}
	return usageFault("--%s was given %q, which is not a number of seconds", name, value)
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
	{name: "md", built: true},
	{name: "html", built: true},
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

// binds says where each switch of the published surface (switches.All) puts
// what it was given, keyed by its name.
//
// The surface itself - names, values, the help sentences - is declared once in
// internal/core/switches, which the window reads too (ADR121 point 3). What is
// here is the part only this program has: a field of options. One entry for
// every declared switch and none besides, which TestEveryDeclaredSwitchIsBound
// holds in both directions - a declared switch without an entry would be
// documented and then refused as unknown. The guard that checks every
// accepted switch is documented still runs over the rendered help, because a
// switch registered straight onto the flag set would bypass both lists and
// nothing else would notice.
var binds = map[string]func(fs *flag.FlagSet, o *options){
	"format":  func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.format, "format", "terminal", "") },
	"json":    func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.jsonAlias, "json", false, "") },
	"out":     func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.out, "out", "-", "") },
	"redact":  func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.redact, "redact", false, "") },
	"pac-url": func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.pacURL, "pac-url", "", "") },
	"in":      func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.in, "in", "", "") },
	"image":   func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.image, "image", "", "") },
	"compare": func(fs *flag.FlagSet, o *options) { fs.StringVar(&o.compare, "compare", "", "") },
	"quiet":   func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.quiet, "quiet", false, "") },
	"verbose": func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.verbose, "verbose", false, "") },
	"no-color": func(fs *flag.FlagSet, o *options) {
		fs.BoolVar(&o.noColor, "no-color", false, "")
	},
	"timeout": func(fs *flag.FlagSet, o *options) {
		fs.Float64Var(&o.timeout, "timeout", switches.DefaultBudgetSeconds, "")
	},
	"probe-timeout": func(fs *flag.FlagSet, o *options) {
		fs.Float64Var(&o.probeTimeout, "probe-timeout", switches.DefaultLayerBudgetSeconds, "")
	},
	"version": func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.showVersion, "version", false, "") },
	"license": func(fs *flag.FlagSet, o *options) { fs.BoolVar(&o.showLicense, "license", false, "") },
	"help": func(fs *flag.FlagSet, o *options) {
		fs.BoolVar(&o.showHelp, "help", false, "")
		fs.BoolVar(&o.showHelp, "h", false, "")
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
	for _, s := range switches.All {
		bind, ok := binds[s.Name]
		if !ok {
			// A declared switch with nowhere to put its value is a mistake in
			// this file, and every run would refuse the switch the help names.
			// Said at the first parse rather than left as a refusal that blames
			// the person who typed it.
			panic("the switch --" + s.Name + " is declared and has no place in options")
		}
		bind(fs, o)
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
		switch f.Name {
		case "format":
			o.formatSet = true
		case "pac-url":
			o.pacURLSet = true
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
			if inlineValue {
				if fault := checkNumericValue(name, arg[strings.IndexByte(arg, '=')+1:]); fault != nil {
					return "", nil, fault
				}
			}
			if !inlineValue && takesValue(fs, name) && i+1 < len(args) {
				i++
				if fault := checkNumericValue(name, args[i]); fault != nil {
					return "", nil, fault
				}
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
	for _, rule := range []func() *fault{o.checkFormat, o.checkContainers, o.checkChannels, o.checkBudgets, o.checkOut, o.checkPACScript} {
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

// checkPACScript refuses an address no script could be fetched from.
//
// IT IS REFUSED AT THE ENTRY POINT AND NOT REPORTED AS A FINDING - ADR60, whose
// case was a port out of range. A value the user typed and this program cannot
// use is a mistake in the asking, and dressing it up as a diagnosis about their
// machine wastes the one channel that could have told them what to type
// instead.
//
// IT ASKS THE FETCHER'S OWN RULE RATHER THAN A COPY. pac.Target is the function
// that decides what the transport will dial and what the allowed set will hold,
// so a second opinion here could accept an address the fetch would then refuse -
// the shape OBS50 measures, met at the two ends of one run.
func (o *options) checkPACScript() *fault {
	if o.pacURL == "" {
		// GIVEN AND EMPTY IS NOT THE SAME AS NOT GIVEN - inviolable rule 1, and
		// the same answer --out gives to the same shape. The commonest way to
		// reach this is a shell variable that did not expand, and a run that
		// quietly examined no script would look exactly like one that was never
		// asked to.
		if o.pacURLSet {
			return configFault("--pac-url was given no address. Leave it out to read only what this machine names")
		}
		return nil
	}
	if _, err := pac.Target(o.pacURL); err != nil {
		return configFault("--pac-url was given an address certdoctor cannot fetch a script from: %v", err)
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
//
// ZERO IS THE DOCUMENTED WAY OF ASKING FOR NO LIMIT, AND IT IS ANSWERED WITH THE
// LONGEST LIMIT THIS PROGRAM ACCEPTS RATHER THAN WITH THE ABSENCE OF ONE. The
// number is not invented for this line: it is maxBudgetSeconds, the upper bound
// the same flag already refuses to go past, so a run asking for no limit and a
// run asking for the largest limit are one case instead of two.
//
// WHY, AND IT IS MEASURED RATHER THAN REASONED - 2026-08-26, this binary. Asked
// for "--timeout 0 --probe-timeout 0" the direct view of L1 died completely:
// four rows saying "sending the query or reading the reply failed" under a
// layer still reporting PASS, and L3 then saw two addresses where an ordinary
// run sees four. The chain was: no budget means no deadline on the run, which
// means no deadline on the layer, which means limitFor has nothing to divide
// and answers "unlimited", which means the query context carries no deadline -
// and dns.Socket REFUSES a socket it cannot bound, because a resolver that
// accepts a packet and never answers would otherwise outlive every budget this
// run has. Five correct decisions ending in a report that accuses a working
// resolver. It is the family of OBS62, reached through the one port that had
// not been part of it.
//
// THE ALTERNATIVE WAS TO LET THAT PORT OPEN AN UNBOUNDED SOCKET, AND IT WAS
// REJECTED. The refusal there has its own test and its own mutation entry, and
// the hazard it names is real - so the fix belongs where the absence of a
// deadline is manufactured, not where it is caught. Bounding the run here also
// makes the sentence at the top of dns.Socket true rather than aspirational:
// every caller in this program now does arrive with a deadline.
func budget(seconds float64) time.Duration {
	if seconds == 0 {
		return maxBudgetSeconds * time.Second
	}
	return time.Duration(seconds * float64(time.Second))
}
