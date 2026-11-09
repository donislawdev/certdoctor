// Package switches is the command line's switches, declared once (ADR121
// point 3). The command line parses with this list and prints its help from
// it, and the window builds its options form from it, so a switch is one entry
// here and neither of the two can offer one the other does not know.
//
// What is here is the contract and nothing else: the names a person types,
// what each takes, and the sentence the help prints for it. How the command
// line stores a value it parsed stays with the command line, and what the
// window calls a switch on its form stays in the window's catalogue of words,
// because those are two presentations of one contract and the contract is the
// part that must not be written twice. Each side holds a test that names every
// switch declared here, so a new one cannot reach one side and be missed by
// the other.
//
// The flag surface is a public contract (docs/15 section 5): a name here is a
// name in somebody's script.
package switches

import (
	"fmt"
	"strings"
)

// Switch is one switch of the command line.
type Switch struct {
	// Name is the switch as written after two dashes.
	Name string
	// Aliases are additional accepted spellings, written after one dash. They
	// exist for -h, which people type without thinking and which should not
	// end in a usage error.
	Aliases []string
	// Arg is the placeholder the help shows for the value, empty for a switch
	// taking no value.
	Arg string
	// Numeric says the value is a number of seconds, so a value that is not a
	// number can be refused in this program's own words.
	Numeric bool
	// Group is the section of the help the switch is printed in.
	Group string
	// Summary is the sentence the help prints beside the switch.
	Summary string
}

// TakesValue says the switch is followed by a value.
func (s Switch) TakesValue() bool { return s.Arg != "" }

// The two budgets a run is given when nobody names one.
//
// These are the starting proposals from the architecture document and NOBODY
// HAS MEASURED THEM. They are written here with that said out loud, because a
// number in code reads like a measurement to the next person who finds it. The
// sign that the overall one is wrong is a person walking away before the run
// ends. The sign that the layer one is wrong is layers timing out on a healthy
// machine.
const (
	DefaultBudgetSeconds      = 60
	DefaultLayerBudgetSeconds = 10
)

// MinBudgetSeconds is the shortest limit that can actually be honoured.
//
// The other end of a defence against arithmetic, and it fails in the worse
// direction. A duration is a whole number of nanoseconds, so a budget of 1e-30
// seconds truncates to zero - and zero is the documented way of asking for NO
// limit. Somebody typing the strictest budget they could think of got an
// unlimited run, which is the exact opposite of what they asked for and is
// silent about it.
//
// A millisecond is also below what the clock can resolve on some platforms, and
// that is said in the message rather than left as a surprise.
const MinBudgetSeconds = 0.001

// Formats are the values --format accepts, in the order the help names them.
var Formats = []string{"terminal", "json", "md", "html"}

// All is the whole flag surface, in the order the help presents it.
var All = []Switch{
	{
		Name: "format", Arg: "<" + strings.Join(Formats, "|") + ">", Group: "output",
		Summary: "how to write the report. Defaults to terminal",
	},
	{
		Name: "json", Group: "output",
		Summary: "the same as --format json",
	},
	{
		Name: "out", Arg: "<path>", Group: "output",
		Summary: "where to write the report. A single dash means standard output, which is the default",
	},
	{
		Name: "redact", Group: "output",
		Summary: "mask host names, paths and user names. Credentials are masked with or without it",
	},
	{
		Name: "pac-url", Arg: "<url>", Group: "input",
		Summary: "also read this proxy auto-configuration script and say where it sends the target",
	},
	{
		Name: "in", Arg: "<container>", Group: "containers",
		Summary: "diagnose from inside a running container",
	},
	{
		Name: "image", Arg: "<image>", Group: "containers",
		Summary: "diagnose from inside a throwaway container built from an image",
	},
	{
		Name: "compare", Arg: "host,container", Group: "containers",
		Summary: "show the host and the container side by side. Needs --in or --image",
	},
	{
		Name: "quiet", Group: "channels",
		Summary: "keep the log on standard error down to failures",
	},
	{
		Name: "verbose", Group: "channels",
		Summary: "say more on standard error about what is happening",
	},
	{
		Name: "no-color", Group: "channels",
		Summary: "never colour the output. NO_COLOR in the environment does the same",
	},
	{
		Name: "timeout", Arg: "<seconds>", Numeric: true, Group: "budget",
		Summary: fmt.Sprintf("limit for the whole run in seconds, at least %g. Zero means no limit. Defaults to %d",
			MinBudgetSeconds, DefaultBudgetSeconds),
	},
	{
		Name: "probe-timeout", Arg: "<seconds>", Numeric: true, Group: "budget",
		Summary: fmt.Sprintf("limit for one layer in seconds, at least %g. Zero means no limit. Defaults to %d",
			MinBudgetSeconds, DefaultLayerBudgetSeconds),
	},
	{
		Name: "version", Group: "meta",
		Summary: "print the version of the tool and of every schema it emits",
	},
	{
		Name: "license", Group: "meta",
		Summary: "print the licence, then the notices of the third party code in this binary",
	},
	{
		Name: "help", Aliases: []string{"h"}, Group: "meta",
		Summary: "print this text",
	},
}

// Named answers the switch called name, and whether there is one.
func Named(name string) (Switch, bool) {
	for _, s := range All {
		if s.Name == name {
			return s, true
		}
	}
	return Switch{}, false
}
