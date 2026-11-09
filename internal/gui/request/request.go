// Package request is the run a person asks the window for: the address and
// the options set on the start screen, and the command line they become
// (ADR121). It knows the switches the command line declares and the words the
// window shows for them, and nothing of the toolkit, so what the form asks for
// can be read and checked without a window (GUI rule 15).
//
// Every switch the command line declares is either offered here, with the
// words it is shown with, or left to the command line with the reason - and a
// test names every one of them, so a switch added to the command line cannot
// be forgotten by the window without that test saying so (ADR121 point 3).
package request

import (
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/switches"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// Control is what a switch is set with on the form, read from what the switch
// takes rather than chosen beside it.
type Control int

// The three controls.
const (
	// Tick is for a switch that takes no value.
	Tick Control = iota
	// Line is for a switch that takes a word, an address or a name.
	Line
	// Seconds is for a switch that takes a number of seconds.
	Seconds
)

// Option is one switch the window offers, with the words it is shown with.
type Option struct {
	// Switch is the name the command line declares.
	Switch string
	Label  words.Key
	// Hint is the sentence under the control, empty for none.
	Hint words.Key
	// Example is what an empty Line shows, empty for the other controls.
	Example words.Key
	// Default is what an empty Seconds field means, and what it shows - the
	// number the command line uses when the switch is not given.
	Default int
}

// Offered is every switch the window offers, in the order of the form.
var Offered = []Option{
	{Switch: "pac-url", Label: words.OptPAC, Hint: words.OptPACHint, Example: words.OptPACExample},
	{Switch: "timeout", Label: words.OptTimeout, Hint: words.OptTimeoutHint, Default: switches.DefaultBudgetSeconds},
	{Switch: "probe-timeout", Label: words.OptLayerTimeout, Hint: words.OptLayerHint, Default: switches.DefaultLayerBudgetSeconds},
	{Switch: "redact", Label: words.OptRedact, Hint: words.OptRedactHint},
}

// NotOffered is every switch the window leaves to the command line, with the
// reason. The reasons are for whoever reads this file - the window does not
// show them.
var NotOffered = map[string]string{
	"format": "the window reads the report itself, and Save report chooses the format of a copy",
	"json":   "the window always asks for the document it reads",
	"out":    "Save report chooses where a copy is written",
	// The day these are built, TestTheGroupTheHelpCallsNotBuiltIsRefused in
	// cmd/certdoctor goes red over the note in the help, and these three come
	// here into Offered with it.
	"in":       "not built in this release, and the command line refuses it with the reason",
	"image":    "not built in this release, and the command line refuses it with the reason",
	"compare":  "not built in this release, and the command line refuses it with the reason",
	"quiet":    "it changes only what goes to standard error, which the window does not show",
	"verbose":  "it changes only what goes to standard error, which the window does not show",
	"no-color": "the window draws its own colours",
	"version":  "the window shows its version in the bar at the top",
	"license":  "the licence and the notices ship as files beside the window",
	"help":     "the window's labels and hints say what each option does",
}

// Control answers how the option is set, from what its switch takes.
func (o Option) Control() Control {
	s, _ := switches.Named(o.Switch)
	switch {
	case !s.TakesValue():
		return Tick
	case s.Numeric:
		return Seconds
	default:
		return Line
	}
}

// Request is one run as the form holds it.
type Request struct {
	// Address is what was typed into the address field.
	Address string
	// Ticked holds the ticked options that take no value, by switch.
	Ticked map[string]bool
	// Typed holds what was typed for the options that take a value, by switch.
	Typed map[string]string
}

// Args is the command line the request becomes: the document the window
// reads, every option that was set, in the order of the form, and the address
// last, after "--", so that nothing typed into the address field can be read
// as a switch.
//
// A value goes with its switch in one argument, after "=", so that a value
// beginning with a dash, or one the command line reads as a number, stays the
// value of the switch it was typed for. What was typed is passed on with the
// space around it taken off - what a shell does to a word typed on a command
// line - and is otherwise not judged here: a number the command line cannot
// read is refused by the command line, in its own words, rather than by a
// second check here that could come to disagree with it. A value that is
// empty after that is no value, the same as a field left alone.
//
// The address is passed on whatever it is, including empty: whether there is
// one to diagnose is the caller's question, asked before a run starts.
func (r Request) Args() []string {
	args := []string{"--json"}
	for _, o := range Offered {
		if o.Control() == Tick {
			if r.Ticked[o.Switch] {
				args = append(args, "--"+o.Switch)
			}
			continue
		}
		if value := strings.TrimSpace(r.Typed[o.Switch]); value != "" {
			args = append(args, "--"+o.Switch+"="+value)
		}
	}
	return append(args, "--", strings.TrimSpace(r.Address))
}
