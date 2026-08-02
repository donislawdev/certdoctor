// Package exitcode defines certdoctor's exit codes: the complete, frozen set of
// ways the process can end.
//
// The table is complete from the first version on purpose. Adding a code after
// release is a breaking change of the worst kind - a run that ends in 0 today
// would start ending in something else inside somebody else's pipeline, with no
// change on their side. In the design phase that completeness costs one
// sentence.
//
// Two of the codes say something about the machine under test rather than about
// certdoctor: Diagnosis and Inconclusive. Inconclusive exists so that "could not
// assess" is never reported as success. Any future severity switch has to map
// onto these codes rather than add new ones.
//
// A warning on its own does not redden CI: WARN keeps the exit code at OK. Any
// machine behind a corporate proxy would otherwise fail its build while its
// connection works perfectly. CI gets one bit from the exit code, and the
// machine-readable report carries the warnings for a pipeline that wants to
// decide for itself.
package exitcode

// Code is a process exit status.
//
// Unlike a status, the zero value here is meaningful: 0 is OK, because that is
// what a shell expects. So this type cannot make a forgotten assignment look
// wrong the way an unset Status does. The protection has to come from the other
// end - every exit is produced from the run's verdict, never from a bare
// literal - and that is what the registry test and the CLI guards are for.
type Code int

const (
	// OK - everything that mattered was assessed and it all passed. A WARN also
	// ends here.
	OK Code = 0
	// Runtime - certdoctor itself broke.
	Runtime Code = 1
	// Usage - bad invocation syntax or an unknown flag.
	Usage Code = 2
	// Config - flags are syntactically valid but contradictory or unsatisfiable.
	Config Code = 3
	// Diagnosis - the run succeeded and found at least one FAIL. This says
	// something about the machine under test, not about the tool.
	Diagnosis Code = 4
	// Inconclusive - no FAIL, but at least one UNKNOWN. This is what keeps
	// "could not assess" from ever being reported as success.
	Inconclusive Code = 5
	// IO - writing the report failed: no space, no permission for the output
	// path.
	IO Code = 6
	// Interrupted - stopped by the user.
	Interrupted Code = 130
	// Terminated - stopped by the system.
	Terminated Code = 143
)

// entry is one row of the registry. Every field is mandatory, and the registry
// test refuses a half-filled row - that is the mistake this shape exists to
// catch.
type entry struct {
	code Code
	// name is a public contract. It appears in --help and in other people's
	// runbooks, so it is renamed only with a version bump.
	name string
	// meaning is the one-line English text shown to the user. Keeping it here
	// rather than at the call site is what stops the same code from being
	// described three different ways in three places.
	meaning string
}

var registry = []entry{
	{OK, "OK", "everything that mattered was assessed and passed"},
	{Runtime, "RUNTIME", "certdoctor itself failed"},
	{Usage, "USAGE", "bad invocation syntax or an unknown flag"},
	{Config, "CONFIG", "flags are valid on their own but contradictory or unsatisfiable"},
	{Diagnosis, "DIAGNOSIS", "the run succeeded and found at least one failure"},
	{Inconclusive, "INCONCLUSIVE", "no failure, but at least one thing could not be assessed"},
	{IO, "IO", "the report could not be written"},
	{Interrupted, "INTERRUPTED", "interrupted by the user"},
	{Terminated, "TERMINATED", "terminated by the system"},
}

// All lists every code exactly once, in the order the help text presents them.
// Anything that needs to enumerate codes reads this rather than repeating the
// list, so a new code cannot be added in one place and forgotten in another.
var All = func() []Code {
	codes := make([]Code, 0, len(registry))
	for _, e := range registry {
		codes = append(codes, e.code)
	}
	return codes
}()

func lookup(c Code) (entry, bool) {
	for _, e := range registry {
		if e.code == c {
			return e, true
		}
	}
	return entry{}, false
}

// Valid reports whether c is one of the declared codes. Use it on anything that
// crossed a boundary, never on our own constants.
func (c Code) Valid() bool {
	_, ok := lookup(c)
	return ok
}

// Name returns the contract name of c, or the empty string for a code outside
// the table. Callers render the empty string as nothing rather than as an
// invented name.
func (c Code) Name() string {
	e, _ := lookup(c)
	return e.name
}

// Meaning returns the user-facing English text for c, or the empty string for a
// code outside the table.
func (c Code) Meaning() string {
	e, _ := lookup(c)
	return e.meaning
}

// Int returns the number to hand to the operating system.
func (c Code) Int() int { return int(c) }
